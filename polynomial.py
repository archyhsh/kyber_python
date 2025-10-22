import numpy as np
from numpy.polynomial.polynomial import Polynomial
import random
import hashlib
import os
from math import ceil
from Crypto.Cipher import AES

def to_bytes_le_u16(x):
    return int(x).to_bytes(2, "little")

def bytes_to_bits(data, n_bits):
    """固定转换：32字节 → 256比特"""
    bits = []
    for byte in data:
        for i in range(8):
            bits.append((byte >> i) & 1)
    return bits[:n_bits]

def bits_to_bytes(bits):
    """固定转换：n比特 → 32字节"""
    bytes_list = []
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bits) and bits[i + j]:
                byte |= (1 << j)
        bytes_list.append(byte)
    return bytes(bytes_list[:32])

class AES256CTR_DRBG:
    """
    Minimal AES-256-CTR style DRBG for deterministic expansion.
    - seed: bytes (will be used as AES-256 key; padded/trimmed to 32 bytes)
    - internal counter increments per block.
    NOTE: toy deterministic DRBG for experiments (not a certified NIST DRBG).
    """
    def __init__(self, seed: bytes):
        if not isinstance(seed, bytes):
            raise TypeError("seed must be bytes")
        # key: first 32 bytes of seed (pad with zeros if needed)
        self.key = (seed + b'\x00'*32)[:32]
        self._aes_ecb = AES.new(self.key, AES.MODE_ECB)
        self.counter = 0

    def _next_block(self):
        # 16-byte counter block (big-endian)
        block = self.counter.to_bytes(16, "big")
        self.counter += 1
        return self._aes_ecb.encrypt(block)

    def random_bytes(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            out.extend(self._next_block())
        return bytes(out[:n])

class BabyKyber:
    def __init__(self, n=256, q=3329, k=2):
        self.n = n
        self.q = q
        self.k = k
        self.f = [1] + [0] * (n - 1) + [1]  # x^n + 1
        self.seed = np.random.seed(0xdeadbeef)
        self.SEED_BYTES = 32
        print(f"初始化 BabyKyber: n={n}, q={q}, k={k}")

    # ---------------------- Polynomial Operations ----------------------
    def add_poly(self, a, b):
        """Add two polynomials mod q"""
        result = [0] * max(len(a), len(b))
        for i in range(len(result)):
            if i < len(a):
                result[i] += a[i]
            if i < len(b):
                result[i] += b[i]
            result[i] %= self.q
        return result

    def inv_poly(self, a):
        """Negate a polynomial mod q"""
        return [(-x) % self.q for x in a]

    def sub_poly(self, a, b):
        """Subtract b from a mod q"""
        return self.add_poly(a, self.inv_poly(b))

    def mul_poly_simple(self, a, b):
        """Multiply two polynomials mod (x^n + 1, q)"""
        tmp = [0] * (len(a) * 2 - 1)
        # Schoolbook multiplication
        for i in range(len(a)):
            for j in range(len(b)):
                tmp[i + j] += a[i] * b[j]
        # Mod x^n + 1 reduction
        for i in range(self.n, len(tmp)):
            tmp[i - self.n] -= tmp[i]
            tmp[i] = 0
        # Mod q
        return [x % self.q for x in tmp[:self.n]]

    def sign_extend(self, poly):
        """Pad polynomial to degree n"""
        if len(poly) >= self.n:
            return poly[:self.n]
        return poly + [0] * (self.n - len(poly))

    def test_mul_poly(self, f):
        degree_f = self.n
        for i in range(5):
            a = (np.random.random(degree_f) * self.q).astype(int)
            b = (np.random.random(degree_f) * self.q).astype(int)
            a_mul_b = self.mul_poly_simple(a, b)
            # NumPy reference poly multiplication
            # note that we need to convert the coefficients to int and extend the list to match the fixed size of our impl
            a_mul_b_ref = list(map(lambda x: int(x) % self.q, ((Polynomial(a) * Polynomial(b)) % Polynomial(f)).coef))
            a_mul_b_ref = self.sign_extend(a_mul_b_ref)
            assert (a_mul_b == a_mul_b_ref)
        return 1

    # ---------------------- Vector/Matrix Operations ----------------------

    def add_vec(self, v0, v1):
        assert len(v0) == len(v1)
        return [self.add_poly(v0[i], v1[i]) for i in range(len(v0))]

    def mul_vec_simple(self, v0, v1):
        """Inner product of polynomial vectors"""
        assert len(v0) == len(v1)
        result = [0] * self.n
        for i in range(len(v0)):
            result = self.add_poly(result, self.mul_poly_simple(v0[i], v1[i]))
        return result

    def mul_mat_vec_simple(self, M, v):
        """Matrix-vector multiplication with polynomial entries"""
        return [self.mul_vec_simple(M[i], v) for i in range(len(M))]

    def transpose(self, M):
        """Transpose a 2D matrix of polynomials"""
        return [[M[j][i] for j in range(len(M))] for i in range(len(M[0]))]

    def test_mul_vec(self, f):
        degree_f = self.n
        for i in range(100):
            m = (np.random.random([self.k, self.k, degree_f]) * self.q).astype(int)
            v = (np.random.random([self.k, degree_f]) * self.q).astype(int)
            m_mul_a = self.mul_mat_vec_simple(m, v)

            m_poly = list(map(lambda x: list(map(Polynomial, x)), m))
            v_poly = list(map(Polynomial, v))
            prod = np.dot(m_poly, v_poly)
            m_mul_a_ref = list(
                map(lambda x: list(map(lambda y: int(y) % self.q, self.sign_extend((x % Polynomial(f)).coef))), prod))
            assert (m_mul_a == m_mul_a_ref)

    # ---------------------- Encryption / Decryption ----------------------

    def encrypt(self, A, t, m_bits, r, e1, e2):
        """Encrypt message bits m_bits"""
        """Based on formula:u = A^T · r + e1, v = t^T · r + e2 - encode(m)"""
        half_q = int(self.q / 2 + 0.5)
        m = [x * half_q for x in m_bits]
        u = self.add_vec(self.mul_mat_vec_simple(self.transpose(A), r), e1)
        v = self.sub_poly(self.add_poly(self.mul_vec_simple(t, r), e2), m)
        return u, v

    def decrypt(self, s, u, v):
        """Decrypt ciphertext (u, v)"""
        """Based on formula:plaintext = decode(v - s^T · u) = decode(encode(m) + 小噪声) ≈ m"""
        m_n = self.sub_poly(v, self.mul_vec_simple(s, u))
        half_q = int(self.q / 2 + 0.5)
        def round_to_bit(x):
            dist_center = abs(half_q - x)
            dist_bound = min(x, self.q - x)
            return half_q if dist_center < dist_bound else 0
        m_n = [round_to_bit(x) for x in m_n]
        m_bits = [x // half_q for x in m_n]
        return m_bits

    # ---------------------- Simple Randomized Key/Noise Setup ----------------------

    def small_noise_poly(self):
        """Centered small noise: coefficients in {-1, 0, 1} mod q"""
        return [random.choice([-1, 0, 1]) % self.q for _ in range(self.n)]

    def random_poly(self):
        return [random.randint(0, self.q - 1) for _ in range(self.n)]

    def random_vec(self):
        return [self.random_poly() for _ in range(self.k)]

    def random_mat(self):
        return [[self.random_poly() for _ in range(self.k)] for _ in range(self.k)]

    def gen_matrix_A_drbg(self, drbg, n, q):
        """ using AES256CTR_DRBG instance to produce k x k matrix of length-n polynomials with coeff in [0,q-1] """
        A = []
        for i in range(self.k):
            row = []
            for j in range(self.k):
                buf = drbg.random_bytes(2 * n)
                poly = [(buf[2 * t] | (buf[2 * t + 1] << 8)) % q for t in range(n)]
                row.append(poly)
            A.append(row)
        return A

    def cbd_eta_from_drbg(self, drbg, n):
        """
        Each coefficient uses 4 bits: (b0+b1) - (b2+b3).
        Need ceil(n*4/8) bytes from drbg.
        """
        need = ceil(n * 4 / 8)
        buf = drbg.random_bytes(need)
        poly = []
        bitpos = 0
        for _ in range(n):
            b0 = (buf[bitpos // 8] >> (bitpos % 8)) & 1;
            bitpos += 1
            b1 = (buf[bitpos // 8] >> (bitpos % 8)) & 1;
            bitpos += 1
            b2 = (buf[bitpos // 8] >> (bitpos % 8)) & 1;
            bitpos += 1
            b3 = (buf[bitpos // 8] >> (bitpos % 8)) & 1;
            bitpos += 1
            poly.append((b0 + b1) - (b2 + b3))
        return poly

    def keygen_drbg(self, seed: bytes = None):
        """Generate key pair based on formula:t = A*s + e"""
        if seed is None:
            seed = os.urandom(self.SEED_BYTES)
        drbg = AES256CTR_DRBG(seed)
        A = self.gen_matrix_A_drbg(drbg, self.n, self.q)
        s = [self.cbd_eta_from_drbg(drbg, self.n) for _ in range(self.k)]
        e = [self.cbd_eta_from_drbg(drbg, self.n) for _ in range(self.k)]
        t = []
        for i in range(self.k):
            acc = [0] * self.n
            for j in range(self.k):
                acc = self.add_poly(acc, self.mul_poly_simple(A[i][j], s[j]))
            t_i = self.add_poly(acc, e[i])
            t.append(t_i)
        pk = (seed, t)
        sk = s
        return pk, sk
    def demo_key_generation(self):
        """演示密钥生成过程"""
        print("\n" + "="*50)
        print("🔑 密钥生成演示")
        print("="*50)
        seedA = b"0123456789abcdef0123456789abcdef"  # 32 bytes
        drbg = AES256CTR_DRBG(seedA)
        A1 = kyber.gen_matrix_A_drbg(drbg, self.n, self.q)

        # reinit and generate again -> must match
        drbg2 = AES256CTR_DRBG(seedA)
        A2 = kyber.gen_matrix_A_drbg(drbg2, self.n, self.q)
        assert A1[0][0][:8] == A2[0][0][:8], "Determinism failed"

        # sample s deterministic
        drbg3 = AES256CTR_DRBG(seedA)
        # consume matrix A bytes first (keep generation order consistent) then s
        _ = kyber.gen_matrix_A_drbg(drbg3, self.n, self.q)
        s0 = [kyber.cbd_eta_from_drbg(drbg3, self.n) for _ in range(self.k)]

        # repeat -> should equal
        drbg4 = AES256CTR_DRBG(seedA)
        _ = kyber.gen_matrix_A_drbg(drbg4, self.n, self.q)
        s1 = [kyber.cbd_eta_from_drbg(drbg4, self.n) for _ in range(self.k)]
        assert s0 == s1
        print("DRBG deterministic generation OK")
        return 1

    def encrypt_drbg(self, pk, m_bits, coins_seed):
        seedA, t = pk
        drbg_coins = AES256CTR_DRBG(coins_seed)
        drbg_A = AES256CTR_DRBG(seedA)
        A = self.gen_matrix_A_drbg(drbg_A, self.n, self.q)
        r = [self.cbd_eta_from_drbg(drbg_coins, self.n) for _ in range(self.k)]
        e1 = [self.cbd_eta_from_drbg(drbg_coins, self.n) for _ in range(self.k)]
        e2 = self.cbd_eta_from_drbg(drbg_coins, self.n)
        half_q = self.q // 2
        m_poly = [(bit * half_q) % self.q for bit in m_bits]
        # Compute u = A^T * r + e1
        u = []
        for j in range(self.k):
            acc = [0] * self.n
            for i in range(self.k):
                acc = self.add_poly(acc, self.mul_poly_simple(A[i][j], r[i]))
            u_j = self.add_poly(acc, e1[j])
            u.append(u_j)
        # Compute v = t^T * r + e2 + m
        v_acc = [0] * self.n
        for i in range(self.k):
            v_acc = self.add_poly(v_acc, self.mul_poly_simple(t[i], r[i]))
        v = self.add_poly(self.add_poly(v_acc, e2), m_poly)
        return (u, v)

    # ---------------------- Demo ----------------------

    def demo(self):
        """Run a simple encrypt-decrypt round to test"""
        print("Running Baby Kyber demo...")
        failed = 0
        for i in range(self.k):
            A = self.random_mat()
            # s = self.random_vec()
            # e1 = self.random_vec()
            # e2 = self.random_poly()
            # r = self.random_vec()
            s = [self.small_noise_poly() for _ in range(self.k)]
            e1 = [self.small_noise_poly() for _ in range(self.k)]
            e2 = self.small_noise_poly()
            r = [self.small_noise_poly() for _ in range(self.k)]
            m_bits = [random.randint(0, 1) for _ in range(self.n)]
            t = self.mul_mat_vec_simple(A, s)
            u, v = self.encrypt(A, t, m_bits, r, e1, e2)
            m_dec = self.decrypt(s, u, v)
            # print("Message bits:   ", m_bits)
            # print("Decrypted bits: ", m_dec)
            # print("Success:", m_bits == m_dec)
            if not m_bits == m_dec:
                # Compute simple Hamming distance to show near-misses
                diff = sum(1 for i in range(len(m_bits)) if m_bits[i] != m_dec[i])
                print(f"Bit errors: {diff}/{len(m_bits)}")
                failed += 1
        print(failed)

    def demo_encryption_decryption(self):
        print("\n" + "=" * 50)
        print("🔒 加密解密演示")
        print("=" * 50)
        seed = b"demo_seed_1234567890123456789012"
        pk, sk = self.keygen_drbg(seed)
        message = "HELLO"
        message_bits = []
        for char in message:
            bits = format(ord(char), '08b')[:5]
            message_bits.extend([int(bit) for bit in bits])
        message_bits = message_bits[:self.n]
        while len(message_bits) < self.n:
            message_bits.append(0)
        print(f"原始消息: '{message}'")
        print(f"消息比特: {message_bits}")
        # m_bits = [random.randint(0, 1) for _ in range(self.n)]
        coins_seed = b"demo_coins_1234567890123456789012"
        ct = self.encrypt_drbg(pk, message_bits, coins_seed)
        u, v = ct
        m_dec = self.decrypt(sk, u, v)
        if message_bits == m_dec:
            print("Match! Successful Decryption with ciphertext:", ct)
        else:
            diff = sum(1 for i in range(len(message_bits)) if message_bits[i] != m_dec[i])
            print(f"  Original: {message_bits}")
            print(f"  Decrypted: {m_dec}")

    def G(self, data: bytes) -> bytes:
        """哈希函数 G - 用于消息扩展"""
        return hashlib.sha3_256(data).digest()

    def H(self, data: bytes) -> bytes:
        """哈希函数 H - 用于密钥派生"""
        return hashlib.sha256(data).digest()

    def KDF(self, data: bytes) -> bytes:
        """密钥派生函数 - 生成128位共享密钥"""
        return hashlib.sha256(data).digest()[:16]

    def serialize_pk(self, pk):
        """序列化公钥：seedA + t的所有系数"""
        seedA, t = pk
        serialized = bytearray(seedA)
        for poly in t:
            for coeff in poly:
                normalized_coeff = coeff % self.q
                serialized.extend(normalized_coeff.to_bytes(2, 'little', signed=False))
        return bytes(serialized)

    def serialize_ct(self, ct):
        """序列化密文：u的所有系数 + v的所有系数"""
        u, v = ct
        serialized = bytearray()
        for poly in u:
            for coeff in poly:
                normalized_coeff = coeff % self.q
                serialized.extend(normalized_coeff.to_bytes(2, 'little', signed=False))
        for coeff in v:
            normalized_coeff = coeff % self.q
            serialized.extend(normalized_coeff.to_bytes(2, 'little', signed=False))
        return bytes(serialized)

    def serialize_sk(self, sk):
        """序列化私钥：s的所有系数（用于拒绝情况）"""
        serialized = bytearray()
        for poly in sk:
            for coeff in poly:
                normalized_coeff = coeff % self.q
                serialized.extend(normalized_coeff.to_bytes(2, 'little', signed=False))
        return bytes(serialized)

    def ct_equal(self, ct1, ct2):
        """常数时间密文比较"""
        u1, v1 = ct1
        u2, v2 = ct2
        equal = True
        for i in range(len(u1)):
            for j in range(len(u1[i])):
                # 规范化系数后再比较
                coeff1 = u1[i][j] % self.q
                coeff2 = u2[i][j] % self.q
                if coeff1 != coeff2:
                    equal = False
        for j in range(len(v1)):
            coeff1 = v1[j] % self.q
            coeff2 = v2[j] % self.q
            if coeff1 != coeff2:
                equal = False
        return equal

    # ---------------------- FO transform ---------------------
    def encapsulate(self, pk):
        """KEM Encapsulation with FO Transform using DRBG"""
        m = os.urandom(self.SEED_BYTES)
        m_bits = bytes_to_bits(m, self.n)
        """ Generate coins seed = H(m || pk) """
        pk_bytes = self.serialize_pk(pk)
        coins_seed = self.H(m + pk_bytes)
        ct = self.encrypt_drbg(pk, m_bits, coins_seed)
        """ Derive shared key = KDF(m || ct) """
        ct_bytes = self.serialize_ct(ct)
        shared_key = self.KDF(m + ct_bytes)
        return ct, shared_key

    def decapsulate(self, sk, pk, ct):
        """KEM Decapsulation with FO Transform using DRBG """
        u, v = ct
        m_prime_bits = self.decrypt(sk, u, v)
        m_prime_bytes = bits_to_bytes(m_prime_bits)
        pk_bytes = self.serialize_pk(pk)
        coins_seed_prime = self.H(m_prime_bytes + pk_bytes)
        ct_prime = self.encrypt_drbg(pk, m_prime_bits, coins_seed_prime)
        if self.ct_equal(ct, ct_prime):
            ct_bytes = self.serialize_ct(ct)
            shared_key = self.KDF(m_prime_bytes + ct_bytes)
            print(f"🔧 解封装调试 - 使用有效分支")
        else:
            sk_bytes = self.serialize_sk(sk)
            shared_key = self.KDF(b'reject' + sk_bytes + self.serialize_ct(ct))
            print(f"🔧 解封装调试 - 使用拒绝分支")
        return shared_key

    # 更新keygen方法
    def keygen(self, seed: bytes = None):
        """Generate key pair - now using DRBG internally"""
        return self.keygen_drbg(seed)
    def demo_kem(self):
        print("\n" + "="*50)
        print("🔐 KEM (密钥封装机制) 演示")
        print("="*50)
        print("步骤1: 密钥生成")
        pk, sk = self.keygen_drbg()
        print("✅ 密钥对生成完成")
        print("\n步骤2: 封装")
        ct, K_encap = self.encapsulate(pk)
        print(f"✅ 封装完成")
        print(f"   共享密钥: {K_encap.hex()[:16]}...")
        print("\n步骤3: 解封装")
        K_decap = self.decapsulate(sk, pk, ct)
        print(f"✅ 解封装完成")
        print(f"   恢复密钥: {K_decap.hex()[:16]}...")
        if K_encap == K_decap:
            print(f"✅ 测试成功")
        else:
            print(f"❌ 测试 {i}: 失败")
        return 1
    def demo_security_features(self):
        """演示安全特性"""
        print("\n" + "=" * 50)
        print("🛡️ 安全特性演示")
        print("=" * 50)
        print("1. 确定性随机性生成 (DRBG)")
        seed = b"security_demo_seed_1234567890123"
        drbg1 = AES256CTR_DRBG(seed)
        drbg2 = AES256CTR_DRBG(seed)
        rand1 = drbg1.random_bytes(16)
        rand2 = drbg2.random_bytes(16)
        print(f"   DRBG确定性测试: {rand1 == rand2}")
        print(f"   随机字节: {rand1.hex()[:16]}...")
        print("\n2. 错误容忍性")
        pk, sk = self.keygen_drbg()
        message = [random.randint(0, 1) for _ in range(self.n)]
        ct = self.encrypt_drbg(pk, message, os.urandom(32))
        u, v = ct
        if len(v) > 0:
            v_err = v.copy()
            v_err[0] = (v_err[0] + 1) % self.q
            decrypted_err = self.decrypt(sk, u, v_err)
            errors = sum(1 for i in range(len(message)) if message[i] != decrypted_err[i])
            print(f"   单个系数错误导致的比特错误数: {errors}/{len(message)}")
        print("\n3. FO变换保护")
        print("   - 重加密验证机制")
        print("   - CCA2安全性")
        print("   - 拒绝情况下返回伪随机密钥")
    def run_comprehensive_demo(self):
        """运行完整的演示"""
        print("🚀 BabyKyber 密码学课程演示")
        print("=" * 60)
        print("本演示展示后量子密码学Kyber方案的简化实现")
        self.demo_key_generation()
        self.demo_encryption_decryption()
        self.demo_kem()
        self.demo_security_features()

        print("\n" + "=" * 60)
        print("📖 教学总结")
        print("=" * 60)
        print("1. 基于格的密码学使用多项式环上的运算")
        print("2. Kyber的安全性基于MLWE问题的困难性")
        print("3. DRBG提供确定性随机性，确保可重复性")
        print("4. FO变换提供CCA2安全性")
        print("5. 中心二项分布提供噪声采样")
        print("\n🎓 演示完成！")

if __name__ == "__main__":
    # ---------- classical kyber parameter ----------
    import time
    from itertools import product
    kyber = BabyKyber(n=256, q=3329, k=2)
    test_f = [1] + [0] * 255 + [1]
    # kyber.test_mul_poly(test_f)
    # kyber.test_mul_vec(test_f)
    # kyber.demo()
    # 测试DRBG加解密
    print("\n" + "=" * 50)
    # kyber.demo_encryption_decryption(trials=5)
    kyber.run_comprehensive_demo()

    print("🔬 Baby Kyber 扩展噪声暴力攻击教学演示")
    print("=" * 60)

    print("\n" + "=" * 60)
    print("🎓 演示完成!")
    print("=" * 60)

