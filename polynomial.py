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
    """固定转换：32字节 → 256比特（对于n=256）或填充/截断到n比特"""
    bits = []
    # 转换所有字节为比特
    for byte in data:
        for i in range(8):
            bits.append((byte >> i) & 1)

    # 对于baby参数(n=4)，只取前4个比特
    # 对于标准参数(n=256)，正好是32字节 × 8 = 256比特
    return bits[:n_bits]


def bits_to_bytes(bits):
    """固定转换：n比特 → 32字节（固定长度）"""
    bytes_list = []

    # 先转换所有完整的比特组
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bits) and bits[i + j]:
                byte |= (1 << j)
        bytes_list.append(byte)

    # 填充到32字节（固定长度）
    while len(bytes_list) < 32:
        bytes_list.append(0)

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
    def __init__(self, n=4, q=17):
        """
        Initialize a simple Kyber-like scheme.
        :param n: Polynomial degree (default 4 for simplicity)
        :param q: Modulus for coefficients
        """
        self.n = n
        self.q = q
        self.f = [1] + [0] * (n - 1) + [1]  # x^n + 1
        self.seed = np.random.seed(0xdeadbeef)
        self.SEED_BYTES = 32

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

    def test_mul_vec(self, k, f):
        degree_f = self.n

        for i in range(100):
            m = (np.random.random([k, k, degree_f]) * self.q).astype(int)
            v = (np.random.random([k, degree_f]) * self.q).astype(int)
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
        half_q = int(self.q / 2 + 0.5)
        m = [x * half_q for x in m_bits]

        u = self.add_vec(self.mul_mat_vec_simple(self.transpose(A), r), e1)
        v = self.sub_poly(self.add_poly(self.mul_vec_simple(t, r), e2), m)

        return u, v

    def decrypt(self, s, u, v):
        """Decrypt ciphertext (u, v)"""
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

    def random_vec(self, k):
        return [self.random_poly() for _ in range(k)]

    def random_mat(self, k):
        return [[self.random_poly() for _ in range(k)] for _ in range(k)]

    def gen_matrix_A_drbg(self, drbg, k, n, q):
        """
        drbg: AES256CTR_DRBG instance
        produce k x k matrix of length-n polynomials with coeff in [0,q-1]
        domain separation: simply consume bytes consecutively (drbg counter ensures uniqueness)
        """
        A = []
        for i in range(k):
            row = []
            for j in range(k):
                # need 2*n bytes (uint16 per coeff) — toy approach
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
            poly.append((b0 + b1) - (b2 + b3))  # value in {-2,-1,0,1,2}
        return poly

    def test_drbg(self, k):
        seedA = b"0123456789abcdef0123456789abcdef"  # 32 bytes
        drbg = AES256CTR_DRBG(seedA)
        A1 = kyber.gen_matrix_A_drbg(drbg, k, self.n, self.q)

        # reinit and generate again -> must match
        drbg2 = AES256CTR_DRBG(seedA)
        A2 = kyber.gen_matrix_A_drbg(drbg2, k, self.n, self.q)
        assert A1[0][0][:8] == A2[0][0][:8], "Determinism failed"

        # sample s deterministic
        drbg3 = AES256CTR_DRBG(seedA)
        # consume matrix A bytes first (keep generation order consistent) then s
        _ = kyber.gen_matrix_A_drbg(drbg3, k, self.n, self.q)
        s0 = [kyber.cbd_eta_from_drbg(drbg3, self.n) for _ in range(k)]

        # repeat -> should equal
        drbg4 = AES256CTR_DRBG(seedA)
        _ = kyber.gen_matrix_A_drbg(drbg4, k, self.n, self.q)
        s1 = [kyber.cbd_eta_from_drbg(drbg4, self.n) for _ in range(k)]
        assert s0 == s1
        print("DRBG deterministic generation OK")

        return 1

    def keygen_drbg(self, k, seed: bytes = None):
        """Generate key pair using DRBG for all randomness"""
        if seed is None:
            seed = os.urandom(self.SEED_BYTES)

        drbg = AES256CTR_DRBG(seed)

        # Generate matrix A
        A = self.gen_matrix_A_drbg(drbg, k, self.n, self.q)

        # Sample secret s and error e from same DRBG
        s = [self.cbd_eta_from_drbg(drbg, self.n) for _ in range(k)]
        e = [self.cbd_eta_from_drbg(drbg, self.n) for _ in range(k)]

        # Compute t = A*s + e
        t = []
        for i in range(k):
            acc = [0] * self.n
            for j in range(k):
                acc = self.add_poly(acc, self.mul_poly_simple(A[i][j], s[j]))
            t_i = self.add_poly(acc, e[i])
            t.append(t_i)

        pk = (seed, t)
        sk = s
        return pk, sk

    def encrypt_drbg(self, k, pk, m_bits, coins_seed):
        """Encrypt using DRBG for all randomness"""
        seedA, t = pk
        drbg_coins = AES256CTR_DRBG(coins_seed)

        # Regenerate A from seed
        drbg_A = AES256CTR_DRBG(seedA)
        A = self.gen_matrix_A_drbg(drbg_A, k, self.n, self.q)

        # Sample all randomness from coins DRBG
        r = [self.cbd_eta_from_drbg(drbg_coins, self.n) for _ in range(k)]
        e1 = [self.cbd_eta_from_drbg(drbg_coins, self.n) for _ in range(k)]
        e2 = self.cbd_eta_from_drbg(drbg_coins, self.n)

        # Encode message
        half_q = self.q // 2
        m_poly = [(bit * half_q) % self.q for bit in m_bits]

        # Compute u = A^T * r + e1
        u = []
        for j in range(k):
            acc = [0] * self.n
            for i in range(k):
                acc = self.add_poly(acc, self.mul_poly_simple(A[i][j], r[i]))
            u_j = self.add_poly(acc, e1[j])
            u.append(u_j)

        # Compute v = t^T * r + e2 + m
        v_acc = [0] * self.n
        for i in range(k):
            v_acc = self.add_poly(v_acc, self.mul_poly_simple(t[i], r[i]))
        v = self.add_poly(self.add_poly(v_acc, e2), m_poly)

        return (u, v)

    # ---------------------- Demo ----------------------

    def demo(self, k=2):
        """Run a simple encrypt-decrypt round to test"""
        print("Running Baby Kyber demo...")
        failed = 0
        for i in range(k):
            A = self.random_mat(k)
            # s = self.random_vec(k)
            # e1 = self.random_vec(k)
            # e2 = self.random_poly()
            # r = self.random_vec(k)
            s = [self.small_noise_poly() for _ in range(k)]
            e1 = [self.small_noise_poly() for _ in range(k)]
            e2 = self.small_noise_poly()
            r = [self.small_noise_poly() for _ in range(k)]
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

    def demo_drbg(self, k=2, trials=10):
        """Test encryption/decryption with DRBG"""
        print("Running Baby Kyber DRBG demo...")

        success_count = 0
        for i in range(trials):
            # Use fixed seed for reproducibility
            seed = b"test_seed_1234567890123456789012"  # 32 bytes

            # Key generation with DRBG
            pk, sk = self.keygen_drbg(k, seed)

            # Generate random message
            m_bits = [random.randint(0, 1) for _ in range(self.n)]

            # Encrypt with DRBG
            coins_seed = b"encrypt_coins_1234567890123456"  # 32 bytes
            ct = self.encrypt_drbg(k, pk, m_bits, coins_seed)

            u, v = ct
            # Decrypt
            m_dec = self.decrypt(sk, u, v)

            if m_bits == m_dec:
                success_count += 1
                print(f"Trial {i}: SUCCESS")
            else:
                diff = sum(1 for i in range(len(m_bits)) if m_bits[i] != m_dec[i])
                print(f"Trial {i}: FAIL - {diff}/{len(m_bits)} bit errors")
                print(f"  Original: {m_bits}")
                print(f"  Decrypted: {m_dec}")

        print(f"DRBG demo success rate: {success_count}/{trials}")

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
        serialized = bytearray(seedA)  # 首先是32字节的种子

        # 然后添加t的所有多项式系数
        for poly in t:
            for coeff in poly:
                # 确保系数在[0, q-1]范围内
                normalized_coeff = coeff % self.q
                serialized.extend(normalized_coeff.to_bytes(2, 'little', signed=False))

        return bytes(serialized)

    def serialize_ct(self, ct):
        """序列化密文：u的所有系数 + v的所有系数"""
        u, v = ct
        serialized = bytearray()

        # 序列化u向量（k个多项式）
        for poly in u:
            for coeff in poly:
                normalized_coeff = coeff % self.q
                serialized.extend(normalized_coeff.to_bytes(2, 'little', signed=False))

        # 序列化v多项式
        for coeff in v:
            normalized_coeff = coeff % self.q
            serialized.extend(normalized_coeff.to_bytes(2, 'little', signed=False))

        return bytes(serialized)

    def serialize_sk(self, sk):
        """序列化私钥：s的所有系数（用于拒绝情况）"""
        serialized = bytearray()
        for poly in sk:
            for coeff in poly:
                # 私钥可能有负系数，需要规范化
                normalized_coeff = coeff % self.q
                serialized.extend(normalized_coeff.to_bytes(2, 'little', signed=False))
        return bytes(serialized)

    def ct_equal(self, ct1, ct2):
        """常数时间密文比较"""
        u1, v1 = ct1
        u2, v2 = ct2

        # 比较u向量（k个多项式）
        equal = True
        for i in range(len(u1)):
            for j in range(len(u1[i])):
                # 规范化系数后再比较
                coeff1 = u1[i][j] % self.q
                coeff2 = u2[i][j] % self.q
                if coeff1 != coeff2:
                    equal = False

        # 比较v多项式
        for j in range(len(v1)):
            coeff1 = v1[j] % self.q
            coeff2 = v2[j] % self.q
            if coeff1 != coeff2:
                equal = False

        return equal

    # ---------------------- FO transform ---------------------
    def encapsulate(self, k, pk):
        """KEM Encapsulation with FO Transform using DRBG"""
        # 1. Generate random message m
        m = os.urandom(self.SEED_BYTES)
        # m = b'\x87\xcc\xd4\x04(\xc6\xcek\xa5)\xe7\xa2Z\x9e\xab\xc9H\xad!W8\x95S\xf9;\x8fV\x95\x8fl4c'

        # 2. Derive m_bits from m using G
        # m_expanded = self.G(m)
        # print(f"🔧 调试 - m_expanded: {m_expanded.hex()}")
        # m_bits = bytes_to_bits(m_expanded, self.n)
        m_bits = bytes_to_bits(m, self.n)

        # 3. Generate coins seed = H(m || pk)
        pk_bytes = self.serialize_pk(pk)
        coins_seed = self.H(m + pk_bytes)

        # 4. Encrypt with deterministic randomness using DRBG
        ct = self.encrypt_drbg(k, pk, m_bits, coins_seed)
        u, v = ct

        # 5. Derive shared key = KDF(m || ct)
        ct_bytes = self.serialize_ct(ct)
        shared_key = self.KDF(m + ct_bytes)

        return ct, shared_key

    def decapsulate(self, k, sk, pk, ct):
        """KEM Decapsulation with FO Transform using DRBG"""
        u, v = ct
        # 1. Decrypt to get m'
        m_prime_bits = self.decrypt(sk, u, v)
        m_prime_bytes = bits_to_bytes(m_prime_bits)

        # 2. Recompute coins seed' = H(m' || pk)
        pk_bytes = self.serialize_pk(pk)
        coins_seed_prime = self.H(m_prime_bytes + pk_bytes)

        # 3. Re-encrypt to verify ciphertext using DRBG
        ct_prime = self.encrypt_drbg(k, pk, m_prime_bits, coins_seed_prime)
        u_prime, v_prime = ct_prime

        # 4. Check ciphertext consistency
        if self.ct_equal(ct, ct_prime):
            # Valid case: derive shared key = KDF(m' || ct)
            ct_bytes = self.serialize_ct(ct)
            shared_key = self.KDF(m_prime_bytes + ct_bytes)
            print(f"🔧 解封装调试 - 使用有效分支")
        else:
            # Invalid case: return random-looking key using sk as seed
            sk_bytes = self.serialize_sk(sk)
            shared_key = self.KDF(b'reject' + sk_bytes + self.serialize_ct(ct))
            print(f"🔧 解封装调试 - 使用拒绝分支")

        return shared_key

    # 更新keygen方法
    def keygen(self, k, seed: bytes = None):
        """Generate key pair - now using DRBG internally"""
        return self.keygen_drbg(k, seed)

    def test_basic_kem(self, k, trials=10):
        """测试正常情况下的KEM功能"""
        print("=== 基础KEM功能测试 ===")
        successes = 0
        for i in range(trials):
            fixed_seed = b"fixed_key_seed_12345678901234567"
            pk, sk = self.keygen(k, fixed_seed)
            ct, K_encap = self.encapsulate(k, pk)
            K_decap = self.decapsulate(k, sk, pk, ct)

            if K_encap == K_decap:
                successes += 1
                print(f"✅ 测试 {i}: 成功")
            else:
                print(f"❌ 测试 {i}: 失败")

        print(f"成功率: {successes}/{trials}")
        return successes == trials

    def test_cca_protection(self, k):
        """测试FO Transform对CCA攻击的防护"""
        print("\n=== CCA攻击防护测试 ===")

        # 正常流程
        pk, sk = self.keygen(k)
        original_ct, original_K = self.encapsulate(k, pk)

        # 模拟攻击者修改密文
        u, v = original_ct
        modified_v = v.copy()
        modified_v[0] = (modified_v[0] + 1) % self.q  # 轻微修改
        modified_ct = (u, modified_v)

        # 尝试解封装被修改的密文
        recovered_K = self.decapsulate(k, sk, pk, modified_ct)

        print(f"原始密钥: {original_K.hex()[:16]}...")
        print(f"恢复密钥: {recovered_K.hex()[:16]}...")

        if original_K != recovered_K:
            print("✅ CCA防护成功：修改的密文产生了不同的密钥")
            return True
        else:
            print("❌ CCA防护失败：攻击者可能获得有效密钥")
            return False

    def test_reencryption_verification(self, k):
        """测试重加密验证机制"""
        print("\n=== 重加密验证测试 ===")

        pk, sk = self.keygen(k)

        # 正常加密
        m = os.urandom(self.SEED_BYTES)
        # m_expanded = self.G(m)
        # m_bits = bytes_to_bits(m_expanded, self.n)
        m_bits = bytes_to_bits(m, self.n)
        pk_bytes = self.serialize_pk(pk)
        coins_seed = self.H(m + pk_bytes)
        ct = self.encrypt_drbg(k, pk, m_bits, coins_seed)

        # 解密并重加密
        u, v = ct
        m_prime_bits = self.decrypt(sk, u, v)
        m_prime_bytes = bits_to_bytes(m_prime_bits)
        coins_seed_prime = self.H(m_prime_bytes + pk_bytes)
        ct_prime = self.encrypt_drbg(k, pk, m_prime_bits, coins_seed_prime)

        print(f"原始密文: {self.serialize_ct(ct).hex()[:32]}...")
        print(f"重加密文: {self.serialize_ct(ct_prime).hex()[:32]}...")
        print(f"密文一致: {self.ct_equal(ct, ct_prime)}")

        return self.ct_equal(ct, ct_prime)

    def test_randomness_properties(self, k, trials=5):
        """测试随机性属性"""
        print("\n=== 随机性属性测试 ===")

        pk, sk = self.keygen(k)

        # 测试相同消息产生不同密文
        print("测试1: 相同消息 → 不同密文")
        m = os.urandom(self.SEED_BYTES)
        m_expanded = self.G(m)
        m_bits = bytes_to_bits(m_expanded, self.n)

        ct_set = set()
        for i in range(trials):
            # 每次使用不同的随机性
            random_suffix = os.urandom(8)
            coins_seed = self.H(m + random_suffix + self.serialize_pk(pk))
            ct = self.encrypt_drbg(k, pk, m_bits, coins_seed)
            ct_bytes = self.serialize_ct(ct)
            ct_set.add(ct_bytes.hex())

        print(f"生成 {len(ct_set)} 个唯一密文 / {trials} 次尝试")

        # 测试不同消息产生不同密钥
        print("测试2: 不同消息 → 不同密钥")
        key_set = set()
        for i in range(trials):
            ct, K = self.encapsulate(k, pk)
            key_set.add(K.hex())

        print(f"生成 {len(key_set)} 个唯一密钥 / {trials} 次尝试")

        return len(ct_set) == trials and len(key_set) == trials

    def run_security_test_suite(self, k):
        """运行完整的安全测试套件"""
        print("=" * 50)
        print("Kyber KEM 安全测试套件")
        print("=" * 50)

        tests = [
            ("基础KEM功能", lambda: self.test_basic_kem(k)),
            ("CCA攻击防护", lambda: self.test_cca_protection(k)),
            ("重加密验证", lambda: self.test_reencryption_verification(k)),
            ("随机性属性", lambda: self.test_randomness_properties(k))
        ]

        results = []
        for test_name, test_func in tests:
            try:
                success = test_func()
                results.append((test_name, success))
                status = "✅ 通过" if success else "❌ 失败"
                print(f"{test_name}: {status}")
            except Exception as e:
                results.append((test_name, False))
                print(f"{test_name}: ❌ 错误 - {e}")

        print("\n" + "=" * 50)
        passed = sum(1 for _, success in results if success)
        total = len(results)
        print(f"测试结果: {passed}/{total} 通过")

        return all(success for _, success in results)

if __name__ == "__main__":
    # ---------- classical kyber parameter ----------
    kyber = BabyKyber(n=256, q=3329)
    test_f = [1] + [0] * 255 + [1]

    # ---------- baby kyber ----------
    # kyber = BabyKyber(n=4, q=257) #q=17 noise is too large!
    # test_f = [1] + [0] * 3 + [1]

    # kyber.test_mul_poly(test_f)
    # kyber.test_mul_vec(2, test_f)
    kyber.demo()
    # kyber.test_drbg(2)
    # 测试DRBG加解密
    print("\n" + "=" * 50)
    kyber.demo_drbg(trials=5)
    kyber.run_security_test_suite(k=2)