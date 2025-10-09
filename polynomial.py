import numpy as np
from numpy.polynomial.polynomial import Polynomial
import random

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
        np.random.seed(0xdeadbeef)

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

    # ---------------------- Demo ----------------------

    def demo(self, k=2):
        """Run a simple encrypt-decrypt round to test"""
        print("Running Baby Kyber demo...")
        failed = 0
        for i in range(100):
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
            else:
                print("All bits recovered correctly!")
        print(failed)


if __name__ == "__main__":
    kyber = BabyKyber(n=256, q=3329)

    test_f = [1] + [0] * 255 + [1]
    # kyber.test_mul_poly(test_f)
    # kyber.test_mul_vec(2, test_f)

    kyber.demo()
