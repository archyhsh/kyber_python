import numpy as np
from itertools import product


class SimpleBabyKyberAttack:
    def __init__(self, n=4, q=17, k=2):
        self.n = n
        self.q = q
        self.k = k
        print(f"初始化简单暴力攻击: n={n}, q={q}, k={k}")

    def add_poly(self, a, b):
        """多项式加法 mod q"""
        result = [0] * self.n
        for i in range(self.n):
            result[i] = (a[i] + b[i]) % self.q
        return result

    def mul_poly_simple(self, a, b):
        """多项式乘法 mod (x^n + 1, q)"""
        tmp = [0] * (2 * self.n - 1)
        for i in range(self.n):
            for j in range(self.n):
                tmp[i + j] = (tmp[i + j] + a[i] * b[j]) % self.q

        # 模 x^n + 1 约简
        result = [0] * self.n
        for i in range(self.n):
            result[i] = tmp[i]
        for i in range(self.n, len(tmp)):
            result[i - self.n] = (result[i - self.n] - tmp[i]) % self.q
        return result

    def mul_mat_vec(self, A, s):
        """矩阵向量乘法 A*s"""
        result = []
        for i in range(self.k):
            acc = [0] * self.n
            for j in range(self.k):
                prod = self.mul_poly_simple(A[i][j], s[j])
                acc = self.add_poly(acc, prod)
            result.append(acc)
        return result

    def generate_test_instance(self):
        """生成一个测试实例：A, s, e, t = A*s + e"""
        # 随机矩阵A
        A = []
        for i in range(self.k):
            row = []
            for j in range(self.k):
                poly = [np.random.randint(0, self.q) for _ in range(self.n)]
                row.append(poly)
            A.append(row)

        # 小秘密s (系数在{-1,0,1})
        s = []
        for _ in range(self.k):
            poly = [np.random.choice([-1, 0, 1]) for _ in range(self.n)]
            s.append(poly)

        # 小误差e (系数在{-1,0,1})
        e = []
        for _ in range(self.k):
            poly = [np.random.choice([-1, 0, 1]) for _ in range(self.n)]
            e.append(poly)

        # 计算 t = A*s + e
        As = self.mul_mat_vec(A, s)
        t = []
        for i in range(self.k):
            t.append(self.add_poly(As[i], e[i]))

        return A, s, e, t

    def brute_force_search(self, A, t):
        """
        最简单的暴力攻击：穷举所有可能的秘密向量s
        假设s的系数在{-1,0,1}中
        """
        print(f"\n🚀 开始暴力穷举攻击...")
        print(f"参数: n={self.n}, q={self.q}, k={self.k}")

        # 可能的系数值
        possible_coeffs = [-1, 0, 1]
        total_combinations = (len(possible_coeffs) ** self.n) ** self.k
        print(f"搜索空间大小: {total_combinations} 种可能")

        tested = 0
        found = False

        # 生成所有可能的s向量组合
        for s_coeffs in product(product(possible_coeffs, repeat=self.n), repeat=self.k):
            tested += 1

            # 显示进度
            if tested % 1000 == 0:
                print(f"已测试: {tested}/{total_combinations}")

            s_candidate = [list(coeffs) for coeffs in s_coeffs]

            # 计算 A * s_candidate
            As_candidate = self.mul_mat_vec(A, s_candidate)

            # 检查是否与t接近（考虑小误差e）
            match = True
            max_error = 0
            for i in range(self.k):
                for j in range(self.n):
                    error = abs(As_candidate[i][j] - t[i][j])
                    # 考虑模q的环绕
                    error = min(error, self.q - error)
                    max_error = max(max_error, error)
                    if error > 2:  # 允许最大误差为2（因为e的系数在{-1,0,1}）
                        match = False
                        break
                if not match:
                    break

            if match:
                print(f"\n✅ 攻击成功！在第 {tested} 次尝试找到秘密s")
                print(f"最大误差: {max_error}")
                print(f"找到的 s: {s_candidate}")

                # 验证结果
                print("\n🔍 验证:")
                As_found = self.mul_mat_vec(A, s_candidate)
                e_found = []
                for i in range(self.k):
                    e_poly = [(t[i][j] - As_found[i][j]) % self.q for j in range(self.n)]
                    # 调整到 [-q/2, q/2] 范围
                    for j in range(self.n):
                        if e_poly[j] > self.q // 2:
                            e_poly[j] -= self.q
                    e_found.append(e_poly)
                    print(f"t[{i}] = A*s[{i}] + e[{i}]")
                    print(f"  A*s[{i}]: {As_found[i]}")
                    print(f"  e[{i}]:   {e_poly}")
                    print(f"  t[{i}]:   {t[i]}")

                found = True
                return s_candidate, e_found

        print(f"\n❌ 攻击失败，测试了所有 {tested} 种可能")
        return None, None

    def demonstrate_attack(self):
        """演示完整的攻击过程"""
        print("=" * 60)
        print("🔓 BabyKyber 简单暴力攻击演示")
        print("=" * 60)

        # 1. 生成测试实例
        print("\n1. 🎲 生成Kyber实例...")
        A, true_s, true_e, t = self.generate_test_instance()

        print("公钥矩阵 A:")
        for i in range(self.k):
            for j in range(self.k):
                print(f"  A[{i}][{j}] = {A[i][j]}")

        print(f"\n真实秘密 s: {true_s}")
        print(f"真实误差 e: {true_e}")
        print(f"目标向量 t: {t}")

        # 验证 t = A*s + e
        As = self.mul_mat_vec(A, true_s)
        print("\n验证 t = A*s + e:")
        for i in range(self.k):
            computed_t = self.add_poly(As[i], true_e[i])
            print(f"  t[{i}]: {t[i]} = A*s[{i}] + e[{i}] = {computed_t}")

        # 2. 执行攻击
        print("\n2. 🔨 开始暴力攻击...")
        found_s, found_e = self.brute_force_search(A, t)

        # 3. 结果分析
        print("\n3. 📊 攻击结果分析:")
        if found_s:
            print("✅ 攻击成功恢复秘密!")
            print(f"   真实 s: {true_s}")
            print(f"   找到 s: {found_s}")
            print(f"   真实 e: {true_e}")
            print(f"   找到 e: {found_e}")

            # 检查是否完全匹配
            if found_s == true_s:
                print("🎉 完美恢复秘密向量!")
            else:
                print("⚠️  找到等效秘密（可能不是原始向量）")
        else:
            print("❌ 攻击失败")

        return found_s is not None


# 运行演示
if __name__ == "__main__":
    print("针对极小参数的 BabyKyber 暴力攻击演示")
    print("参数: n=4, q=17, k=2")
    print("=" * 50)

    # 对于 n=4 的攻击
    attacker_n4 = SimpleBabyKyberAttack(n=4, q=17, k=2)
    success_n4 = attacker_n4.demonstrate_attack()

    print("\n" + "=" * 50)

    # 对于 n=8 的攻击（搜索空间更大）
    print("\n尝试 n=8 的参数（搜索空间更大）:")
    attacker_n8 = SimpleBabyKyberAttack(n=8, q=17, k=2)

    # 对于n=8，搜索空间太大，我们只演示生成实例而不运行完整攻击
    A, true_s, true_e, t = attacker_n8.generate_test_instance()
    possible_combinations = (3 ** 8) ** 2  # 3^8 * 3^8
    print(f"n=8时的搜索空间: {possible_combinations} 种可能")
    print("这在实际中不可行，显示了为什么需要更大的参数保证安全")

