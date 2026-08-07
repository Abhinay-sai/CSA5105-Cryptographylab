"""
Assessment Tool 3 - Task 5: Debugging and Enhancing Elliptic Curve Cryptography (ECC) Implementation
Course: Cryptography and Network Security (CSA51 / CSA5105)

Requirements Addressed:
A. Debug & fix point addition, point doubling, modular inverse, and Point-at-Infinity logic on elliptic curves.
B. Implement Double-and-Add & Montgomery Ladder scalar multiplication algorithms.
C. Comprehensive comparative analysis of ECC vs RSA for resource-constrained environments (IoT/Mobile).
"""

import time
import random
import sys


def extended_gcd(a: int, b: int):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def mod_inverse(a: int, m: int) -> int:
    """
    Part A Fix: Robust Modular Inverse under prime modulo p.
    Handles negative numbers correctly via (x % m + m) % m.
    """
    a = a % m
    gcd, x, _ = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError(f"Modular inverse does not exist for {a} mod {m}")
    return (x % m + m) % m


class EllipticCurve:
    """
    Represents an Elliptic Curve over Finite Field F_p:
    y^2 = x^3 + a*x + b (mod p)
    """

    def __init__(self, a: int, b: int, p: int, g_x: int, g_y: int, n: int):
        self.a = a
        self.b = b
        self.p = p
        self.G = (g_x, g_y) # Generator Base Point
        self.n = n # Order of base point

        # Singular curve validation: 4a^3 + 27b^2 != 0 (mod p)
        disc = (4 * (a ** 3) + 27 * (b ** 2)) % p
        if disc == 0:
            raise ValueError("Invalid curve: Discriminant is zero (singular curve)!")

    def is_on_curve(self, point: tuple) -> bool:
        """Verifies whether a point (x, y) satisfies the curve equation."""
        if point is None:
            return True # Point at Infinity O
        x, y = point
        lhs = (y ** 2) % self.p
        rhs = (x ** 3 + self.a * x + self.b) % self.p
        return lhs == rhs

    # ==========================================
    # PART A: FIXED POINT ADDITION & DOUBLING LOGIC
    # ==========================================
    def point_addition(self, P: tuple, Q: tuple) -> tuple:
        """
        Part A Fix: Correct Point Addition logic handling:
        1. Point at Infinity O (identity element).
        2. Vertical line addition P + (-P) = O where x1 = x2, y1 = -y2 mod p.
        3. Point Doubling P == Q.
        4. General Point Addition P != Q.
        """
        # Case 1: Point at Infinity handling
        if P is None:
            return Q
        if Q is None:
            return P

        x1, y1 = P
        x2, y2 = Q

        # Case 2: P + (-P) = Point at Infinity
        if x1 == x2 and (y1 + y2) % self.p == 0:
            return None

        # Case 3: Point Doubling (P == Q)
        if P == Q:
            if y1 == 0:
                return None # Tangent line is vertical
            # Slope s = (3*x1^2 + a) / (2*y1) mod p
            num = (3 * (x1 ** 2) + self.a) % self.p
            den = (2 * y1) % self.p
            s = (num * mod_inverse(den, self.p)) % self.p
        else:
            # Case 4: General Addition (P != Q)
            # Slope s = (y2 - y1) / (x2 - x1) mod p
            num = (y2 - y1) % self.p
            den = (x2 - x1) % self.p
            s = (num * mod_inverse(den, self.p)) % self.p

        # Compute resulting point R = (x3, y3)
        # x3 = s^2 - x1 - x2 mod p
        # y3 = s*(x1 - x3) - y1 mod p
        x3 = (s ** 2 - x1 - x2) % self.p
        y3 = (s * (x1 - x3) - y1) % self.p

        return (x3, y3)

    # ==========================================
    # PART B: OPTIMIZED SCALAR MULTIPLICATION
    # ==========================================
    def scalar_mult_naive(self, k: int, P: tuple) -> tuple:
        """Naive O(k) repeated addition (Extremely slow for 256-bit scalars!)."""
        result = None
        for _ in range(k):
            result = self.point_addition(result, P)
        return result

    def scalar_mult_double_and_add(self, k: int, P: tuple) -> tuple:
        """
        Part B Optimization: Fast Double-and-Add Scalar Multiplication.
        Time Complexity: O(log k) group operations.
        """
        result = None # Point at Infinity O
        addend = P

        while k > 0:
            if k & 1:
                result = self.point_addition(result, addend)
            addend = self.point_addition(addend, addend) # Point doubling
            k >>= 1

        return result

    def scalar_mult_montgomery_ladder(self, k: int, P: tuple) -> tuple:
        """
        Part B Enhancement: Montgomery Ladder Scalar Multiplication.
        Provides constant-time execution resistant to side-channel timing attacks.
        """
        r0 = None # Point at Infinity O
        r1 = P

        for bit in bin(k)[2:]:
            if bit == '0':
                r1 = self.point_addition(r0, r1)
                r0 = self.point_addition(r0, r0)
            else:
                r0 = self.point_addition(r0, r1)
                r1 = self.point_addition(r1, r1)

        return r0


# Standard secp256k1 Curve Definition (Bitcoin / Ethereum curve)
SECP256K1 = EllipticCurve(
    a=0,
    b=7,
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    g_x=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    g_y=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
)


def run_tests_and_benchmarks():
    print("=" * 70)
    print("TASK 5: DEBUGGING & ENHANCING ELLIPTIC CURVE CRYPTOGRAPHY (ECC)")
    print("=" * 70)

    # Test Part A: Point Addition & Doubling Logic
    print("\n--- Part A: Verifying Point Addition, Doubling, & Identity Laws ---")
    curve = SECP256K1
    G = curve.G

    print(f"Generator Point G is on curve: {curve.is_on_curve(G)}")
    assert curve.is_on_curve(G), "Base generator point G is not on the curve!"

    # Test P + O = P
    g_plus_o = curve.point_addition(G, None)
    print(f"G + O == G: {g_plus_o == G}")
    assert g_plus_o == G, "G + O must equal G!"

    # Test P + (-P) = O
    neg_G = (G[0], (-G[1]) % curve.p)
    g_plus_neg_g = curve.point_addition(G, neg_G)
    print(f"G + (-G) == O (None): {g_plus_neg_g is None}")
    assert g_plus_neg_g is None, "G + (-G) must yield Point at Infinity!"

    # Test Point Doubling 2G
    double_G = curve.point_addition(G, G)
    print(f"Point Doubling 2G on curve: {curve.is_on_curve(double_G)}")
    assert curve.is_on_curve(double_G), "2G must lie on the elliptic curve!"

    # Test Part B: Scalar Multiplication Algorithms
    print("\n--- Part B: Double-and-Add & Montgomery Ladder Benchmarks ---")
    k = random.randint(1, 10**6)

    t0 = time.time()
    p_daa = curve.scalar_mult_double_and_add(k, G)
    t_daa = time.time() - t0

    t1 = time.time()
    p_mont = curve.scalar_mult_montgomery_ladder(k, G)
    t_mont = time.time() - t1

    assert p_daa == p_mont, "Double-and-Add and Montgomery Ladder results mismatch!"
    assert curve.is_on_curve(p_daa), "Scalar multiplication result is not on curve!"

    print(f"Scalar k: {k}")
    print(f"Double-and-Add Execution Time:      {t_daa * 1000:.3f} ms")
    print(f"Montgomery Ladder Execution Time:   {t_mont * 1000:.3f} ms (Side-channel resistant)")

    # ECC Key Exchange Simulation (ECDH)
    print("\n--- Elliptic Curve Diffie-Hellman (ECDH) Key Exchange Test ---")
    alice_priv = random.randint(1, curve.n - 1)
    alice_pub = curve.scalar_mult_double_and_add(alice_priv, G)

    bob_priv = random.randint(1, curve.n - 1)
    bob_pub = curve.scalar_mult_double_and_add(bob_priv, G)

    # Alice computes S = alice_priv * bob_pub
    # Bob computes S = bob_priv * alice_pub
    s_alice = curve.scalar_mult_double_and_add(alice_priv, bob_pub)
    s_bob = curve.scalar_mult_double_and_add(bob_priv, alice_pub)

    assert s_alice == s_bob, "ECDH Key Agreement failed!"
    print(f"ECDH Key Agreement Successful! Shared Point X-Coord: {hex(s_alice[0])[:30]}...")

    # Part C Evaluation: ECC vs RSA Comparison
    print("\n--- Part C: Comparative Analysis (ECC vs RSA for Resource-Constrained Environments) ---")
    comparison = """
    ECC vs RSA COMPARATIVE SECURITY AND EFFICIENCY ANALYSIS:

    +-------------------+--------------------+--------------------+-----------------------+
    | Security Level    | RSA Key Size (bits)| ECC Key Size (bits)| Key Size Ratio        |
    +-------------------+--------------------+--------------------+-----------------------+
    | 80-bit (Legacy)   | 1024               | 160                | 1 : 6.4               |
    | 112-bit (Standard)| 2048               | 224                | 1 : 9.1               |
    | 128-bit (High)    | 3072               | 256                | 1 : 12.0              |
    | 256-bit (Ultra)   | 15360              | 512                | 1 : 30.0              |
    +-------------------+--------------------+--------------------+-----------------------+

    SUITABILITY FOR RESOURCE-CONSTRAINED ENVIRONMENTS (IoT, Microcontrollers, Smartcards):

    1. Key Size & Storage Footprint:
       - 256-bit ECC provides equivalent security to 3072-bit RSA while requiring 1/12th the key storage space.
       - Reduces EEPROM/RAM utilization and memory buffer requirements on microcontrollers.

    2. Bandwidth & Energy Consumption:
       - Transmitting 256-bit public keys and signatures uses significantly less wireless bandwidth (BLE, LoRaWAN, Zigbee) compared to 3072-bit RSA certificates.
       - Reduces radio transmission energy, drastically extending battery life in IoT sensors.

    3. Computational Efficiency:
       - Scalar multiplication on 256-bit ECC requires far fewer CPU cycles than modular exponentiation on 3072-bit integers, yielding faster signatures and key exchanges on low-power CPUs.

    Conclusion: Elliptic Curve Cryptography (ECC) is superior to RSA in resource-constrained environments due to drastically smaller keys, lower battery drain, and higher security density.
    """
    print(comparison)


if __name__ == "__main__":
    run_tests_and_benchmarks()
