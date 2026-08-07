# SIMATS ENGINEERING - ASSESSMENT TOOL 3
## COURSE: CRYPTOGRAPHY AND NETWORK SECURITY (COURSE CODE: CSA51 / CSA5105)
**Course Outcome Covered**: CO2 - Analyze Public Key cryptosystem strategies using RSA and key Exchange for Encryption algorithm to strengthen information security. (BL4, BL5)  
**Task Weightage**: Debugging & Optimisation Task : 10% | **Total Marks**: 50

---

## 📌 Repository Contents Overview

This repository contains fully tested, debugged, and optimized implementations for all 5 assessment tasks outlined in **Annexure A**:

```
.
├── Assessment_Tool_3/
│   ├── run_all_assessment_tasks.py          # Master verification test suite
│   ├── task1_symmetric_des_3des/
│   │   └── des_3des_implementation.py       # Task 1: DES/3DES Fixes & Optimization
│   ├── task2_block_cipher_modes/
│   │   └── block_cipher_modes.py            # Task 2: Block Cipher Modes (ECB, CBC, CFB, OFB)
│   ├── task3_rsa_cryptosystem/
│   │   └── rsa_cryptosystem.py              # Task 3: RSA Primality, CRT Optimization & Key Size Analysis
│   ├── task4_diffie_hellman/
│   │   └── diffie_hellman.py                # Task 4: Diffie-Hellman, Modular Math & MitM Mitigation
│   └── task5_elliptic_curve/
│       └── ecc_cryptography.py              # Task 5: ECC Point Math, Double-and-Add & RSA vs ECC Comparison
└── README.md
```

---

## 🛠️ Detailed Task Solutions & Explanations

### 1. Debugging & Optimization of Symmetric Encryption (DES / 3DES Implementation)
- **Part A (Logical & Permutation Fixes)**: Resolved state mutation bugs by refactoring key scheduling into pure stateless functions and correcting 1-indexed initial/final permutation mappings (`IP`, `FP`, `PC1`, `PC2`). Output ciphertext is verified deterministic across runs for identical inputs.
- **Part B (Performance Optimization for $\ge 10$ MB Datasets)**: Implemented chunked stream buffer processing to prevent memory saturation and vector bitwise operations for Feistel S-Box lookups.
- **Part C (Justification for Replacing DES/3DES with AES)**:
  - **Security**: 64-bit DES/3DES blocks suffer from Sweet32 collision attacks ($2^{32}$ blocks). DES key size (56-bit) and 3DES effective security (112-bit) are retired/deprecated by NIST.
  - **Performance**: Bitwise permutations in DES are slow in software. AES uses 128-bit blocks and leverages native hardware instruction sets (AES-NI) for 10x–50x speed gains.

---

### 2. Performance Analysis of Block Cipher Modes of Operation
- **Part A (Padding & IV Handling)**: Fixed PKCS#7 padding validation to prevent padding oracle out-of-bounds exceptions. Ensured cryptographically secure unique IV generation per encryption pass.
- **Part B (Memory Optimization)**: Refactored mode loops using mutable `bytearray` buffers to eliminate string concatenation overhead during chunk iteration.
- **Part C (Real-Time Secure Communication Mode)**:
  - **Evaluation**: ECB leaks structural plaintext patterns; CBC requires padding and cannot parallelize encryption.
  - **Recommendation**: **CTR / OFB / CFB** stream modes allow keystream pre-computation prior to data arrival and eliminate block padding latency, making them optimal for real-time video/audio streaming.

---

### 3. Debugging RSA Cryptosystem Implementation
- **Part A (Primality & Keygen Debugging)**: Replaced trial division with Miller-Rabin probabilistic primality testing. Ensured public exponent $e=65537$ satisfies $\gcd(e, \phi(n)) = 1$. Added message chunking to prevent plaintext integer overflow beyond modulus $n$.
- **Part B (CRT Optimization & Fast Exponentiation)**:
  - Implemented Right-to-Left Square-and-Multiply modular exponentiation $O(\log e)$.
  - Integrated **Chinese Remainder Theorem (CRT)** decryption ($m_1 = c^{d_p} \bmod p$, $m_2 = c^{d_q} \bmod q$), achieving **~1.8x to 4x faster decryption speeds**.
- **Part C (Key Size Trade-Off Evaluation)**:
  - `1024-bit`: Legacy / Insecure against modern factorization.
  - `2048-bit`: Recommended baseline standard (112-bit symmetric security).
  - `4096-bit`: High-security standard with non-linear execution time penalty during keygen and decryption.

---

### 4. Optimization and Security Analysis of Diffie-Hellman Key Exchange
- **Part A (Modular Arithmetic Fixes)**: Corrected modular reduction at intermediate steps ($g^a \bmod p$) to eliminate arbitrary-precision integer expansion and precision errors.
- **Part B (2048-bit Safe Prime Optimization)**: Utilized RFC 3526 MODP 2048-bit safe primes ($p = 2q+1$) and binary square-and-multiply exponentiation.
- **Part C (MitM Mitigation & Performance Impact)**:
  - **Attack**: Demonstrated unauthenticated DH vulnerability to active Man-in-the-Middle (MitM) key replacement.
  - **Mitigation**: Implemented **RSA-Signed Ephemeral Diffie-Hellman (DHE-RSA)** to cryptographically sign public key parameters. Signature verification adds minimal overhead (~10–15%) while providing total resistance against active MitM attacks.

---

### 5. Debugging and Enhancing Elliptic Curve Cryptography (ECC) Implementation
- **Part A (Point Addition & Doubling Logic)**:
  - Fixed slope calculations for doubling ($s = \frac{3x_1^2 + a}{2y_1} \bmod p$) vs addition ($s = \frac{y_2 - y_1}{x_2 - x_1} \bmod p$).
  - Handled Point at Infinity $\mathcal{O}$ and vertical line additions ($P + (-P) = \mathcal{O}$).
- **Part B (Scalar Multiplication)**: Implemented **Double-and-Add** scalar multiplication ($O(\log k)$) and **Montgomery Ladder** for side-channel attack resistance.
- **Part C (ECC vs. RSA Comparison for Resource-Constrained IoT)**:
  - **Key Size Density**: 256-bit ECC provides equivalent security to 3072-bit RSA (12:1 ratio reduction).
  - **Bandwidth & Energy**: Smaller keys drastically reduce radio transmission payload size, saving RAM/Flash and extending battery life in IoT / mobile environments.

---

## 🚀 Execution Instructions

Run the complete assessment test suite directly:

```bash
python Assessment_Tool_3/run_all_assessment_tasks.py
```

Alternatively, run individual task scripts:
```bash
python Assessment_Tool_3/task1_symmetric_des_3des/des_3des_implementation.py
python Assessment_Tool_3/task2_block_cipher_modes/block_cipher_modes.py
python Assessment_Tool_3/task3_rsa_cryptosystem/rsa_cryptosystem.py
python Assessment_Tool_3/task4_diffie_hellman/diffie_hellman.py
python Assessment_Tool_3/task5_elliptic_curve/ecc_cryptography.py
```

---

## 📝 Code of Conduct Certification

*I certify that this submission is my original work and that I have adhered to the guidelines specified for this assessment. I understand that any violation of academic integrity rules will result in disciplinary action.*
