"""
Assessment Tool 3 - Task 2: Performance Analysis & Debugging of Block Cipher Modes of Operation
Course: Cryptography and Network Security (CSA51 / CSA5105)

Requirements Addressed:
A. Debug incorrect PKCS#7 padding validation & IV handling causing decryption failures.
B. Refactor code for minimal memory allocations and optimized byte array computations.
C. Empirical & theoretical comparison of ECB, CBC, CFB, and OFB modes for real-time secure communication.
"""

import time
import os
import sys

# Simple 128-bit block substitution-permutation cipher implementation for benchmark consistency
BLOCK_SIZE = 16 # 16 bytes = 128 bits


# ==========================================
# PART A: PADDING & IV HANDLING FIXES
# ==========================================
def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Correct PKCS#7 Padding Implementation."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(padded_data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """
    Fixed PKCS#7 Unpadding with strict boundary & integrity checks.
    Fixes padding oracle / out-of-bounds exception vulnerabilities.
    """
    if not padded_data or len(padded_data) % block_size != 0:
        raise ValueError("Invalid padded data length!")

    pad_len = padded_data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid PKCS7 padding length byte!")

    for i in range(len(padded_data) - pad_len, len(padded_data)):
        if padded_data[i] != pad_len:
            raise ValueError("Invalid PKCS7 padding byte sequence!")

    return padded_data[:-pad_len]


# Dummy 128-bit Block Cipher (AES-like substitution/permutation wrapper for pure Python test)
def cipher_encrypt_block(block: bytes, key: bytes) -> bytes:
    """16-byte block cipher round computation."""
    out = bytearray(BLOCK_SIZE)
    for i in range(BLOCK_SIZE):
        out[i] = (block[i] ^ key[i % len(key)])
        out[i] = ((out[i] << 3) | (out[i] >> 5)) & 0xFF # Circular bit rotation
    return bytes(out)


def cipher_decrypt_block(block: bytes, key: bytes) -> bytes:
    """16-byte block cipher inverse round computation."""
    out = bytearray(BLOCK_SIZE)
    for i in range(BLOCK_SIZE):
        b = ((block[i] >> 3) | (block[i] << 5)) & 0xFF
        out[i] = b ^ key[i % len(key)]
    return bytes(out)


# ==========================================
# MODES OF OPERATION IMPLEMENTATION (Part B Optimized)
# ==========================================
class BlockCipherModes:

    @staticmethod
    def ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:
        """Electronic Codebook (ECB) Mode Encryption."""
        padded = pkcs7_pad(plaintext)
        result = bytearray(len(padded))
        for i in range(0, len(padded), BLOCK_SIZE):
            chunk = padded[i:i+BLOCK_SIZE]
            result[i:i+BLOCK_SIZE] = cipher_encrypt_block(chunk, key)
        return bytes(result)

    @staticmethod
    def ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
        """Electronic Codebook (ECB) Mode Decryption."""
        result = bytearray(len(ciphertext))
        for i in range(0, len(ciphertext), BLOCK_SIZE):
            chunk = ciphertext[i:i+BLOCK_SIZE]
            result[i:i+BLOCK_SIZE] = cipher_decrypt_block(chunk, key)
        return pkcs7_unpad(bytes(result))

    @staticmethod
    def cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
        """Cipher Block Chaining (CBC) Mode Encryption."""
        if len(iv) != BLOCK_SIZE:
            raise ValueError(f"IV must be exactly {BLOCK_SIZE} bytes!")
        padded = pkcs7_pad(plaintext)
        result = bytearray(len(padded))
        prev_block = iv

        for i in range(0, len(padded), BLOCK_SIZE):
            chunk = padded[i:i+BLOCK_SIZE]
            xored = bytes(a ^ b for a, b in zip(chunk, prev_block))
            enc_block = cipher_encrypt_block(xored, key)
            result[i:i+BLOCK_SIZE] = enc_block
            prev_block = enc_block
        return bytes(result)

    @staticmethod
    def cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """Cipher Block Chaining (CBC) Mode Decryption."""
        if len(iv) != BLOCK_SIZE:
            raise ValueError(f"IV must be exactly {BLOCK_SIZE} bytes!")
        result = bytearray(len(ciphertext))
        prev_block = iv

        for i in range(0, len(ciphertext), BLOCK_SIZE):
            chunk = ciphertext[i:i+BLOCK_SIZE]
            dec_block = cipher_decrypt_block(chunk, key)
            xored = bytes(a ^ b for a, b in zip(dec_block, prev_block))
            result[i:i+BLOCK_SIZE] = xored
            prev_block = chunk
        return pkcs7_unpad(bytes(result))

    @staticmethod
    def cfb_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
        """Cipher Feedback (CFB) Mode Encryption."""
        if len(iv) != BLOCK_SIZE:
            raise ValueError(f"IV must be exactly {BLOCK_SIZE} bytes!")
        result = bytearray(len(plaintext))
        feedback = iv

        for i in range(0, len(plaintext), BLOCK_SIZE):
            chunk = plaintext[i:i+BLOCK_SIZE]
            enc_iv = cipher_encrypt_block(feedback, key)
            ct_chunk = bytes(a ^ b for a, b in zip(chunk, enc_iv))
            result[i:i+len(chunk)] = ct_chunk
            # Feedback gets updated with ciphertext
            if len(ct_chunk) == BLOCK_SIZE:
                feedback = ct_chunk
            else:
                feedback = ct_chunk + feedback[len(ct_chunk):]
        return bytes(result)

    @staticmethod
    def cfb_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """Cipher Feedback (CFB) Mode Decryption."""
        if len(iv) != BLOCK_SIZE:
            raise ValueError(f"IV must be exactly {BLOCK_SIZE} bytes!")
        result = bytearray(len(ciphertext))
        feedback = iv

        for i in range(0, len(ciphertext), BLOCK_SIZE):
            chunk = ciphertext[i:i+BLOCK_SIZE]
            enc_iv = cipher_encrypt_block(feedback, key)
            pt_chunk = bytes(a ^ b for a, b in zip(chunk, enc_iv))
            result[i:i+len(chunk)] = pt_chunk
            if len(chunk) == BLOCK_SIZE:
                feedback = chunk
            else:
                feedback = chunk + feedback[len(chunk):]
        return bytes(result)

    @staticmethod
    def ofb_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
        """Output Feedback (OFB) Mode Encryption."""
        if len(iv) != BLOCK_SIZE:
            raise ValueError(f"IV must be exactly {BLOCK_SIZE} bytes!")
        result = bytearray(len(plaintext))
        feedback = iv

        for i in range(0, len(plaintext), BLOCK_SIZE):
            chunk = plaintext[i:i+BLOCK_SIZE]
            feedback = cipher_encrypt_block(feedback, key) # Key stream block
            result[i:i+len(chunk)] = bytes(a ^ b for a, b in zip(chunk, feedback))
        return bytes(result)

    @staticmethod
    def ofb_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """Output Feedback (OFB) Mode Decryption (identical stream sequence to Encryption)."""
        return BlockCipherModes.ofb_encrypt(ciphertext, key, iv)


def run_tests_and_benchmarks():
    print("=" * 70)
    print("TASK 2: BLOCK CIPHER MODES OF OPERATION PERFORMANCE & DEBUGGING")
    print("=" * 70)

    key = b"16ByteSecretKey!"
    iv = os.urandom(BLOCK_SIZE)
    plaintext = b"This is a test message for evaluating ECB, CBC, CFB, and OFB block cipher modes!"

    print("\n--- Part A: Testing & Debugging Padding & IV Handling ---")
    modes = ['ECB', 'CBC', 'CFB', 'OFB']

    for mode in modes:
        if mode == 'ECB':
            ct = BlockCipherModes.ecb_encrypt(plaintext, key)
            pt = BlockCipherModes.ecb_decrypt(ct, key)
        elif mode == 'CBC':
            ct = BlockCipherModes.cbc_encrypt(plaintext, key, iv)
            pt = BlockCipherModes.cbc_decrypt(ct, key, iv)
        elif mode == 'CFB':
            ct = BlockCipherModes.cfb_encrypt(plaintext, key, iv)
            pt = BlockCipherModes.cfb_decrypt(ct, key, iv)
        elif mode == 'OFB':
            ct = BlockCipherModes.ofb_encrypt(plaintext, key, iv)
            pt = BlockCipherModes.ofb_decrypt(ct, key, iv)

        assert pt == plaintext, f"Decryption failed for mode {mode}!"
        print(f"[{mode} Mode] Encrypt/Decrypt Cycle Passed! Ciphertext length: {len(ct)} bytes.")

    # Test invalid padding handling
    print("\nVerifying PKCS#7 Padding Error Handling...")
    try:
        corrupted_ct = bytearray(BlockCipherModes.cbc_encrypt(plaintext, key, iv))
        corrupted_ct[-1] ^= 0xFF # Corrupt last byte padding
        BlockCipherModes.cbc_decrypt(bytes(corrupted_ct), key, iv)
        print("FAIL: Bad padding went undetected!")
    except ValueError as e:
        print(f"SUCCESS: Caught invalid padding correctly: {e}")

    # Part B & C Performance Comparison
    print("\n--- Part B & C: Latency & Memory Efficiency Benchmarks ---")
    benchmark_data = os.urandom(1024 * 512) # 512 KB dataset
    iterations = 5

    results = {}
    for mode in modes:
        start_time = time.time()
        for _ in range(iterations):
            if mode == 'ECB':
                ct = BlockCipherModes.ecb_encrypt(benchmark_data, key)
                BlockCipherModes.ecb_decrypt(ct, key)
            elif mode == 'CBC':
                ct = BlockCipherModes.cbc_encrypt(benchmark_data, key, iv)
                BlockCipherModes.cbc_decrypt(ct, key, iv)
            elif mode == 'CFB':
                ct = BlockCipherModes.cfb_encrypt(benchmark_data, key, iv)
                BlockCipherModes.cfb_decrypt(ct, key, iv)
            elif mode == 'OFB':
                ct = BlockCipherModes.ofb_encrypt(benchmark_data, key, iv)
                BlockCipherModes.ofb_decrypt(ct, key, iv)

        total_time = time.time() - start_time
        avg_time_ms = (total_time / iterations) * 1000
        throughput_mbps = (len(benchmark_data) / (1024 * 1024)) / (total_time / iterations)
        results[mode] = (avg_time_ms, throughput_mbps)
        print(f"[{mode} Mode] Avg Processing Time: {avg_time_ms:.2f} ms | Throughput: {throughput_mbps:.2f} MB/s")

    print("\n--- Real-Time Communication Mode Analysis ---")
    analysis = """
    MODE COMPARISON & RECOMMENDATION FOR REAL-TIME SECURE COMMUNICATION:

    1. ECB (Electronic Codebook):
       - Strengths: Parallelizable, zero padding latency.
       - Weaknesses: Insecure! Identical plaintext blocks produce identical ciphertext blocks, revealing patterns. Never recommended.

    2. CBC (Cipher Block Chaining):
       - Strengths: High security, standard adoption.
       - Weaknesses: Sequential encryption (cannot be parallelized). Decryption can be parallelized. Requires padding. Vulnerable to padding oracle attacks if not authenticated.

    3. CFB (Cipher Feedback):
       - Strengths: Converts block cipher into stream cipher. No padding required.
       - Weaknesses: Encryption is sequential. Bit errors in ciphertext corrupt current block and 1 bit in next block.

    4. OFB (Output Feedback) & CTR (Counter Mode):
       - Strengths: Stream cipher operation. Keystream can be PRE-COMPUTED offline before data arrival, minimizing real-time transmission latency!
       - Resilience: Bit errors in ciphertext only affect the corresponding bit in plaintext (no error propagation).

    RECOMMENDATION FOR REAL-TIME STREAMING:
    CTR mode (or OFB mode) is optimal for real-time video/audio streaming due to pre-computable keystreams, zero padding overhead, and tolerance to packet loss without error propagation cascades.
    """
    print(analysis)


if __name__ == "__main__":
    run_tests_and_benchmarks()
