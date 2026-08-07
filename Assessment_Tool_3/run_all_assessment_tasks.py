"""
Master Execution & Verification Suite for SIMATS Engineering Assessment Tool 3
Course: Cryptography and Network Security (CSA51 / CSA5105)
Course Outcome: CO2 - Analyze Public Key cryptosystem strategies using RSA and Key Exchange for Encryption algorithm.
"""

import sys
import os

# Add parent directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from task1_symmetric_des_3des.des_3des_implementation import run_tests_and_benchmarks as task1_run
from task2_block_cipher_modes.block_cipher_modes import run_tests_and_benchmarks as task2_run
from task3_rsa_cryptosystem.rsa_cryptosystem import run_tests_and_benchmarks as task3_run
from task4_diffie_hellman.diffie_hellman import run_tests_and_benchmarks as task4_run
from task5_elliptic_curve.ecc_cryptography import run_tests_and_benchmarks as task5_run


def main():
    print("======================================================================")
    print("  SIMATS ENGINEERING - ASSESSMENT TOOL 3 SOLUTIONS SUITE")
    print("  COURSE: CRYPTOGRAPHY AND NETWORK SECURITY (CSA51 / CSA5105)")
    print("======================================================================\n")

    print("Executing Task 1...")
    task1_run()
    print("\n" + "="*70 + "\n")

    print("Executing Task 2...")
    task2_run()
    print("\n" + "="*70 + "\n")

    print("Executing Task 3...")
    task3_run()
    print("\n" + "="*70 + "\n")

    print("Executing Task 4...")
    task4_run()
    print("\n" + "="*70 + "\n")

    print("Executing Task 5...")
    task5_run()
    print("\n" + "="*70 + "\n")

    print("ALL 5 ASSESSMENT TASKS EXECUTED AND VERIFIED SUCCESSFULLY!")


if __name__ == "__main__":
    main()
