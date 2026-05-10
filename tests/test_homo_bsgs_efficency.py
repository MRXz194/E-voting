"""
Benchmark: Homomorphic Tally + BSGS vs Traditional Approach
Place this file in: tests/test_efficency.py (already there)
Run from project ROOT: python -m tests.test_efficency
"""

import sys
import os
import random
import time

# Fix import path — point to project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.elgamal import (
    elgamal_keygen,
    elgamal_encrypt,
    elgamal_decrypt,
    homomorphic_tally,
    recover_tally,
    Ciphertext,
)
from crypto.utils import mod_pow, baby_step_giant_step

# ── Setup: generate keys once ─────────────────────────────────────────────────
print("Generating ElGamal keys (256-bit safe prime)... please wait.")
pub, priv = elgamal_keygen(bits=256)
print("Keys ready.\n")

RUNS = 3  # average over multiple runs

# ── Brute force DLog (traditional baseline) ───────────────────────────────────
def brute_force_dlog(g: int, target: int, p: int, max_val: int):
    """Traditional O(N) brute force — baseline for BSGS comparison"""
    curr = 1
    for i in range(max_val + 1):
        if curr == target:
            return i
        curr = (curr * g) % p
    return None

# ── Benchmark 1: Homomorphic Tally vs Individual Decrypt ─────────────────────
def benchmark_tally(n_voters: int):
    votes = [random.randint(0, 1) for _ in range(n_voters)]
    ciphertexts = [elgamal_encrypt(v, pub) for v in votes]

    # Traditional: decrypt each ballot individually
    start = time.perf_counter()
    for ct in ciphertexts:
        elgamal_decrypt(ct, priv)
    individual_time = (time.perf_counter() - start) * 1000  # ms

    # Your approach: aggregate then decrypt once
    start = time.perf_counter()
    agg = homomorphic_tally(ciphertexts, pub.p)
    elgamal_decrypt(agg, priv)
    homomorphic_time = (time.perf_counter() - start) * 1000  # ms

    return individual_time, homomorphic_time

# ── Benchmark 2: BSGS vs Brute Force ─────────────────────────────────────────
def benchmark_dlog(n_voters: int):
    actual_sum = random.randint(1, n_voters)
    g_sum = mod_pow(pub.g, actual_sum, pub.p)

    # Traditional: brute force O(N)
    start = time.perf_counter()
    brute_force_dlog(pub.g, g_sum, pub.p, n_voters)
    brute_time = (time.perf_counter() - start) * 1000  # ms

    # Your approach: BSGS O(√N)
    start = time.perf_counter()
    recover_tally(g_sum, pub.g, pub.p, n_voters)
    bsgs_time = (time.perf_counter() - start) * 1000  # ms

    return brute_time, bsgs_time

# ── Run ───────────────────────────────────────────────────────────────────────
voter_counts = [100, 500, 1000, 2000, 5000]

print("BENCHMARK 1: Homomorphic Tally vs Individual Decrypt")
print(f"{'N Voters':<12} {'Individual (ms)':<22} {'Homomorphic (ms)':<22} {'Improvement'}")
print("-" * 70)

tally_results = []
for n in voter_counts:
    ind_times, hom_times = [], []
    for _ in range(RUNS):
        ind, hom = benchmark_tally(n)
        ind_times.append(ind)
        hom_times.append(hom)
    avg_ind = sum(ind_times) / RUNS
    avg_hom = sum(hom_times) / RUNS
    improvement = ((avg_ind - avg_hom) / avg_ind) * 100
    tally_results.append((n, avg_ind, avg_hom, improvement))
    print(f"{n:<12} {avg_ind:<22.3f} {avg_hom:<22.3f} {improvement:.1f}% faster")

print()
print("BENCHMARK 2: BSGS vs Brute Force (Discrete Log Recovery)")
print(f"{'N Voters':<12} {'Brute Force (ms)':<24} {'BSGS (ms)':<20} {'Improvement'}")
print("-" * 70)

dlog_results = []
for n in voter_counts:
    bf_times, bsgs_times = [], []
    for _ in range(RUNS):
        bf, bsgs = benchmark_dlog(n)
        bf_times.append(bf)
        bsgs_times.append(bsgs)
    avg_bf = sum(bf_times) / RUNS
    avg_bsgs = sum(bsgs_times) / RUNS
    improvement = ((avg_bf - avg_bsgs) / avg_bf) * 100 if avg_bf > 0 else 0
    dlog_results.append((n, avg_bf, avg_bsgs, improvement))
    print(f"{n:<12} {avg_bf:<24.3f} {avg_bsgs:<20.3f} {improvement:.1f}% faster")

print()
print("SUMMARY")
avg_tally = sum(r[3] for r in tally_results) / len(tally_results)
avg_dlog  = sum(r[3] for r in dlog_results)  / len(dlog_results)
print(f"Homomorphic tally : {avg_tally:.1f}% faster than individual decrypt")
print(f"BSGS              : {avg_dlog:.1f}% faster than brute force")