import time
import statistics
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA44PrivateKey

MESSAGE = b"my authenticated message"
ITERATIONS = 5000  # adjust based on desired precision

# Warm-up run to eliminate JIT/import/caching overhead
_pk = MLDSA44PrivateKey.generate()
_sig = _pk.sign(MESSAGE)
_pub = _pk.public_key()
_pub.verify(_sig, MESSAGE)

# -------------------------------------------------------------
# 1. Key Generation
# -------------------------------------------------------------
keygen_times = []
for _ in range(ITERATIONS):
    t0 = time.perf_counter_ns()
    priv = MLDSA44PrivateKey.generate()
    t1 = time.perf_counter_ns()
    keygen_times.append(t1 - t0)

# -------------------------------------------------------------
# 2. Public Key Derivation
# -------------------------------------------------------------
pubkey_times = []
for _ in range(ITERATIONS):
    t0 = time.perf_counter_ns()
    pub = priv.public_key()
    t1 = time.perf_counter_ns()
    pubkey_times.append(t1 - t0)

# -------------------------------------------------------------
# 3. Signing
# -------------------------------------------------------------
sign_times = []
for _ in range(ITERATIONS):
    t0 = time.perf_counter_ns()
    sig = priv.sign(MESSAGE)
    t1 = time.perf_counter_ns()
    sign_times.append(t1 - t0)

# -------------------------------------------------------------
# 4. Verification
# -------------------------------------------------------------
verify_times = []
for _ in range(ITERATIONS):
    t0 = time.perf_counter_ns()
    pub.verify(sig, MESSAGE)
    t1 = time.perf_counter_ns()
    verify_times.append(t1 - t0)


def report(name, ns_list):
    # Convert nanoseconds to microseconds
    us_list = [t / 1_000 for t in ns_list]
    median = statistics.median(us_list)
    mean = statistics.mean(us_list)
    min_t = min(us_list)
    ops_per_sec = 1_000_000 / mean if mean > 0 else 0
    print(f"{name:<24} | Min: {min_t:7.1f} µs | Median: {median:7.1f} µs | Ops/sec: {ops_per_sec:9.1f}")


print(f"Benchmarking ML-DSA-44 over {ITERATIONS} iterations:")
print("-" * 70)
report("Key Generation", keygen_times)
report("Public Key Derivation", pubkey_times)
report("Signing", sign_times)
report("Verification", verify_times)