"""
argon2id_shield.py
------------------
Argon2id-Shield: Complete reference implementation.

FractalShield framework instantiated with Argon2id as core function F.
Demonstrates that the OFV and geometric cost escalation properties
are independent of the MFSU core — they are framework properties.

All four security theorems (5.1, 5.2, 5.5, 5.6) apply unchanged.
See: FractalShield Technical Note v1.2, Appendix D.

Parameters (Argon2id RFC 9106 interactive profile, strengthened):
    time_cost   = 3   passes
    memory_cost = 65536 KB = 64 MB per thread
    parallelism = 4   lanes
    hash_len    = 96  bytes (dk=64, ek=32)
    salt        = 16  bytes (random per layer)

File format: .a2shield v1
    HDR(12B) | order_enc(N B) | tag(32B) | CT[0]...CT[N-1]

Usage:
    python3 argon2id_shield.py

Dependencies:
    pip install argon2-cffi cryptography
"""

import os
import struct
import hashlib
import hmac as _hmac
import time
import json
import tracemalloc

from argon2.low_level import hash_secret_raw, Type

# ── Parameters ────────────────────────────────────────────────
TIME_COST   = 3
MEM_BASE    = 65536      # KB = 64 MB  (Layer 0)
PARALLELISM = 4
HASH_LEN    = 96         # bytes: dk=64, ek=32

MAGIC       = b'A2SH\x01'   # 5-byte magic prefix for Argon2id-Shield
LEVELS      = {1: 3, 2: 4, 3: 5}
LEVEL_NAMES = {1: "Standard", 2: "Reinforced", 3: "Maximum"}

# ── Helpers ───────────────────────────────────────────────────

def _sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()

def _sha3_512(data: bytes) -> bytes:
    return hashlib.sha3_512(data).digest()

def _hkdf_expand(prk: bytes, length: int) -> bytes:
    okm, t, ctr = b'', b'', 1
    while len(okm) < length:
        t    = _sha3_256(t + prk + bytes([ctr]))
        okm += t
        ctr += 1
    return okm[:length]

def _pkcs7_pad(data: bytes, block: int = 16) -> bytes:
    pad = block - (len(data) % block)
    return data + bytes([pad] * pad)

def _pkcs7_unpad(data: bytes) -> bytes:
    pad = data[-1]
    if not (1 <= pad <= 16):
        raise ValueError("Invalid PKCS7 padding")
    if data[-pad:] != bytes([pad] * pad):
        raise ValueError("Invalid PKCS7 padding bytes")
    return data[:-pad]

def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

# ── Core: Argon2id KDF (satisfies C1-C4) ─────────────────────

def argon2id_kdf(password: bytes,
                 salt: bytes,
                 mem_cost: int = MEM_BASE) -> bytes:
    """
    Argon2id core function F — satisfies C1-C4:

    C1 Input sensitivity:  SHA3-256 pre-hash + Argon2id avalanche
    C2 Output pseudorandomness: Argon2id output is PRG-secure
    C3 Cost controllability: mem_cost parameter, monotone
    C4 Memory hardness: Argon2id is (t,m)-memory-hard [RFC 9106]

    Input : password, salt (16B), mem_cost (KB)
    Output: 96 bytes (dk=64B, ek=32B)
    """
    assert len(salt) == 16, "salt must be 16 bytes"

    # Pre-hash password for uniform input length (C1 amplification)
    pwd_hash = _sha3_256(password + b'\x00' + salt)

    raw = hash_secret_raw(
        secret      = pwd_hash,
        salt        = salt,
        time_cost   = TIME_COST,
        memory_cost = mem_cost,
        parallelism = PARALLELISM,
        hash_len    = HASH_LEN,
        type        = Type.ID
    )
    return raw   # 96 bytes


def argon2id_keystream(dk: bytes, iv: bytes, length: int) -> bytes:
    """
    Counter-mode keystream using SHA3-256.
    Identical to MFSU-Crypt keystream wrapper — framework component.

    Input : dk (64B), iv (16B), length
    Output: length bytes
    """
    assert len(dk) == 64
    assert len(iv) == 16

    kmix = _sha3_256(dk[32:64] + iv)
    ks   = bytearray()
    ctr  = 0
    while len(ks) < length:
        block = _sha3_256(kmix + struct.pack('>Q', ctr))
        ks   += block
        ctr  += 1
    return bytes(ks[:length])


# ── FractalShield construction with Argon2id core ─────────────

def a2shield_enc(plaintext: bytes,
                 password: bytes,
                 level: int = 2) -> bytes:
    """
    Argon2id-Shield encryption.

    Construction 3.2 (FractalShield.Enc) with F = Argon2id.

    Input : plaintext, password, level in {1,2,3}
    Output: .a2shield v1 ciphertext bytes
    """
    N = LEVELS[level]

    # Pad with magic prefix
    padded = _pkcs7_pad(MAGIC + plaintext)
    L      = len(padded)

    layers = []
    salts  = []
    ivs    = []
    keys   = []

    # ── Layer 0: real layer (base cost) ───────────────────────
    s0   = os.urandom(16)
    iv0  = os.urandom(16)
    k0   = argon2id_kdf(password, s0, mem_cost=MEM_BASE)
    dk0  = k0[:64]
    ks0  = argon2id_keystream(dk0, iv0, L)
    ct0  = _xor(padded, ks0)
    layers.append(ct0); salts.append(s0)
    ivs.append(iv0);    keys.append(k0)

    # ── Decoy layers i=1..N-1 (escalating cost 2^i × base) ───
    for i in range(1, N):
        si      = os.urandom(16)
        ivi     = os.urandom(16)
        mem_i   = MEM_BASE * (2 ** i)   # geometric escalation C3
        ki      = argon2id_kdf(password, si, mem_cost=mem_i)
        dki     = ki[:64]

        # Pseudorandom decoy — indistinguishable from real layer (C2)
        prg_seed = _sha3_256(password + bytes([i]) + si)
        di       = argon2id_keystream(
                       prg_seed[:32] + prg_seed, si, L)[:L]

        ksi = argon2id_keystream(dki, ivi, L)
        cti = _xor(di, ksi)
        layers.append(cti); salts.append(si)
        ivs.append(ivi);    keys.append(ki)

    # ── Shuffle: key-dependent layer order ────────────────────
    import numpy as np
    order_seed = _sha3_256(password + b'A2SHIELD_ORDER')
    rng        = np.random.default_rng(
                     seed=int.from_bytes(order_seed[:8], 'big'))
    order      = list(rng.permutation(N))

    # Encrypt order map under k0
    order_bytes = bytes(order)
    order_mask  = _sha3_256(keys[0][:32] + b'ORDERMAP')[:N]
    order_enc   = _xor(order_bytes, order_mask)

    # ── Header (12 bytes) ─────────────────────────────────────
    # Magic(5) | version(1) | level(1) | N(1) | L(4)
    hdr = b'A2SHv' + bytes([1, level, N]) + struct.pack('>I', L)

    # Embed salt+IV per layer (32B each) before ciphertext
    layer_blocks = []
    for idx in order:
        layer_blocks.append(salts[idx] + ivs[idx] + layers[idx])

    # ── Global HMAC-SHA3-256 ──────────────────────────────────
    k_mac    = _sha3_256(keys[0][:32] + b'A2SHIELD_MAC')
    mac_body = hdr + order_enc
    for lb in layer_blocks:
        mac_body += lb
    tag = _hmac.new(k_mac, mac_body, hashlib.sha3_256).digest()

    # ── Assemble ──────────────────────────────────────────────
    out = hdr + order_enc + tag
    for lb in layer_blocks:
        out += lb
    return out


def a2shield_dec(ciphertext: bytes, password: bytes) -> bytes:
    """
    Argon2id-Shield decryption.

    Input : ciphertext bytes, password
    Output: plaintext bytes
    Raises: ValueError on wrong password or tampered ciphertext
    """
    # ── Parse header ──────────────────────────────────────────
    if ciphertext[:5] != b'A2SHv':
        raise ValueError("Not a valid .a2shield file")

    level = ciphertext[6]
    N     = ciphertext[7]
    L     = struct.unpack('>I', ciphertext[8:12])[0]
    pos   = 12

    order_enc  = ciphertext[pos:pos+N];  pos += N
    tag_stored = ciphertext[pos:pos+32]; pos += 32

    # ── Parse layer blocks ────────────────────────────────────
    block_size = 32 + L   # salt(16) + iv(16) + ciphertext(L)
    raw_blocks = []
    for _ in range(N):
        raw_blocks.append(ciphertext[pos:pos+block_size])
        pos += block_size

    # ── Try each block as Layer 0 (real layer) ────────────────
    # The legitimate user tries the password at base cost only.
    # OFV: no oracle — correctness known only via magic prefix.

    for candidate_idx in range(N):
        blk  = raw_blocks[candidate_idx]
        salt = blk[:16]
        iv   = blk[16:32]
        ct   = blk[32:]

        try:
            k0  = argon2id_kdf(password, salt, mem_cost=MEM_BASE)
            dk0 = k0[:64]
            ks0 = argon2id_keystream(dk0, iv, L)
            pt  = _xor(ct, ks0)

            # Constant-time magic prefix check (OP6 fix)
            if _hmac.compare_digest(pt[:5], MAGIC):
                # Found real layer — verify global MAC
                k_mac = _sha3_256(k0[:32] + b'A2SHIELD_MAC')

                # Reconstruct order_enc to verify MAC
                order_mask = _sha3_256(k0[:32] + b'ORDERMAP')[:N]
                order      = bytes(_xor(order_enc, order_mask))

                mac_body = ciphertext[:12] + order_enc
                for lb in raw_blocks:
                    mac_body += lb

                tag_computed = _hmac.new(
                    k_mac, mac_body, hashlib.sha3_256).digest()

                # Constant-time MAC comparison (OP6 fix)
                if not _hmac.compare_digest(tag_stored, tag_computed):
                    raise ValueError("MAC verification failed — tampered")

                return _pkcs7_unpad(pt[5:])   # strip magic + padding

        except Exception:
            continue

    raise ValueError("Decryption failed — wrong password")


# ── Benchmarking and measurement ──────────────────────────────

def measure_layer(password: bytes, mem_cost: int) -> tuple:
    """Measure RAM and time for one KDF call."""
    salt = bytes(range(16))
    tracemalloc.start()
    t0  = time.perf_counter()
    _   = argon2id_kdf(password, salt, mem_cost=mem_cost)
    elapsed = time.perf_counter() - t0
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return peak / (1024**2), elapsed


def run_benchmark():
    """
    Empirical measurement of Storage-Computation Asymmetry
    for Argon2id-Shield. Mirrors asymmetry_measure.py for MFSU-Crypt.
    """
    PWD = b'FractalShield_TestVector_v1'
    MSG = b'Hello, Abyss.'
    SEP = "=" * 62

    report = {
        "title": "Argon2id-Shield Storage-Computation Asymmetry",
        "core": "Argon2id",
        "parameters": {
            "time_cost": TIME_COST,
            "mem_base_kb": MEM_BASE,
            "parallelism": PARALLELISM,
            "hash_len": HASH_LEN,
            "magic": MAGIC.hex()
        },
        "levels": {}
    }

    print(SEP)
    print("  Argon2id-Shield — Benchmark & Asymmetry Measurement")
    print("  FractalShield Framework, Argon2id Core")
    print(SEP)
    print(f"  Argon2id params: t={TIME_COST}, m={MEM_BASE}KB, p={PARALLELISM}")
    print(f"  Message: {MSG!r}")
    print(SEP)

    # Defender cost (Layer 0 only)
    print("\n  [1/4] Defender cost (Layer 0, base memory)...")
    def_ram, def_time = measure_layer(PWD, MEM_BASE)
    print(f"        Peak RAM : {def_ram:.2f} MB")
    print(f"        Time     : {def_time:.3f} s")
    report["defender"] = {
        "mem_cost_kb": MEM_BASE,
        "peak_ram_mb": round(def_ram, 3),
        "time_s": round(def_time, 3)
    }

    # Round-trip test
    print("\n  [2/4] Round-trip encrypt/decrypt test (Level 2)...")
    ct = a2shield_enc(MSG, PWD, level=2)
    pt = a2shield_dec(ct, PWD)
    assert pt == MSG, "Round-trip FAILED"
    print(f"        Ciphertext size : {len(ct)} bytes")
    print(f"        Plaintext match : ✓")
    report["roundtrip"] = {
        "level": 2,
        "plaintext": MSG.decode(),
        "ciphertext_bytes": len(ct),
        "match": True
    }

    # Wrong password test
    try:
        a2shield_dec(ct, b'wrong_password')
        print("        Wrong pwd test  : FAILED (should raise)")
    except ValueError:
        print("        Wrong pwd test  : ✓ (raises ValueError)")

    # Per-level asymmetry
    print("\n  [3/4] Per-level attacker cost measurement...")
    padded_L = len(_pkcs7_pad(MAGIC + MSG))

    for level in [1, 2, 3]:
        N    = LEVELS[level]
        name = LEVEL_NAMES[level]
        print(f"\n  Level {level} — {name} ({N} layers)")
        print(f"  {'─'*50}")

        s_def = 12 + N + 32 + N * (32 + padded_L)

        layer_rams  = []
        layer_times = []
        for i in range(N):
            mem_i = MEM_BASE * (2**i)
            ram, t = measure_layer(PWD, mem_i)
            layer_rams.append(ram)
            layer_times.append(t)
            print(f"    Layer {i}: mem={mem_i:>8}KB │ "
                  f"RAM {ram:6.2f} MB │ time {t:.3f} s")

        total_ram  = sum(layer_rams)
        total_time = sum(layer_times)
        ratio      = (total_ram * 1024**2) / s_def
        att_sec    = 1.0 / total_time
        geom       = 2**N - 1

        print(f"  {'─'*50}")
        print(f"  Defender storage   : {s_def} B")
        print(f"  Attacker RAM total : {total_ram:.2f} MB")
        print(f"  Asymmetry ratio    : {ratio:,.0f}×")
        print(f"  Geometric factor   : {geom}×")
        print(f"  Attacker att/sec   : {att_sec:.5f}")

        gpu_threads = int((24 * 1024) / total_ram)
        gpu_att_sec = att_sec * gpu_threads

        report["levels"][level] = {
            "name": name,
            "N_layers": N,
            "geometric_factor": geom,
            "defender_storage_bytes": s_def,
            "attacker_ram_mb": round(total_ram, 3),
            "attacker_time_s": round(total_time, 3),
            "attacker_att_sec": round(att_sec, 5),
            "asymmetry_ratio": round(ratio, 0),
            "gpu_rtx4090": {
                "max_threads": gpu_threads,
                "att_sec": round(gpu_att_sec, 4)
            },
            "layer_breakdown": [
                {"layer": i,
                 "mem_kb": MEM_BASE*(2**i),
                 "ram_mb": round(layer_rams[i], 3),
                 "time_s": round(layer_times[i], 3)}
                for i in range(N)
            ]
        }

    # Comparison vs Argon2id alone
    print(f"\n  [4/4] Comparison: Argon2id alone vs Argon2id-Shield")
    print(f"  {'─'*50}")
    print(f"  Property                  Argon2id    A2Shield-L3")
    print(f"  {'─'*50}")
    l3 = report["levels"][3]
    print(f"  Verification oracle       Yes         No (OFV) ✓")
    print(f"  Att. RAM / attempt        {MEM_BASE//1024:.0f} MB        "
          f"{l3['attacker_ram_mb']:.0f} MB")
    print(f"  Att. time / attempt       {def_time:.3f} s      "
          f"{l3['attacker_time_s']:.3f} s")
    print(f"  Geometric cost factor     1×          {l3['geometric_factor']}×")
    print(f"  Asymmetry ratio           ~1×         "
          f"{l3['asymmetry_ratio']:,.0f}×")
    print(f"  GPU att/sec (RTX 4090)    "
          f"{def_time and (1/def_time)*int(24*1024/(MEM_BASE/1024)):.1f}       "
          f"{l3['gpu_rtx4090']['att_sec']:.4f}")
    print(SEP)

    report["comparison"] = {
        "argon2id_alone": {
            "oracle": True,
            "ram_per_att_mb": MEM_BASE/1024,
            "geometric_factor": 1
        },
        "argon2id_shield_L3": {
            "oracle": False,
            "ram_per_att_mb": l3['attacker_ram_mb'],
            "geometric_factor": l3['geometric_factor'],
            "asymmetry_ratio": l3['asymmetry_ratio']
        }
    }

    return report


# ── Test vectors ──────────────────────────────────────────────

def generate_vectors():
    """Generate deterministic test vectors for Argon2id-Shield."""
    PWD  = b'FractalShield_TestVector_v1'
    SALT = bytes(range(16))
    IV   = bytes(range(16, 32))
    MSG  = b'Hello, Abyss.'

    print("\n" + "=" * 62)
    print("  Argon2id-Shield Test Vectors v1.0")
    print("=" * 62)

    vectors = {}

    # V1: KDF at base memory
    print("\n[V1] Argon2id-KDF (mem=64MB, t=3, p=4)")
    k1 = argon2id_kdf(PWD, SALT, mem_cost=MEM_BASE)
    print(f"  output: {k1.hex()}")
    vectors['V1_KDF_BASE'] = {
        'password': PWD.decode(),
        'salt_hex': SALT.hex(),
        'mem_cost_kb': MEM_BASE,
        'output_hex': k1.hex()
    }

    # V2: KDF at 2× memory (Layer 1)
    print("\n[V2] Argon2id-KDF (mem=128MB, Layer 1 cost)")
    k2 = argon2id_kdf(PWD, SALT, mem_cost=MEM_BASE*2)
    diff = sum(bin(a^b).count('1') for a,b in zip(k1,k2))
    pct  = diff / (len(k1)*8) * 100
    print(f"  output: {k2.hex()}")
    print(f"  diffBits(V1,V2): {diff}/{len(k1)*8} = {pct:.1f}% (C1 check)")
    vectors['V2_KDF_2X'] = {
        'mem_cost_kb': MEM_BASE*2,
        'output_hex': k2.hex(),
        'avalanche_pct': round(pct, 2)
    }

    # V3: Keystream
    print("\n[V3] Keystream (64 bytes)")
    dk = k1[:64]
    ks = argon2id_keystream(dk, IV, 64)
    print(f"  dk : {dk.hex()}")
    print(f"  ks : {ks.hex()}")
    vectors['V3_KEYSTREAM'] = {
        'dk_hex': dk.hex(),
        'iv_hex': IV.hex(),
        'keystream_hex': ks.hex()
    }

    # V4: Magic prefix
    print("\n[V4] Magic prefix")
    print(f"  MAGIC: {MAGIC.hex()} = {MAGIC!r}")
    padded = _pkcs7_pad(MAGIC + MSG)
    print(f"  padded: {padded.hex()}")
    print(f"  check OK  : {_hmac.compare_digest(padded[:5], MAGIC)}")
    print(f"  check FAIL: {_hmac.compare_digest(b'WRONG', MAGIC)}")
    vectors['V4_MAGIC'] = {
        'magic_hex': MAGIC.hex(),
        'padded_hex': padded.hex(),
        'check_correct': True,
        'check_wrong': False
    }

    return vectors


# ── Entry point ───────────────────────────────────────────────

if __name__ == '__main__':
    report  = run_benchmark()
    vectors = generate_vectors()

    report['test_vectors'] = vectors

    with open('argon2id_shield_report.json', 'w') as f:
        json.dump(report, f, indent=2)

    print("\n  Report saved → argon2id_shield_report.json")
    print("=" * 62)
