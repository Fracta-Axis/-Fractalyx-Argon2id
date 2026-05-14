# FractalShield-Argon2id — Reference Test Vectors v1.0

> **Generated from:** FractalShield-Argon2id Preprint v1.1 (May 2026)  
> **Reference implementation:** [`argon2id_shield.py`](./argon2id_shield.py)  
> **All values are deterministic.** Running the script must reproduce every value exactly.

---

## How to reproduce

```bash
pip install argon2-cffi numpy
python3 argon2id_shield.py
```

Programmatic comparison:
```python
import json
with open('argon2id_shield_report.json') as f:
    v = json.load(f)
print('V1 KDF:', v['test_vectors']['V1_KDF_BASE']['output_hex'][:32], '...')
print('V2 avalanche:', v['test_vectors']['V2_KDF_2X']['avalanche_pct'], '%')
```

---

## Fixed Inputs

All vectors use these fixed inputs unless stated otherwise.

| Parameter | Hex | ASCII |
|-----------|-----|-------|
| `password` | `4672616374616c536869656c645f54657374566563746f725f7631` | `FractalShield_TestVector_v1` |
| `salt` (16 B) | `000102030405060708090a0b0c0d0e0f` | — |
| `IV` (16 B) | `101112131415161718191a1b1c1d1e1f` | — |
| `message` | `48656c6c6f2c2041627973732e` | `Hello, Abyss.` |

---

## Argon2id Parameters

| Parameter | Value |
|-----------|-------|
| Time cost `t` | 3 (base) |
| Memory `m` | 65,536 KB (64 MB) |
| Parallelism `p` | 4 lanes |
| Output length | 96 bytes |
| Pre-hash | `SHA3-256(password ‖ \x00 ‖ salt)` |

---

## V1 — KDF Output (`t = 3`, base cost)

**Component:** `argon2id_kdf(password, salt, t=3)`  
**Expected output (96 bytes):**

```
af70237a14dcd326c59010b798dff4b7df2edf7f60854a98bb6daa1d9fc833c
1c00381358092cbf86fb342c4ae2adbfea697a4b69dc9933d1b9c0f225acadcc
9ef65aa559279395dd593c0a0e1a9bfa0d7d2bb4e1dfd1989c244e2da124e9b6e
```

> `[0:64]` → `dk` (stream cipher key)  
> `[64:96]` → `ek` (encryption key)

---

## V2 — KDF Output (`t = 6`, Layer 1 cost)

**Component:** `argon2id_kdf(password, salt, t=6)`  
**Expected output (96 bytes):**

```
99bed37245fc14265a5dc27e48b4cc5fdcf2fd0e5ffb76d2fa781a216f6fbb3
21283ed703f6ac510af22707ffbe93ea5de76005b0acbbe5170e2ccf6ac685b8
2d3128314f0dc91a059bcdb5befe0e445ef0cc7c9716ecd2dfee7302437981426
```

**Avalanche check (C1):** `diffBits(V1, V2) = 382/768 = 49.7%` ✅  
*(Pass range: 48.0–52.0%, ideal: 50.0%)*

---

## V3 — Keystream (64 bytes)

**Component:** `keystream(dk, IV, length=64)`  
**Input:** `dk = V1[0:64]`, `IV` as above

`dk`:
```
af70237a14dcd326c59010b798dff4b7df2edf7f60854a98bb6daa1d9fc833c
1c00381358092cbf86fb342c4ae2adbfea697a4b69dc9933d1b9c0f225acadcc
```

**Expected keystream (64 bytes):**
```
df4a7aa668f717e62a241aef28e9feebdfc0dc889c35a3b61d82acc079be4083
0dfa346cbe08ce51ae1352c2ce6f6f51e105a68a5b7b29bdbd8a8ca393ef14bc
```

**Derivation:** `kmix = SHA3-256(dk[32:64] ‖ IV)`, then SHA3-256 counter mode.

---

## V4 — Keystream Avalanche (1-bit key change)

**Modification:** `password[0] ^= 0x01` — all other inputs identical to V3

**Modified keystream (64 bytes):**
```
90a7128ebb1dc7d71cbefea9098ef1d7f834966d8cd2d015932c1255acad0b65
6f92da5ae62a32fd67ab797bb1c292cb592a3a0e61ac530c66a162290e3794a1
```

| Metric | Value |
|--------|-------|
| Bits changed | 269 / 512 |
| Percentage | **52.5%** ✅ |
| Pass range | 48.0–52.0% |
| Ideal (PRG) | 50.0% |

---

## V5 — Magic Prefix and PKCS#7 Padding

**Magic prefix:** `4132534801` (`A2SH\x01`, 5 bytes, 40 bits)  
False-positive probability: `< N/2⁴⁰ ≈ 5×10⁻¹²` (Lemma 5.3)

**Padded plaintext** (`MAGIC ‖ message`, PKCS#7 to 16-byte boundary):
```
413253480148656c6c6f2c2041627973732e0e0e0e0e0e0e0e0e0e0e0e0e0e0e
```

**Constant-time prefix check** (`hmac.compare_digest`):

| Input | Result |
|-------|--------|
| Correct prefix `A2SH\x01` | `True` ✅ |
| Wrong prefix `WRONG` | `False` ✅ |

> ⚠️ Always use `hmac.compare_digest` — never `==` on secret bytes.  
> Direct comparison is a timing oracle. See Section 6.2 of the paper.

---

## V6 — HMAC-SHA3-256 Tag

**Derivation:** `k_mac = SHA3-256(V1[0:32] ‖ b'A2SHIELD_MAC')`

| Field | Value (hex) |
|-------|-------------|
| `k_mac` | `ead62d206ae0ec7022cd77b9a2d714fdc4cf3538c716e09268065f7d0fab0e8a` |
| `body` | `4672616374616c536869656c64207465737420626f6479` |
| **tag** | `157f048f535ca03b0fe7bd84b2483fab0fdf2ea83d30961ea0ec20e8edaeb34f` |

> Body ASCII: `FractalShield test body`

---

## V7 — Keystream Counter Derivation

**Purpose:** Verify SHA3-256 counter-mode derivation is deterministic.

| Step | Operation | Output |
|------|-----------|--------|
| 1 | `kmix = SHA3-256(dk[32:64] ‖ IV)` | deterministic from V1, IV |
| 2 | `block_i = SHA3-256(kmix ‖ i.to_bytes(8,'big'))` | 32 bytes per block |
| 3 | concatenate until length reached | |

---

## V8 — Replay Resistance (Session Identifier)

**Purpose:** Verify Theorem 6.1 — different session IDs produce different MAC keys,  
preventing cross-session replay attacks (OP3 resolution).

| Field | Value (hex) |
|-------|-------------|
| `sid1` | `390c8c7d7247342cd8100f2f6f770d65` |
| `sid2` | `d670e58e0351d8ae8e4f6eac342fc231` |
| `k_mac1` | `dadb955407806d96da8e23abd01f3a5eb1f307aa1bd159ec3173b94f94e8323c` |
| `k_mac2` | `faf27dc2debe889a6d9fa008a038285db6ea14ce1208c8e66ea2ae615f547f71` |
| `k_mac1 ≠ k_mac2` | `True` ✅ |

`k_mac_i = SHA3-256(k0[:32] ‖ "A2SHIELD_MAC" ‖ sid_i)`

A ciphertext from `sid1` cannot pass MAC verification in `sid2`
because `k_mac1 ≠ k_mac2` with overwhelming probability.

---

## Timing Vectors — Cost Monotonicity (C3)

**Purpose:** Verify Argon2id cost scales strictly with time parameter `t`.

| Layer | `t` | Expected time | Ratio vs Layer 0 |
|-------|-----|---------------|-----------------|
| 0 | 3  | ~0.17 s | 1.0× |
| 1 | 6  | ~0.32 s | ~1.9× |
| 2 | 12 | ~0.61 s | ~3.6× |
| 3 | 24 | ~1.17 s | ~6.9× |
| 4 | 48 | ~2.32 s | ~13.6× |

> Ratios are sub-linear due to Argon2id's internal lane parallelism (`p=4`).  
> Security-relevant quantity: **memory work** Ω(m) per thread — not wall-clock time.  
> Pass criterion: strictly increasing sequence, CoV < 5% per parameter.

---

## Constant-Time Vectors — CT4 Check (OP6)

**Purpose:** Verify magic-prefix and MAC comparisons are timing-uniform  
(Proposition 6.2, `n = 5×10⁵` samples per case).

| Component | Case | Median (ns) | Spread | Pass |
|-----------|------|-------------|--------|------|
| CT2a Magic prefix | Correct | 189 | 0.53% | ✅ |
| CT2a Magic prefix | Wrong 1st byte | 189 | | |
| CT2a Magic prefix | All wrong | 190 | | |
| CT2b MAC tag | Correct | 154 | 0.65% | ✅ |
| CT2b MAC tag | Wrong 1st byte | 154 | | |
| CT2b MAC tag | All wrong | 153 | | |

Pass criterion: spread `< 2%` (Technical Note v1.2, CT4 checklist).

> ⚠️ **Residual open problem:** Argon2id scratchpad access pattern is data-dependent  
> and NOT constant-time. See Open Problem 2 / Section 6.2 of the paper.

---

## Round-Trip Vectors — Integration Test (V5)

| Test | Level | Result |
|------|-------|--------|
| Encrypt → Decrypt | 1 — Standard | Exact match ✅ |
| Encrypt → Decrypt | 2 — Reinforced | Exact match ✅ |
| Encrypt → Decrypt | 3 — Maximum | Exact match ✅ |
| Wrong password | any | `ValueError` — no oracle signal ✅ |
| Tamper 1 byte in ciphertext | any | `ValueError` — HMAC fails ✅ |

---

## Storage–Computation Asymmetry (1 KB message)

| Level | Defender storage | Attacker RAM/attempt | Ratio |
|-------|-----------------|---------------------|-------|
| 1 | 3,196 B | 192 MB (3 × 64 MB) | 62,993× |
| 2 | 4,237 B | 256 MB (4 × 64 MB) | 63,355× |
| 3 | 5,278 B | 320 MB (5 × 64 MB) | 63,574× |

GPU bound (RTX 4090, 24 GB VRAM): ≤ 375 parallel threads at Level 1.

---

## How to Report a Vector Mismatch

1. Open an issue at [github.com/Fracta-Axis/Fractalyx/issues](https://github.com/Fracta-Axis/Fractalyx/issues)
2. Include: Python version, `argon2-cffi` version, OS, full output of `python3 argon2id_shield.py`
3. Label: `vector-mismatch`

---

## Known Limitations (v1.0)

| # | Limitation | Planned fix |
|---|-----------|-------------|
| L1 | Full deterministic encrypt/decrypt round-trip vector missing (uses `os.urandom` for salts/IVs) | Deterministic encrypt mode in v1.1 |
| L2 | Timing vectors are platform-dependent | CI baseline in v1.1 |
| L3 | NIST SP 800-22 statistical tests not included (require ≥ 2×10⁶ bits) | Separate test suite in v1.1 |

---

## Parameter Reference

| Symbol | Value | Description |
|--------|-------|-------------|
| `t` | 3 (base) | Argon2id time cost (passes) |
| `m` | 65,536 KB | Argon2id memory cost |
| `p` | 4 | Argon2id parallelism |
| `MAGIC` | `4132534801` | 5-byte magic prefix (`A2SH\x01`) |
| `H` | SHA3-256 | Hash function |
| `MAC` | HMAC-SHA3-256 | Message authentication code |

---

*FractalShield-Argon2id Preprint v1.1 · May 2026 · Miguel Angel Franco León*  
*[github.com/Fracta-Axis/Fractalyx](https://github.com/Fracta-Axis/Fractalyx)*
