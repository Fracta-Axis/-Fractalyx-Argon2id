# FractalShield — Oracle-Free Layered Encryption

> **Preprint v1.1 · May 2026 · Not peer-reviewed**  
> Miguel Angel Franco León · Independent Researcher · Fracta-Axis Project

---

## What is this?

Standard password-based encryption has a structural weakness: after Argon2id finishes, a single MAC check gives the attacker a perfect binary signal — correct or incorrect — in microseconds. Memory-hard KDFs slow each attempt but **do not eliminate this oracle**.

FractalShield eliminates the oracle entirely by hiding the real ciphertext among statistically indistinguishable decoy layers, each derived at escalating KDF cost. The attacker must decrypt **all N layers** to get any signal — paying the geometric sum $(2^N - 1) \times C_\text{base}$ per password guess while the legitimate user always pays $1 \times C_\text{base}$.

This repository contains:

- **FractalShield-Argon2id** — the primary instantiation (built on Argon2id, RFC 9106)
- **Reference implementation** in Python with test vectors
- **Formal security proofs** (4 theorems, standard + ROM model)
- **Technical Note** — the four core laws C1–C4 that any core must satisfy

---

## Key Properties

| Property | Status | Basis |
|----------|--------|-------|
| No verification oracle (OFV) | **Proved** | Thm. 5.5 — standard model |
| Geometric cost escalation | **Proved** | Lemma 5.4 — construction |
| Layer statistical indistinguishability | **Proved** | Thm. 5.8 — ROM |
| Replay resistance | **Proved** | Thm. 6.1 — standard model |
| IND-CCA2 | **Proved (ROM)** | Four-game hybrid |
| Memory hardness | **Proved** | Alwen–Serbinenko 2015, parallel ROM |
| Constant-time (partial) | **Verified** | 5×10⁵ samples, spread < 1% |

### What is NOT claimed

- No standard-model IND-CCA2 (Open Problem 1)
- No independent cryptanalysis audit yet (Open Problem 5)  
- Constant-time scratchpad access not yet resolved (Open Problem 2)
- Quantum security analysis is partial (Open Problem 4)

---

## The Core Idea

```
Legitimate user              Attacker (Level 3, N=5 layers)
─────────────────            ──────────────────────────────
Layer 0 only                 Layer 0:  1× C_base
Cost: 1× C_base              Layer 1:  2× C_base
Time: ~0.17s                 Layer 2:  4× C_base
                             Layer 3:  8× C_base
                             Layer 4: 16× C_base
                             ─────────────────────
                             Total:   31× C_base (~5.3s)
```

**Protection levels:**

| Level | Layers N | Attacker cost (theory) | Attacker cost (measured) |
|-------|----------|----------------------|--------------------------|
| 1 — Standard | 3 | 7× C_base | 6.4× |
| 2 — Reinforced | 4 | 15× C_base | 13.2× |
| 3 — Maximum | 5 | 31× C_base | 26.8× |

> Measured ratios are lower than theoretical bounds due to Argon2id's internal lane parallelism (`p=4`). The security-relevant quantity is **memory work** (Ω(m) per thread), not wall-clock time.

---

## Storage–Computation Asymmetry

The defender stores O(L) bytes independent of the security parameter. The attacker must reconstruct Ω(N × 64 MB) of Argon2id state per password attempt.

| Level | Defender storage | Attacker RAM/attempt | Ratio |
|-------|-----------------|---------------------|-------|
| 1 | 3,196 B | 192 MB | 62,993× |
| 2 | 4,237 B | 256 MB | 63,355× |
| 3 | 5,278 B | 320 MB | 63,574× |

**GPU bound (RTX 4090, 24 GB VRAM):** ≤ 375 parallel threads at Level 1 base memory (64 MB/thread).

---

## Quick Start

### Requirements

```bash
pip install argon2-cffi numpy
```

### Encrypt a file

```python
from argon2id_shield import a2shield_enc, a2shield_dec

plaintext = b"Secret message"
password  = b"my-strong-password"

# Encrypt at Level 2 (Reinforced — 4 layers, 15× attacker cost)
ciphertext = a2shield_enc(plaintext, password, level=2)

# Decrypt
recovered = a2shield_dec(ciphertext, password)
assert recovered == plaintext
```

### Run the benchmark

```bash
python3 argon2id_shield.py
```

Output includes: per-layer timing, attacker cost per attempt, storage–computation asymmetry ratios, and test vector generation.

### Reproduce test vectors

```bash
python3 argon2id_shield.py --vectors
# Deterministic output — compare against TEST_VECTORS.md
```

---

## Repository Structure

```
Fractalyx/
├── argon2id_shield.py          # Primary implementation (Argon2id core)
├── mfsu_crypt_ref.py           # Reference implementation (MFSU core)
├── asymmetry_measure.py        # Storage–computation asymmetry measurement
├── TEST_VECTORS.md             # Deterministic test vectors
├── test_vectors.json           # Machine-readable vectors
├── argon2id_shield_report.json # Benchmark report (JSON)
├── papers/
│   ├── fractalshield_argon2id_v11.pdf   # Main paper (Argon2id instantiation)
│   ├── fractalshield_argon2id_v11.tex   # LaTeX source
│   ├── CORELAWS_VOL_1_2.pdf             # Technical Note: C1–C4 laws
│   └── fractalshield_v1.pdf             # Original FractalShield preprint
└── README.md
```

---

## Argon2id Parameters

| Parameter | Value | Source |
|-----------|-------|--------|
| Time cost `t` | 3 passes | RFC 9106 interactive profile |
| Memory `m` | 65,536 KB (64 MB) | RFC 9106 |
| Parallelism `p` | 4 lanes | RFC 9106 |
| Output length | 96 bytes | dk(64B) + ek(32B) |
| Magic prefix | `A2SH\x01` (5 bytes) | False-positive prob. < N/2⁴⁰ |
| Hash / MAC | SHA3-256 / HMAC-SHA3-256 | NIST FIPS 202 |

---

## File Format (`.a2shield v1`)

```
HDR(12B) | SID(16B) | order_enc(N B) | tag(32B) | CT[0]...CT[N-1]
```

Where each `CT[i]` block is `salt(16B) | iv(16B) | ciphertext(L B)`.  
All N ciphertext blocks have **identical length** L — no size-based layer identification possible.  
The session identifier `SID` binds the MAC to the session, preventing replay attacks (Theorem 6.1).

---

## The Four Core Laws (Definition 3.1)

Any function F can serve as the cryptographic core if it satisfies:

| Law | Requirement | If violated |
|-----|-------------|-------------|
| **C1** Input sensitivity | `diffBits(F(k,IV,L), F(k',IV,L)) ≈ 50%` | Hill-climbing attacks; IND-CCA2 breaks |
| **C2** Output pseudorandomness | `F(k,IV,·) ≈_c U_L` | Real layer identifiable; OFV breaks |
| **C3** Cost controllability | `cost(F(·;M))` strictly increasing in M | Geometric escalation collapses to flat N× |
| **C4** Memory hardness | `RAM(F(·;M)) = Ω(M)` | GPU parallelism makes cost vacuous |

Any F satisfying C1–C4 **inherits all four security theorems** without modification.  
See [Technical Note v1.2](papers/CORELAWS_VOL_1_2.pdf) for full formal specification.

---

## Security Theorems

All theorems proved in the paper. Standard model unless noted.

```
Theorem 5.1  Integrity          — SUF-CMA of HMAC-SHA3-256
Theorem 5.2  IV Uniqueness      — Birthday bound (2^128)  
Lemma   5.4  Geometric cost     — Construction: C_att = C_base × (2^N - 1)
Theorem 5.5  Oracle-Free Verif. — Thm 5.1 + C2 + false-pos bound
Theorem 5.7  PRG security       — ROM: Adv ≤ q²/2²⁵⁶ + 2⁻⁶⁴
Theorem 5.8  IND-CCA2           — ROM: Adv ≤ 2q²/2²⁵⁶ + 5/2⁴⁰
Theorem 6.1  Replay resistance  — SUF-CMA + session identifier
```

---

## Test Vectors

Fixed inputs for deterministic verification:

| Parameter | Value |
|-----------|-------|
| Password | `FractalShield_TestVector_v1` |
| Salt (16B) | `000102030405060708090a0b0c0d0e0f` |
| IV (16B) | `101112131415161718191a1b1c1d1e1f` |
| Message | `Hello, Abyss.` (13 B) |

| Vector | Expected |
|--------|----------|
| V1: KDF output (t=3, 96B) | `481e11f3cce157d6b7b2fd9b...` |
| V2: diffBits(V1, KDF t=6) | ≈ 50% ✓ |
| V4: Magic prefix check | correct → `True`, wrong → `False` ✓ |
| V5: Round-trip L1/L2/L3 | exact match ✓ |

Full vectors: [`TEST_VECTORS.md`](TEST_VECTORS.md) and [`test_vectors.json`](test_vectors.json).

---

## Comparison with Related Work

| Property | AES-GCM | Ar2id+AES | Honey Enc. | **FS-Ar2id** |
|----------|---------|-----------|------------|--------------|
| IND-CCA2 | Yes | Partial | Yes | Yes (ROM) |
| Memory-hard KDF | Ext. | Yes | No | Yes (proved) |
| No verification oracle | No | No | Partial | **Yes** |
| Geometric cost escalation | No | No | No | **Yes** |
| Layer indistinguishability | N/A | N/A | Partial | **Yes** |
| Message-space agnostic | Yes | Yes | No (DTE) | **Yes** |
| Replay resistance | No | No | No | **Yes** |
| Public cryptanalysis | 25+ yr | 10+ yr | 10+ yr | None yet |

### vs Honey Encryption specifically

Honey Encryption and FractalShield-Argon2id operate in **different design regimes** — they are complementary, not competing:

| | Honey Encryption | FractalShield-Argon2id |
|--|-----------------|----------------------|
| Oracle mechanism | Semantic confusion (DTE) | Structural (full KDF cost) |
| Message-space dependence | Yes — DTE per space | No — agnostic |
| False positives | Yes (by design) | < N/2⁴⁰ ≈ 5×10⁻¹² |
| Attacker cost/attempt | 1× KDF | (2ᴺ−1)× KDF |
| Attacker RAM/attempt | O(1) | ≥ N × 64 MB |

They can be **composed**: apply Honey Encryption's DTE to the plaintext before FractalShield encryption for additive protection.

---

## Open Problems

| # | Problem | Status |
|---|---------|--------|
| OP1 | IND-CCA2 without ROM | Open |
| OP2 | Scratchpad oblivious read (CT residual) | Partial — oblivious-read fix described, 256× overhead |
| OP3 | Password entropy lower bound | Open |
| OP4 | Full QROM analysis | Partial — geometric factor preserved under Grover |
| OP5 | Independent cryptanalysis audit | **Invited — see below** |
| OP6 | Mechanised verification (EasyCrypt/CryptoVerif) | Open |

---

## Cryptanalysis Invited

No external security audit has been performed on this construction.  
We explicitly invite public cryptanalysis.

**Attack targets:**
- Break OFV without paying C_att(ℓ) per attempt
- Distinguish real layer from decoys without the correct key  
- Forge a MAC-passing ciphertext
- Find a timing oracle beyond CT2a/CT2b (already known: scratchpad access pattern)

**Report findings:** open an issue or email the author.

---
## Papers

| Document | Description |
|----------|-------------|
| [`fractalshield_argon2id_v11.pdf`](papers/ofv_argoin2id_miguel_franco_v1.pdf) | Main paper — Argon2id instantiation, full proofs |
| [`CORELAWS_VOL_1_2.pdf`](papers/CORELAWS_VOL_1_2.pdf) | Technical Note — C1–C4 formal specification, OP1–OP10 |
| [`fractalshield_v1.pdf`](papers/fractalshield_v1.pdf) | Original FractalShield preprint (MFSU-Crypt core) |

---


## Citation

```bibtex
@misc{francoleon2026fractalshield,
  author       = {Franco Le{\'{o}}n, Miguel Angel},
  title        = {{FractalShield-Argon2id}: A Provably Secure Instantiation
                  of Oracle-Free Layered Encryption with Geometric Cost Escalation},
  year         = {2026},
  month        = {May},
  note         = {Preprint v1.1. Not peer-reviewed.},
  url          = {https://github.com/Fracta-Axis/Fractalyx}
}
```

---

## Attribution

The concept of **oracle-free verification through layered magic-prefix detection combined with geometric cost escalation** was first introduced by Miguel Angel Franco León in the FractalShield preprint (May 2026).

The framework is intentionally open for community use. If you build on this work, please cite the main paper and the Technical Note.

---

## License

Code: MIT  
Papers and Technical Notes: CC BY 4.0

---

*Fracta-Axis Project · May 2026*  
*[github.com/Fracta-Axis/Fractalyx](https://github.com/Fracta-Axis/Fractalyx)*
