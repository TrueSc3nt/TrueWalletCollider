# TrueWalletCollider — Forensic Suite / Recovery Lab

**TrueScent** portable Windows toolkit for **authorized** Bitcoin Core `wallet.dat` recovery, DFIR triage, and cryptanalysis R&D.

Dear ImGui + GLFW + OpenGL GUI with embedded **CUDA AES** search (TrueMkeyCollider core), native **passphrase / KDF**, **salvage carve**, **dual-verify**, and **Hashcat Bridge** (`$bitcoin$` / `-m 11300`).

> **Authorized use only** — wallet owners, businesses recovering their own assets, and DFIR under clear legal authority.  
> Unauthorized access to wallets or systems is illegal.  
> Passphrase/KDF + dual-verify + salvage + **partial** AES are the real levers. Raw full AES-256 against unknown keys remains **2^256** — GPU rate ≠ a break.

---

## Who it’s for

| Audience | Use |
|----------|-----|
| Owner / self-recovery | Forgotten passphrase, corrupt `wallet.dat`, constrained key material |
| Business / custody ops | Authorized internal recovery with dual-verify before moving funds |
| DFIR labs | Extract, salvage, archaeology flags, hash export, evidence hygiene |

**Not** a magic AES breaker, malware kit, or silent memory scraper.

---

## Feature inventory (what ships today)

| Area | Capabilities |
|------|----------------|
| **Extract** | Parse `wallet.dat`, BDB magic / notes, mkey + ckeys UI, metadata, archaeology flags, folder scan (low-iter first), TXT/JSON/ckeys export, drag-and-drop `.dat` |
| **Salvage** | Carve mkey/ckey/pubkey from damaged BDB or raw dumps; heatmap; ranked ckeys; TXT/JSON |
| **Passphrase Lab** | Method-0 KDF, single try, dictionary, simple mask (`?d/?l/?u/?s`), recall token wizard (case/leet/years/walks), H/s + ETA, batch `dual_verify_passphrase` |
| **AES Partial** | Known hex prefix → CUDA `MODE_PARTIAL`; cold-boot candidate keys (64-hex lines) on host |
| **Hashcat Bridge** | Export `$bitcoin$…` for `-m 11300` / John; write hash file; spawn `hashcat.exe` if on PATH or under `third_party\hashcat\` after setup |
| **Results** | Last dual-verify status, multi-ckey decrypt from recovered master, `FOUND_WALLET.txt`, secure-erase checklist + zero wipe |
| **Tools** | Quick passphrase try, WIF verify, experiments (`dual_fp` / `passphrase` / `secp`) |
| **CUDA Crack** | Random / sequential / mixed AES search, try key, selftest, live rate / HIT → WIF |
| **Console / Lab Docs** | Log copy, in-app workflow notes + hibernation guidance |

Deeper research notes: [docs/RECOVERY_RESEARCH.md](docs/RECOVERY_RESEARCH.md) · Format: [docs/FORMAT.md](docs/FORMAT.md) · CUDA: [docs/CUDA.md](docs/CUDA.md)

---

## Quick start

```bat
cd %USERPROFILE%\Desktop\TrueWalletCollider
TrueWalletCollider.exe
```

Optional Hashcat for the Bridge (download into `third_party\` — binaries are large, not in git):

```bat
setup_forensics.bat
```

Full walkthrough: **[docs/USER_GUIDE.md](docs/USER_GUIDE.md)** · One-pager: **[docs/QUICKSTART.md](docs/QUICKSTART.md)**

---

## CLI

```bat
TrueWalletCollider.exe                         rem Recovery Lab GUI
TrueWalletCollider.exe --help
TrueWalletCollider.exe --selftest              rem GPU+host PoC + passphrase/secp experiments
TrueWalletCollider.exe --parse wallet.dat      rem TXT/JSON + ckeys/mkeys + hashcat line
TrueWalletCollider.exe --export-hashcat wallet.dat
TrueWalletCollider.exe --salvage dump.bin
TrueWalletCollider.exe --experiment help
TrueWalletCollider.exe --experiment dual_fp|passphrase|secp|hashcat_fmt
TrueWalletCollider.exe --partial-help
TrueWalletCollider.exe --cmd doublesha256 <pubkey_hex>
TrueWalletCollider.exe --cmd aesdecrypt <iv32hex> <key64hex> <enc96hex>
TrueWalletCollider.exe --cmd privatekeytowif <priv64hex>
```

CUDA-only sibling with rich CLI: [TrueMkeyCollider](https://github.com/TrueSc3nt/TrueMkeyCollider) (`--partial`, `-ckeys`, etc.).

---

## Build (Windows x64 + CUDA)

```bat
cd %USERPROFILE%\Desktop\TrueWalletCollider
build_cuda.bat
```

Requires Visual Studio 2022/18 C++ tools and CUDA Toolkit 12.x/13.x. Quick rebuild: `rebuild_quick.bat`.

Portable run: double-click `TrueWalletCollider.exe` from the folder (no installer). CUDA needs a compatible NVIDIA GPU + drivers for crack tabs; parse / salvage / passphrase / export work without GPU.

---

## Legal / honesty banner

- **Authorized recovery and DFIR only.** No unauthorized wallet or host access.
- Dual-verify (PKCS + secp256k1 pubkey match when possible) before trusting a “hit.”
- **No claim** of breaking AES-256 over the full key space.
- After recovery: move funds / re-secure, then wipe `FOUND_WALLET.txt` and scratch files (Results tab).

---

## Sample PoC (bundled selftest)

| Field | Value |
|-------|--------|
| AES key | `563758754506d53828c5383d2cb6296efe7f217c5ef6a84b13bce3ecec66da2e` |
| WIF_c | `KyKVQiQTML68gzEEce7HsEK9S4j4XqyZWQ6GdaGrSSk8XZJHqNWe` |

Do **not** commit live wallets with funds.

---

## Attribution

- Wallet pattern concepts: BitcoinWalletAnalyzer (Mizogg) — clean-room C++
- AES / WIF pipeline: crackBTCwallet concepts via [TrueMkeyCollider](https://github.com/TrueSc3nt/TrueMkeyCollider)
- secp256k1 dual-verify: [micro-ecc](https://github.com/kmackay/micro-ecc) (BSD)
- AES tables: Bitcoin Core `ctaes`
- UI: Dear ImGui, GLFW
- Hashcat (optional interop): see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)

## License

MIT — see [LICENSE](LICENSE). Third-party licenses apply to vendored ImGui/GLFW/ctaes/micro-ecc and any tools fetched by `setup_forensics.bat`.

**Repo:** https://github.com/TrueSc3nt/TrueWalletCollider
