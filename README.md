# TrueWalletCollider — Forensic Suite / Recovery Lab

**Made by TrueScent** · Telegram: [https://t.me/TrueScent](https://t.me/TrueScent)

Portable Windows **x64** toolkit for **authorized** Bitcoin Core `wallet.dat` recovery, DFIR triage, and cryptanalysis R&D.

Dear ImGui + GLFW + OpenGL GUI with embedded **CUDA AES** search (TrueMkeyCollider core), native passphrase / KDF with **runtime CPU SIMD detection** (SSE2 / AVX / AVX2 / AVX-512), salvage, dual-verify, **Breaker & Rebuild Lab**, Verify / Case evidence tabs, and bundled third-party bridges (Hashcat, BTCRecover + embeddable Python, John the Ripper) after one `setup_forensics.bat` run.

> **Authorized use only** — wallet owners, businesses recovering their own assets, and DFIR under clear legal authority.  
> Unauthorized access to wallets or systems is illegal.  
> Classic Bitcoin Core `wallet.dat` typically stores **no BIP39 mnemonic** — Breaker Lab reports that honestly.  
> Passphrase/KDF + dual-verify + salvage + **partial** AES are the real levers. Raw full AES-256 against unknown keys remains **2^256**.

---

## Feature inventory (ships in this build)

### Left-column GUI tabs

| Tab | Capabilities |
|-----|----------------|
| **Extract** | Parse `wallet.dat`, archaeology flags, folder scan by iters, TXT/JSON/ckey exports, drag-drop |
| **Salvage** | Carve mkey/ckey from damaged dumps; heatmap + ranked candidates |
| **Passphrase Lab** | Method-0 KDF, dict/mask/recall wizard, dual-verify batch, measured H/s |
| **AES Partial** | CUDA prefix search (`MODE_PARTIAL`) + cold-boot hex candidates |
| **Breaker & Rebuild** | Orchestrate verify / carve / native KDF / Hashcat / John / BTCRecover / CUDA-hint; carve mnemonics with honesty; rebuild = decrypt all keys + re-encrypt mkey under **your** new passphrase + WIF/JSON export |
| **Verify** | REAL / SUSPECT / FAKE / CORRUPT checklist (wallet, `$bitcoin$`, pasted mkey/ckey) |
| **Case** | `cases/<id>/` notes, artifact copies, PowerShell zip export |
| **BTCRecover Lab** | tokenlist / passwordlist / BIP39 / Electrum / typos / seedrecover + stream |
| **Hashcat Bridge** | `$bitcoin$` `-m 11300` export, spawn + **stream**, John `--format=bitcoin` |
| **Results** | Dual-verify status, `decrypt_all_ckeys`, FOUND_WALLET, secure-erase checklist |
| **Tools** | Pass/WIF, BIP39, brainwallet, Base58/Bech32, hex+entropy, wallet.dat diff, strings, balance HTTP, triage |

### Right-column GUI tabs

| Tab | Capabilities |
|-----|----------------|
| **CUDA Crack** | Random / sequential / mixed AES search, try key, selftest, live HIT + WIF |
| **Console** | Unified log (clear / copy) |
| **Lab Docs** | In-app workflow, hibernation guidance (import only), secure-erase reminder |

### Native status / branding

- Brand bar: **TrueWalletCollider // Forensic Suite** · Made by TrueScent · [t.me/TrueScent](https://t.me/TrueScent)
- Status line: `CPU: AVX2 active (N KDF workers)` (runtime SIMD → orchestrator parallel native KDF)

### Bundled via `setup_forensics.bat`

| Bundle | Path |
|--------|------|
| Hashcat 6.2.6 | `third_party/hashcat/` |
| Python embed 3.12 | `third_party/python/` |
| BTCRecover | `third_party/btcrecover/` |
| John jumbo | `third_party/john/` |
| BIP39 wordlist | `data/bip39_english.txt` |
| Launchers | `third_party/run_hashcat.bat`, `run_btcrecover.bat`, `run_john.bat` |

---

## Quick start

```bat
cd %USERPROFILE%\Desktop\TrueWalletCollider
setup_forensics.bat
TrueWalletCollider.exe
```

Confirm brand bar shows SIMD status, then:

```bat
TrueWalletCollider.exe --tools-status
```

Guides: [docs/QUICKSTART.md](docs/QUICKSTART.md) · [docs/USER_GUIDE.md](docs/USER_GUIDE.md)  
Notices: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)

---

## CLI

```bat
TrueWalletCollider.exe                  # Forensic Suite GUI
TrueWalletCollider.exe -h
TrueWalletCollider.exe --tools-status
TrueWalletCollider.exe --verify wallet.dat
TrueWalletCollider.exe --verify "$bitcoin$..."
TrueWalletCollider.exe --parse wallet.dat
TrueWalletCollider.exe --export-hashcat wallet.dat
TrueWalletCollider.exe --salvage dump.bin
TrueWalletCollider.exe --selftest
TrueWalletCollider.exe --experiment help
TrueWalletCollider.exe --partial-help
```

Sibling CUDA CLI (partial key research): [TrueMkeyCollider](https://github.com/TrueSc3nt/TrueMkeyCollider)

---

## Build (Windows x64)

Requires Visual Studio C++ tools, CUDA Toolkit 12.x/13.x, and CMake:

```bat
build_cuda.bat
rem or incremental:
rebuild_quick.bat
```

Parse, salvage, Passphrase Lab, Verify, Case, Hashcat export, BTCRecover (CPU), and most Tools work **without** a GPU. AES Partial / CUDA Crack need an NVIDIA driver stack.

---

## Legal / honesty

| Topic | Position |
|-------|----------|
| Authorized use | Own wallets, business-owned assets, or DFIR under written authority |
| No AES-256 miracle | Full unknown-key search space is **2^256**; GPU rates are research / partial-key only |
| BIP39 | Classic Bitcoin Core `wallet.dat` usually has **no** seed — Carve says so |
| Dual-verify | Prefer `pubkey_match` over PKCS-only before moving funds |
| Third-party tools | Hashcat / John / BTCRecover / Python are not owned by TrueScent — see notices |

---

**Made by TrueScent** · [t.me/TrueScent](https://t.me/TrueScent) · Authorized recovery only.
