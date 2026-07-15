# TrueWalletCollider — Forensic Suite / Recovery Lab

**Made by TrueScent** · Telegram: [https://t.me/TrueScent](https://t.me/TrueScent)

Portable Windows toolkit for **authorized** Bitcoin Core `wallet.dat` recovery, DFIR triage, and cryptanalysis R&D.

Dear ImGui + GLFW + OpenGL GUI with embedded **CUDA AES** search (TrueMkeyCollider core), native passphrase / KDF with **runtime CPU SIMD detection** (SSE2/AVX/AVX2/AVX-512), salvage, dual-verify, **Breaker & Rebuild Lab**, and bundled third-party bridges (Hashcat, BTCRecover + embeddable Python, John the Ripper) after one `setup_forensics.bat` run.

> **Authorized use only** — wallet owners, businesses recovering their own assets, and DFIR under clear legal authority.  
> Unauthorized access to wallets or systems is illegal.  
> Classic Bitcoin Core `wallet.dat` typically stores **no BIP39 mnemonic** — Breaker Lab reports that honestly.  
> Passphrase/KDF + dual-verify + salvage + **partial** AES are the real levers. Raw full AES-256 against unknown keys remains **2^256**.

---

## Feature inventory (ships in this build)

### Native

| Area | Capabilities |
|------|----------------|
| **Extract** | Parse wallet.dat, archaeology, folder scan by iters, exports, drag-drop |
| **Salvage** | Carve mkey/ckey from damaged dumps |
| **Passphrase Lab** | Method-0 KDF, dict/mask/recall wizard, dual-verify batch |
| **AES Partial** | CUDA prefix search + cold-boot hex candidates |
| **Breaker & Rebuild Lab** | Orchestrate verify/carve/native KDF/Hashcat/John/BTCRecover/CUDA-hint; carve mnemonics with honesty; rebuild = decrypt all keys + re-encrypt mkey under **your** new passphrase + WIF/JSON export |
| **Verify** | REAL/SUSPECT/FAKE/CORRUPT + CLI `--verify` |
| **Case** | `cases/<id>/` notes, artifacts, zip export |
| **Hashcat Bridge** | `$bitcoin$` -m 11300 export, spawn + **stream**, John `--format=bitcoin` |
| **BTCRecover Lab** | tokenlist / BIP39 / Electrum / typos / seedrecover + stream |
| **Tools** | BIP39, brainwallet, Base58/Bech32, hex+entropy, wallet.dat diff, strings, balance HTTP, triage |
| **CUDA Crack** | Random/seq/mixed AES, try key, selftest |
| **CPU SIMD** | Status bar: `CPU: AVX2 active (N KDF workers)` — orchestrator parallel native KDF |

### Bundled via `setup_forensics.bat`

| Bundle | Path |
|--------|------|
| Hashcat | `third_party/hashcat/` |
| Python embed | `third_party/python/` |
| BTCRecover | `third_party/btcrecover/` |
| John jumbo | `third_party/john/` |
| BIP39 wordlist | `data/bip39_english.txt` |

---

## Quick start

```bat
cd %USERPROFILE%\Desktop\TrueWalletCollider
setup_forensics.bat
TrueWalletCollider.exe
```

Guide: [docs/USER_GUIDE.md](docs/USER_GUIDE.md) · Notices: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)

## CLI

```bat
TrueWalletCollider.exe --tools-status
TrueWalletCollider.exe --verify wallet.dat
TrueWalletCollider.exe --parse wallet.dat
TrueWalletCollider.exe --export-hashcat wallet.dat
TrueWalletCollider.exe --salvage dump.bin
TrueWalletCollider.exe --selftest
```

Sibling CUDA CLI: [TrueMkeyCollider](https://github.com/TrueSc3nt/TrueMkeyCollider)

---

**Made by TrueScent** · [t.me/TrueScent](https://t.me/TrueScent) · Authorized recovery only.
