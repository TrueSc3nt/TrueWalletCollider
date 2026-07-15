# TrueWalletCollider — Forensic Suite / Recovery Lab

**Made by TrueScent** · Telegram: [https://t.me/TrueScent](https://t.me/TrueScent)

Portable Windows **x64** toolkit for **authorized** Bitcoin Core `wallet.dat` recovery, DFIR triage, and cryptanalysis R&D.

Dear ImGui + GLFW + OpenGL GUI with embedded **CUDA AES** search (TrueMkeyCollider core), native passphrase / KDF with **runtime CPU SIMD detection** (SSE2 / AVX / AVX2 / AVX-512), salvage, dual-verify, **Breaker & Rebuild Lab**, **Outside Box** maximalist archaeology, **Universal Tool Bay** (full DFIR research catalog — nothing left docs-only), Verify / Case evidence tabs, and bundled third-party bridges after `setup_forensics.bat`.

> **Authorized use only** — wallet owners, businesses recovering their own assets, and DFIR under clear legal authority.  
> Unauthorized access to wallets or systems is illegal.  
> Classic Bitcoin Core `wallet.dat` typically stores **no BIP39 mnemonic** — Breaker Lab reports that honestly.  
> Passphrase/KDF + dual-verify + salvage + **partial** AES are the real levers. Raw full AES-256 against unknown keys remains **2^256**.  
> Memory / VSS features are **guided capture + import** of user-supplied dumps (and elevated PowerShell VSS copy). **No silent RAM stealers.**  
> **Commercial LE / on-chain tools are Integration Hub bridges only** — never claimed as free embeds. GPU seed tools may be experimental. **On-chain labeling ≠ crack.**

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
| **Outside Box** | All 23 archaeology / memory-import / structural / lab-exotic modules (see below) |
| **Verify** | REAL / SUSPECT / FAKE / CORRUPT checklist (wallet, `$bitcoin$`, pasted mkey/ckey) |
| **Case** | `cases/<id>/` notes, artifact copies, PowerShell zip export |
| **BTCRecover Lab** | tokenlist / passwordlist / BIP39 / Electrum / typos / seedrecover + stream |
| **Hashcat Bridge** | `$bitcoin$` `-m 11300` export, spawn + **stream**, John `--format=bitcoin` |
| **Results** | Dual-verify status, `decrypt_all_ckeys`, FOUND_WALLET, secure-erase checklist |
| **Tools** | Pass/WIF, BIP39, brainwallet, Base58/Bech32, hex+entropy, wallet.dat diff, strings, balance HTTP, triage |
| **Tool Bay** | Searchable Universal Tool Bay (100+ DFIR entries) · native Pipelines · Commercial Integration Hub |

### Right-column GUI tabs

| Tab | Capabilities |
|-----|----------------|
| **CUDA Crack** | Random / sequential / mixed AES search, try key, selftest, live HIT + WIF |
| **Console** | Unified log (clear / copy) |
| **Lab Docs** | In-app workflow, honesty limits, hibernation guidance (import only), secure-erase reminder |

### Universal Tool Bay (nothing left out)

`TrueWalletCollider.exe --catalog-count` prints live counts. Every item from the Huge DFIR research dump (Hashcat/John/BTCRecover, pywallet, WalletForge, BitcoinCarver, key-elf, seedcat, Hydra, CUDA_Mnemonic, MetaMask/Exodus, bulk_extractor, TSK/Autopsy, Volatility3, VSS, OCR, aLEAPP/iLEAPP, Electrum, PassLLM, Top 25, 150 quickfire, commercial LE, on-chain) has a GUI catalog row.

| Class | Meaning |
|-------|---------|
| **Native** | Built-in runnable pipelines |
| **Setup** | `setup_forensics.bat` → `third_party/` (Installed/Missing in GUI) |
| **Experimental** | Clone/build (seed GPU farms, etc.) |
| **Bridge** | Launch if installed |
| **Commercial** | Licensed path detect — never pirate |
| **Idea** | Research checklist (still in the bay, never docs-only) |

### Outside Box modules (honest status)

| # | Module | Status | Notes |
|---|--------|--------|-------|
| 1 | Shadow-copy / VSS harvester | **LANDED** | List shadows + UAC-elevated PowerShell copy into `case/vss/` |
| 2 | NTFS undelete / MFT residual | **LANDED** | Best-effort carve of **user-supplied** unallocated/disk-image dump (not full NTFS undelete engine) |
| 3 | Cloud sync ghost finder | **LANDED** | Recursive `wallet.dat*`, `(1)`, `.tmp`, conflict copies under chosen roots |
| 4 | Portable / leftover scanner | **LANDED** | Common Core paths + USB/drive-letter scan |
| 5 | Unlock-session capture kit | **LANDED** | Checklist UI + import scavenger (no live silent dump) |
| 6 | pagefile / hiberfil hunt | **LANDED** | Stream BIP39/wordlike/passphrase pattern scan with progress |
| 7 | GPU VRAM residue | **EXPERIMENTAL-LITE** | Import raw VRAM dump → string/hex candidates; noisy by nature |
| 8 | Passphrase-change archaeology | **LANDED** | Extract multiple mkeys; shared-dict attack each |
| 9 | Crash-dump partial AES keys | **LANDED** | 32-byte candidates from dump → dual-verify |
| 10 | Descriptor / PSBT scrapyard | **LANDED** | Carve descriptors, PSBT magic, xpub/xprv scraps |
| 11 | Multi-wallet / Two-Body | **LANDED** | Case folder load + shared-passphrase multi-target |
| 12 | Keyboard adjacency / fat-finger | **LANDED** | Mutants from almost-password → Passphrase Lab candidates |
| 13 | Heir interview grammar | **LANDED** | Structured story fields → recall candidates |
| 14 | Password-manager CSV bridge | **LANDED** | Chrome / Bitwarden / KeePass CSV → wordlist |
| 15 | Backup stitch surgeon | **LANDED** | mkey from A + ckeys from B → dual-verify |
| 16 | Rebuild / re-encrypt | **LANDED** | Breaker tab **3 · Rebuild** |
| 17 | ChipWhisperer / EM importer | **EXPERIMENTAL-LITE** | CSV/bin ranked guesses → AES verify |
| 18 | Fault-injection candidates | **LANDED** | Paste/file of hex keys → dual-verify |
| 19 | Fake-wallet detector++ | **LANDED** | Entropy + consistency scoring beyond basic Verify |
| 20 | Network timeline | **LANDED** | Optional read-only HTTP balance / activity proxy |
| 21 | Time-Slice Crack | **LANDED** | Attack plan ordered by file age × KDF iters |
| 22 | Keyhole mode | **LANDED** | Known AES bytes → plan wired to AES Partial / CUDA |
| 23 | Seed Mirage Meter | **LANDED** | Score carved BIP39 vs wallet addresses (experimental overlap) |

### Bundled via `setup_forensics.bat`

| Bundle | Path |
|--------|------|
| Hashcat 6.2.6 (+ exodus2hashcat) | `third_party/hashcat/` |
| Python embed 3.12 | `third_party/python/` |
| BTCRecover | `third_party/btcrecover/` |
| John jumbo | `third_party/john/` |
| pywallet, metamask_*, Volatility3, LEAPPs, seed/OCR clones, GPU seed repos, PhotoRec, … | `third_party/` (see `setup_forensics.bat`) |
| BIP39 wordlist | `data/bip39_english.txt` |
| Launchers | `third_party/run_*.bat` |

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
TrueWalletCollider.exe --catalog-count
TrueWalletCollider.exe --outside-box
```

Guides: [docs/QUICKSTART.md](docs/QUICKSTART.md) · [docs/USER_GUIDE.md](docs/USER_GUIDE.md) · [docs/DFIR_CATALOG.md](docs/DFIR_CATALOG.md)  
Notices: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)

---

## CLI

```bat
TrueWalletCollider.exe                  # Forensic Suite GUI
TrueWalletCollider.exe -h
TrueWalletCollider.exe --tools-status
TrueWalletCollider.exe --catalog-count
TrueWalletCollider.exe --pipeline metamask "C:\path\to\LevelDB"
TrueWalletCollider.exe --pipeline orch wallet.dat
TrueWalletCollider.exe --outside-box
TrueWalletCollider.exe --verify wallet.dat
TrueWalletCollider.exe --verify-plus wallet.dat
TrueWalletCollider.exe --parse wallet.dat
TrueWalletCollider.exe --export-hashcat wallet.dat
TrueWalletCollider.exe --salvage dump.bin
TrueWalletCollider.exe --vss-list
TrueWalletCollider.exe --portable-scan
TrueWalletCollider.exe --ghost-scan "%USERPROFILE%\OneDrive"
TrueWalletCollider.exe --scavenge-dump unlock.dmp
TrueWalletCollider.exe --timeslice cases\my_case
TrueWalletCollider.exe --csv-bridge passwords.csv
TrueWalletCollider.exe --keyhole 56375875
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

Parse, salvage, Passphrase Lab, Outside Box (CPU paths), Verify, Case, Hashcat export, BTCRecover (CPU), and most Tools work **without** a GPU. AES Partial / CUDA Crack / Keyhole-to-Partial need an NVIDIA driver stack.

---

## Legal / honesty

| Topic | Position |
|-------|----------|
| Authorized use | Own wallets, business-owned assets, or DFIR under written authority |
| No AES-256 miracle | Full unknown-key search space is **2^256**; GPU rates are research / partial-key only |
| BIP39 | Classic Bitcoin Core `wallet.dat` usually has **no** seed — Carve / Seed Mirage say so |
| Memory / VSS | Guided + import / elevated copy only — not malware |
| Dual-verify | Prefer `pubkey_match` over PKCS-only before moving funds |
| Commercial / on-chain | Bridges + licensed installs only; labeling ≠ local crack |
| GPU seed tools | Often experimental (clone/build); need address/xpub |
