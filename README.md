# TrueWalletCollider — Recovery Lab

**TrueScent** authorized owner recovery / cryptanalysis R&D for Bitcoin Core `wallet.dat`.

Brass-noir GUI (Dear ImGui + GLFW + OpenGL) with embedded CUDA AES search (TrueMkeyCollider core).

> Passphrase/KDF + dual-verify + salvage + **partial** AES key are the real levers.  
> Raw full AES-256 against unknown keys remains **2^256** — GPU rate ≠ a break. No malware, no silent RAM scrapers.

## Recovery Lab tabs

| Tab | Purpose |
|-----|---------|
| **Extract** | Parse wallet.dat, archaeology flags, folder scan (low-iter first) |
| **Salvage** | Carve damaged BDB / raw dumps; heatmap; ranked ckeys |
| **Passphrase Lab** | Method-0 KDF, dictionary / mask / recall wizard, H/s + ETA |
| **AES Partial** | Known hex prefix → `MODE_PARTIAL` GPU (research / constrained) |
| **Hashcat Bridge** | One-click `$bitcoin$…` for hashcat `-m 11300` / John; optional spawn |
| **Results** | Dual-verify, multi-ckey WIF export, secure-erase checklist |
| **CUDA Crack** | Random / sequential / mixed / partial AES search + auto WIF |
| **Lab Docs** | Experiments + hibernation guidance (import-only) |

## Build

```bat
cd %USERPROFILE%\Desktop\TrueWalletCollider
build_cuda.bat
```

Requires VS 2022/18 C++ tools + CUDA Toolkit 12.x/13.x.

## Run

```bat
TrueWalletCollider.exe                      rem Recovery Lab GUI
TrueWalletCollider.exe --selftest           rem AES PoC + passphrase + secp
TrueWalletCollider.exe --parse wallet.dat
TrueWalletCollider.exe --export-hashcat wallet.dat
TrueWalletCollider.exe --salvage dump.bin
TrueWalletCollider.exe --experiment help
TrueWalletCollider.exe --partial-help
```

## How to open Recovery Lab

Launch `TrueWalletCollider.exe` (no args). Left column tabs are the Lab; right column is CUDA / Console / Docs.

## Research notes

See [docs/RECOVERY_RESEARCH.md](docs/RECOVERY_RESEARCH.md) and [docs/HIBERNATION_FORENSICS.md](docs/HIBERNATION_FORENSICS.md).

CUDA details: [docs/CUDA.md](docs/CUDA.md). OpenCL is a future option — CUDA first.

## Sample / PoC

Bundled crackBTCwallet-style PoC (Load PoC / `--selftest`):

| Field | Value |
|-------|--------|
| AES key | `563758754506d53828c5383d2cb6296efe7f217c5ef6a84b13bce3ecec66da2e` |
| WIF_c | `KyKVQiQTML68gzEEce7HsEK9S4j4XqyZWQ6GdaGrSSk8XZJHqNWe` |

Do **not** commit live wallets with funds.

## Attribution

- Wallet pattern concepts: BitcoinWalletAnalyzer (Mizogg) — clean-room C++
- AES / WIF pipeline concepts: crackBTCwallet (AlbertoBSD) via [TrueMkeyCollider](https://github.com/TrueSc3nt/TrueMkeyCollider)
- secp256k1 dual-verify: [micro-ecc](https://github.com/kmackay/micro-ecc) (BSD)
- AES tables: Bitcoin Core `ctaes`
- UI: Dear ImGui, GLFW

## License

MIT — see [LICENSE](LICENSE). Third-party licenses apply to vendored ImGui/GLFW/ctaes/micro-ecc.
