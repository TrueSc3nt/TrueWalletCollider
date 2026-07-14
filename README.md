# TrueWalletCollider

**TrueScent lab** — a redesigned Bitcoin Core `wallet.dat` analyzer with **TrueMkeyCollider** CUDA AES-256 mkey/ckey cracking built in.

Dark brass-noir GUI (Dear ImGui + GLFW + OpenGL). Full key extraction, export, passphrase attempt, and GPU search with auto post-hit decrypt → WIF → `FOUND_WALLET.txt`.

> Educational / recovery tooling. Never commit real wallets that hold funds. Key space for raw AES-256 remains 2^256 — GPU rate ≠ feasibility for unknown keys.

## Features

- **wallet.dat parse** (clean-room port of BitcoinWalletAnalyzer concepts + extras)
  - BDB magic check (offset 12)
  - Master key (`mkey`): encrypted blob, salt, KDF method, iterations, IV, CT, hashcat-style target string
  - All **ckeys**: encrypted private keys, public keys, P2PKH addresses (SHA256 → RIPEMD160 → Base58)
  - Metadata tag scan: `version`, `bestblock`, `pool`, `name`, `hdchain`, …
  - Target address match
  - Export **TXT / JSON** + `ckeys.txt` / `mkeys.txt` formats for the cracker
- **CUDA crack panel** (embedded [TrueMkeyCollider](https://github.com/TrueSc3nt/TrueMkeyCollider) kernels)
  - Modes `-r` / `-q` / `-rs`, grids `-g`, streams, `-M auto`, device select
  - Live speed (auto K/M/G keys/s), start/stop
  - On hit: IV from double-SHA256(pubkey) → AES-CBC → padding → WIF → `FOUND_WALLET.txt`
  - `--selftest` PoC pipeline
- **Tools**: passphrase attempt (Bitcoin Core method 0 / EVP_BytesToKey SHA512), WIF verify, copy hex buttons
- Drag-drop `.dat`, open file dialog, console log, noir/light theme toggle

## Screenshots (layout)

| Panel | Contents |
|-------|----------|
| Overview | Path, magic, mkey summary, ckey count, target address, export |
| Master Key | Full hex fields + copy |
| CKeys | List + detail (enc / pub / address / hash chain) |
| Metadata | Tag table with offsets |
| CUDA Crack | Device, grid, streams, mode, live rate, hits |
| Tools / Console | Passphrase, WIF check, log |

## Requirements

- Windows 10/11 x64
- Visual Studio 2022 **or** VS 18 Build Tools (MSVC)
- NVIDIA CUDA Toolkit 12.x (preferred) or 13.x
- GPU compute capability ≥ 7.5 (fatbin `sm_75`…`sm_90`)

## Build

```bat
cd %USERPROFILE%\Desktop\TrueWalletCollider
build_cuda.bat
```

(`build.bat` is an alias.) Produces `TrueWalletCollider.exe` and runs `--selftest`.

## Run

```bat
TrueWalletCollider.exe                 rem GUI
TrueWalletCollider.exe --selftest      rem host+GPU PoC
TrueWalletCollider.exe --parse wallet.dat
```

### GUI workflow

1. Drop or Open a `wallet.dat` (or **Load PoC targets** for the bundled crackBTCwallet sample).
2. Review Master Key / CKeys / Metadata; export if needed.
3. Open **CUDA Crack** → set device / `-M auto` / streams → **START**.
4. On hit, inspect WIFs and `FOUND_WALLET.txt`.

### Sample / PoC notes

Bundled PoC (also used by `--selftest`):

| Field | Value |
|-------|--------|
| AES key | `563758754506d53828c5383d2cb6296efe7f217c5ef6a84b13bce3ecec66da2e` |
| WIF_u | `5JHsqscg3o1iAWjRP83nWWJFbgMrjnXwVQoxejtAqp4t6cCVgbo` |
| WIF_c | `KyKVQiQTML68gzEEce7HsEK9S4j4XqyZWQ6GdaGrSSk8XZJHqNWe` |

Do **not** commit live `wallet.dat` files with funds. Use empty/test dumps only.

## How CUDA is integrated

TrueWalletCollider **statically links** the same sources as TrueMkeyCollider:

| Component | Path |
|-----------|------|
| CUDA AES search | `cuda/aes256_cuda.cu` / `.h` |
| Host crypto / WIF | `src/crypto/crypto_wallet.*`, `ctaes.*` |
| Threaded controller | `src/crack/CrackEngine.*` (GUI start/stop + status) |

The GUI builds `TargetCipher` blobs from parsed mkey/ckeys and drives `cuda_aes_launch` in a background thread. Post-hit uses `post_hit_decrypt_wif` + `save_found_wallet`.

File formats for offline CLI targets: see [docs/FORMAT.md](docs/FORMAT.md).

## Attribution

- Wallet byte-pattern extraction concepts: [BitcoinWalletAnalyzer](https://github.com/Mizogg/BitcoinWalletAnalyzer) (Mizogg) — clean-room C++ reimplementation
- AES crack / WIF pipeline concepts: [crackBTCwallet](https://github.com/albertobsd/crackBTCwallet) (AlbertoBSD) via [TrueMkeyCollider](https://github.com/TrueSc3nt/TrueMkeyCollider)
- AES table implementation: Bitcoin Core `ctaes` (see `docs/CTAES_COPYING.txt`)
- UI: [Dear ImGui](https://github.com/ocornut/imgui), [GLFW](https://github.com/glfw/glfw)

## License

MIT — see [LICENSE](LICENSE). Third-party licenses apply to vendored ImGui/GLFW/ctaes.
