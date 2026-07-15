# TrueWalletCollider — Quick Start

**Made by TrueScent** · https://t.me/TrueScent  
Authorized owner / DFIR recovery only. Windows x64.

## 1. Open the suite

```bat
cd %USERPROFILE%\Desktop\TrueWalletCollider
setup_forensics.bat
TrueWalletCollider.exe
```

Confirm brand bar shows `CPU: AVXx active` and tools via `--tools-status`.

## 2. Load / classify

- **Extract** → Open `wallet.dat`
- **Verify** → REAL / SUSPECT / FAKE / CORRUPT
- **Case** → notes + evidence zip
- Damaged → **Salvage** / Breaker → Carve

## 3. Recover

| Situation | Go to |
|-----------|--------|
| Multi-strategy attack | **Breaker & Rebuild** → Break |
| Password fragments | **Passphrase Lab** |
| Tokenlist / BIP39 / Electrum | **BTCRecover Lab** |
| GPU / large wordlist | **Hashcat Bridge** / John |
| Known AES prefix | **AES Partial** |
| Rematerialize + new password | **Breaker & Rebuild** → Rebuild |

## 4. Confirm & clean up

1. Dual-verify OK
2. Rebuild export or `FOUND_WALLET.txt` offline
3. Secure erase

Full manual: [USER_GUIDE.md](USER_GUIDE.md)
