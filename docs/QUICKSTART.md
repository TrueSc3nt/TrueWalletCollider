# TrueWalletCollider — Quick Start

Authorized owner / DFIR recovery only. Windows x64.

## 1. Open the suite

```bat
cd %USERPROFILE%\Desktop\TrueWalletCollider
TrueWalletCollider.exe
```

Optional Hashcat for Bridge spawn:

```bat
setup_forensics.bat
```

## 2. Load evidence

- **Extract** → Open `wallet.dat`, or drag-and-drop a `.dat`  
- Check **Magic** and **Archaeology flags**  
- Damaged file → **Salvage**

## 3. Recover

| Situation | Go to |
|-----------|--------|
| Remember fragments of the password | **Passphrase Lab** |
| Large wordlist / GPU dict attack | **Hashcat Bridge** → `-m 11300` |
| Known AES key prefix / cold-boot hex keys | **AES Partial** |
| Research AES search / try key / selftest | **CUDA Crack** |

## 4. Confirm & clean up

1. **Results** → dual-verify OK (+ pubkey match when possible)  
2. `decrypt_all_ckeys` / copy `FOUND_WALLET.txt` offline  
3. Secure erase → wipe FOUND + hit log  

## CLI cheatsheet

```bat
TrueWalletCollider.exe --parse wallet.dat
TrueWalletCollider.exe --export-hashcat wallet.dat
TrueWalletCollider.exe --salvage dump.bin
TrueWalletCollider.exe --selftest
TrueWalletCollider.exe --help
```

Full manual: [USER_GUIDE.md](USER_GUIDE.md)
