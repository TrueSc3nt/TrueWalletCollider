# Forensic bundles (not in git)

Run from repo root:

```bat
setup_forensics.bat
```

Populates (when downloads/clones succeed):

| Path | Purpose |
|------|---------|
| `hashcat/` | Hashcat Windows binaries (+ tools/exodus2hashcat.py) |
| `python/` | Embeddable CPython |
| `btcrecover/` | BTCRecover upstream |
| `john/` | John the Ripper jumbo |
| `pywallet/` | jackjack pywallet |
| `metamask_pwn/`, `metamask-leveldb-forensic-tools/`, `hashcat_26620_kernel/` | MetaMask extractors |
| `volatility3/` | `run_vol.bat` → `python -m volatility3` |
| `iLEAPP/`, `aLEAPP/` | Mobile artifact parsers |
| `seedcat/`, `Hydra/`, `CUDA_Mnemonic_Recovery/` | Experimental GPU seed (may need build) |
| `seed-sweep/`, `Image-Seed-Phrase-Finder/`, … | OCR / FS seed scanners |
| `WalletForge/`, `BitcoinCarver/`, … | Carving research clones |
| `testdisk/` | PhotoRec / TestDisk portable (best-effort) |
| `cupp/`, `CeWL/`, `kwprocessor/`, `princeprocessor/` | Wordlist helpers |
| `run_*.bat` | Thin launchers |
| `FORENSICS_STATUS.txt` | Smoke status |

GUI: **Tool Bay** shows Installed/Missing for every catalog entry.  
Commercial tools are **not** downloaded — Integration Hub only.

Authorized recovery / DFIR use only. Made by TrueScent — https://t.me/TrueScent
