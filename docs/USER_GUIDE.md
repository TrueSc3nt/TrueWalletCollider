# TrueWalletCollider — Professional User Guide

**Product:** TrueWalletCollider Forensic Suite / Recovery Lab  
**Audience:** Authorized wallet owners, business recovery operators, DFIR analysts  
**Platform:** Windows 10/11 x64 (CUDA optional; NVIDIA GPU for AES search tabs)  
**Repo:** https://github.com/TrueSc3nt/TrueWalletCollider

This guide matches the **current** GUI tabs and CLI flags. It does not describe planned panels that are not in the binary yet.

---

## 1. Legal & honesty

| Rule | Meaning |
|------|---------|
| Authorized use only | Own wallets, business-owned assets, or DFIR under written authority |
| No unauthorized access | Imaging or cracking other people’s wallets without authority is illegal |
| Dual-verify before trust | PKCS padding alone can false-positive; use pubkey EC match when present |
| No AES-256 miracle | Full unknown-key search space is **2^256**. GPU shows research rates; it does not “break” AES |
| Evidence hygiene | Export, transfer offline, then wipe local FOUND/scratch files |

In-app reminders: **Lab Docs** tab and **Results** secure-erase checklist.

---

## 2. Installation / portable layout

### 2.1 What you need on disk

Typical folder after clone or release unpack:

```
TrueWalletCollider/
  TrueWalletCollider.exe      # run this (portable; no installer)
  build_cuda.bat              # full rebuild
  rebuild_quick.bat           # incremental rebuild
  setup_forensics.bat         # optional: fetch Hashcat into third_party/
  README.md
  docs/
  third_party/                # ImGui, GLFW, micro-ecc; Hashcat after setup
  data/                       # sample text helpers (not live wallets)
  cuda/                       # CUDA sources
  src/
```

`.exe` is produced by `build_cuda.bat` / `rebuild_quick.bat`. Live `wallet.dat` files should stay outside the repo (gitignores `*.dat`).

### 2.2 Optional Hashcat (for Hashcat Bridge spawn)

Hashcat Windows binaries are **large** and are **not** committed to git. To integrate them locally:

```bat
setup_forensics.bat
```

This downloads the official Hashcat Windows release into `third_party\hashcat\` (when network is available). The GUI **Hashcat Bridge** looks for:

1. `third_party\hashcat\hashcat.exe` (relative to the process working directory)
2. `hashcat.exe` / `hashcat` on **PATH**

If neither is found, export still works — run Hashcat manually with the written hash file.

**John the Ripper / BTCRecover:** not bundled in this release. Export `$bitcoin$` / use `--export-hashcat` and feed external tools. John: `john --format=bitcoin hash.txt` (after bitcoin2john-style export).

### 2.3 CUDA (AES Partial + CUDA Crack)

- NVIDIA GPU + recent driver  
- For **building**: CUDA Toolkit 12.x/13.x + VS C++  
- For **running** a prebuilt `.exe`: Toolkit not required if the binary is already linked; still need a working CUDA driver stack for those tabs  

Parse, salvage, Passphrase Lab, Hashcat export, and most Tools work **without** a GPU.

### 2.4 Architecture note

Target: **Windows x64**. On unsupported architectures expect clear CUDA/device errors; the suite is not shipped for ARM/x86 as first-class.

---

## 3. First launch

```bat
cd C:\Users\loulo\Desktop\TrueWalletCollider
TrueWalletCollider.exe
```

Window title: **TrueWalletCollider — Recovery Lab**.

- **Left column tabs:** Extract · Salvage · Passphrase Lab · AES Partial · Hashcat Bridge · Results · Tools  
- **Right column tabs:** CUDA Crack · Console · Lab Docs  

Console should log something like `Recovery Lab ready`. If a CUDA device is found it is named; otherwise `[!] no CUDA devices visible`.

**Drag-and-drop:** drop a `.dat` onto the window to load it into Extract.

---

## 4. Recommended case workflow (operator practice)

There is no separate “Case” tab yet. Use a folder convention next to the suite:

```
cases\<matter_name>\
  evidence\          # original wallet.dat / dumps (read-only copies)
  hashes\            # wallet_hash.txt exports
  dicts\             # wordlists
  jobs\              # notes / hashcat command lines
  results\           # FOUND_WALLET copies, reports
  chain_of_custody.txt
```

Suggested operator steps:

1. Record operator ID, date, authority, and source of evidence in `chain_of_custody.txt`.
2. Copy evidence into `evidence\` (never work solely on the only original).
3. **Extract** → parse; note magic, iterations, archaeology flags.
4. If damaged → **Salvage**.
5. Forgotten password → **Passphrase Lab** and/or **Hashcat Bridge**.
6. Partial key / cold-boot candidates → **AES Partial** / **CUDA Crack**.
7. On hit → **Results** dual-verify + multi-ckey decrypt; copy `FOUND_WALLET.txt` offline.
8. Secure erase local secrets (Results).

SHA-256 evidence hashing can be done with built-in Windows tools, e.g. `certutil -hashfile evidence\wallet.dat SHA256`, and recorded in the case notes.

---

## 5. GUI reference (every major tab)

### 5.1 Extract

**Purpose:** Parse a Bitcoin Core–style `wallet.dat`, review integrity signals, export structured data, triage many wallets by iteration count.

| Control / area | Behavior |
|----------------|----------|
| Open wallet.dat | File picker |
| Load PoC targets | Loads built-in crackBTCwallet-style research targets |
| Folder scan mode | Scan a directory for `*.dat`, sort low-iter first; load selected |
| File / Size / Magic | `Magic: OK` or `BAD` plus BDB note text |
| Archaeology flags | Severity-colored table (unencrypted keys, multi-mkey, plaintext scraps, low-iter, etc.) |
| Master key | Offset, encrypted48, salt, IV, CT, method, iterations, target_mkey; copy buttons |
| CKeys | List + detail (address, enc, pubkey); copy |
| Metadata | Tag / offset / note table |
| Export TXT / JSON / ckeys | Writes analysis; `ckeys_export.txt` / `mkeys_export.txt` |

**Authenticity signals available today (not a separate Verify tab):**

- BDB **magic** OK vs BAD  
- Parser notes (`bdb_note`)  
- Archaeology severity flags and counts (`mkeys`, `unencrypted_keys`, `plaintext_scraps`)  
- Structured mkey fields: 48-byte encrypted blob (96 hex), salt/iter/method  
- Ckey pubkey lengths (compressed 33 / uncompressed 65 typical) and 96-hex ciphertext  

Treat odd combinations (bad magic + “perfect” mkey, impossible sizes, garbage hex) as **suspect** until dual-verify against known behavior. A dedicated REAL/FAKE verdict panel is not in the current GUI.

### 5.2 Salvage

**Purpose:** Carve candidates from damaged Berkeley DB or raw dumps.

| Control | Behavior |
|---------|----------|
| Import path + Browse | Path to dump / image fragment |
| salvage_file | File-oriented salvage |
| salvage_carve (raw bytes) | Byte-buffer carve |
| Heatmap | ASCII intensity by offset |
| Ranked ckeys table | Score + note / address |
| Export salvage TXT/JSON | Write report |

CLI twin: `--salvage FILE`.

### 5.3 Passphrase Lab

**Requires:** Loaded wallet with structured **mkey**.

| Control | Behavior |
|---------|----------|
| Single passphrase + Try single | `dual_verify_passphrase` once |
| Dictionary file | Load wordlist (cap ~500k in GUI batch gen) |
| Simple mask | `?d` digit, `?l` lower, `?u` upper, `?s` symbol (e.g. `Pass?d?d?d`) |
| Recall token interview | Known words, prefixes/suffixes, keyboard walks, case, leet, years |
| Generate candidates | Merge dict + mask + recall + optional single |
| Measure H/s | Host KDF throughput estimate |
| Run batch dual_verify_passphrase | Background thread; progress bar; Stop |
| ETA line | Based on iters × candidates ÷ measured H/s |

Hits update dual-verify state and recovered master hex for **Results**.

### 5.4 AES Partial

**Purpose:** Constrained AES search — **not** full 256-bit brute force.

| Control | Behavior |
|---------|----------|
| Hex prefix | Even length, 1..31 bytes → CUDA `MODE_PARTIAL` |
| Start PARTIAL CUDA | Needs loaded wallet/targets + CUDA device |
| Cold-boot keys box | One 64-hex AES key per line; **Try all** on host |

Honesty banner in-tab: use Passphrase Lab / Hashcat Bridge for wallet **passwords**.

CLI doc: `--partial-help`. TrueMkeyCollider CLI can run `--partial HEXPREFIX`.

### 5.5 Hashcat Bridge

**Purpose:** bitcoin2john-style export and optional Hashcat launch.

| Control | Behavior |
|---------|----------|
| `$bitcoin$` display | Extended line when first ckey+pubkey available |
| Copy / Write hash file | Default `wallet_hash.txt` |
| hashcat path status | Shows discovered exe or `(not found on PATH)` |
| Wordlist + Spawn hashcat -m 11300 | `CreateProcess` new console if exe found |

Manual examples shown in-tab:

```text
hashcat -m 11300 -a 0 wallet_hash.txt wordlist.txt
John: bitcoin2john wallet.dat > hash.txt
```

CLI: `--export-hashcat FILE`, and `--parse` also writes `wallet_hashcat.txt` when possible.

### 5.6 Results

| Control | Behavior |
|---------|----------|
| FOUND_WALLET path | Default `FOUND_WALLET.txt`; open location |
| Last dual verify | OK/FAIL, PKCS flags, pubkey_match, master hex |
| Recovered master (64 hex) + decrypt_all_ckeys | Multi-ckey decrypt report + WIF export path via FOUND |
| Secure-erase checklist | Operator bullets |
| Wipe FOUND + hit log | Checkbox + **Run secure erase** (zero overwrite) |

### 5.7 Tools

| Control | Behavior |
|---------|----------|
| Quick passphrase | Method-0 try (message / derived key hex) without full lab batch |
| Verify WIF | Checksum / decode detail |
| Experiments | Buttons for `dual_fp`, `passphrase`, `secp` (log to Console) |

### 5.8 CUDA Crack (right column)

| Control | Behavior |
|---------|----------|
| CUDA device combo | From `CrackEngine::list_devices()` |
| Include mkey / ckeys | Target selection |
| Mode | Random (`-r`), Sequential (`-q`), Mixed (`-rs`) |
| Blocks / Threads / Streams / Mixed span / VRAM | Grid + memory hints |
| Seq start / FOUND / Hit log paths | Files |
| Try AES key (64 hex) | Host decrypt attempt |
| Selftest | PoC pipeline |
| START / STOP | Live keys, rate, peak, HIT + WIF copy |

### 5.9 Console

Clear / Copy all log lines. Primary feedback channel for loads, salvage, cracks, experiments.

### 5.10 Lab Docs

In-app summary of experiment help, recommended workflow bullets, hibernation/RAM guidance (**import only**, authorized), and secure-erase reminder.

---

## 6. wallet.dat extract, salvage, and “is this real?”

### 6.1 Healthy path

1. Extract → Open / drop `wallet.dat`.  
2. Confirm **Magic: OK**, readable mkey (method, iterations, salt, 96-hex enc), ckeys with addresses/pubkeys.  
3. Read archaeology: low severity is normal for encrypted Core wallets; high severity (plaintext keys, scraps) needs extra care.  
4. Export JSON/TXT into your case `results\` folder.

### 6.2 Damaged / corrupt path

1. Salvage → point at dump → `salvage_file` or `salvage_carve`.  
2. Review heatmap and ranked ckeys.  
3. Export salvage report; promote best candidates into Passphrase Lab / CUDA only if structure looks coherent.

### 6.3 Integrity checklist (manual)

| Check | Expectation |
|-------|-------------|
| File size | Non-trivial; empty/tiny files suspect |
| Magic | OK for BDB wallet.dat; BAD → salvage or wrong file |
| mkey enc length | 96 hex (48 bytes) typical |
| salt / iters | Present; extreme iters → slower KDF / triage |
| ckey enc | 96 hex typical |
| pubkey | 33 or 65 bytes hex typical |
| Address | Derives when pubkey present |
| Dual-verify after candidate | Must pass before operational use |

---

## 7. Passphrase Lab, Hashcat jobs, dual-verify

### 7.1 Passphrase Lab first

Best when you remember fragments of the password. Build recall tokens → Generate → Measure H/s → batch.

### 7.2 Hashcat Bridge for large wordlists

1. Write hash file from Bridge (or `--export-hashcat`).  
2. Run `setup_forensics.bat` if you want local Hashcat.  
3. Spawn from GUI **or**:

```bat
hashcat -m 11300 -a 0 cases\matter\hashes\wallet_hash.txt cases\matter\dicts\rockyou.txt
```

4. When Hashcat reports a password, paste it into Passphrase Lab **Try single** to dual-verify and populate Results.

### 7.3 Dual-verify meaning

On success the engine decrypts mkey/ckey material and, when possible, checks that the recovered private key matches the stored **pubkey** via secp256k1 (micro-ecc). Prefer hits with `pubkey_match` over PKCS-only.

---

## 8. AES partial / CUDA crack / FOUND_WALLET

| Scenario | Tab | Mode |
|----------|-----|------|
| Known prefix from dump | AES Partial | `MODE_PARTIAL` |
| Candidate full keys from cold-boot | AES Partial | Try all cold-boot keys |
| Constrained research search | CUDA Crack | Mixed / sequential window |
| Random rate experiment | CUDA Crack | Random (honest: will not finish 2^256) |

On HIT:

- AES key and WIF shown in CUDA Crack status  
- Written to `FOUND_WALLET.txt` (path configurable)  
- Dual-verify runs in the crack pipeline when wallet targets carry pubkeys  

Never leave FOUND files on shared disks after the case closes — use Results wipe.

---

## 9. CLI flags reference

| Flag | Action |
|------|--------|
| *(no args)* | Launch Recovery Lab GUI |
| `-h` / `--help` | Usage |
| `--selftest` | GPU+host PoC AES/WIF; then passphrase + secp experiments. Options: `-d N`, `--found FILE` |
| `--parse FILE` | Parse → stdout TXT; write `FILE.twc.txt`, `FILE.twc.json`, `ckeys_export.txt`, `mkeys_export.txt`, optional `wallet_hashcat.txt` |
| `--export-hashcat FILE` | Print `$bitcoin$` line (extended when possible) |
| `--salvage FILE` | Carve; write `FILE.salvage.txt` / `.json` |
| `--experiment NAME` | `help` \| `dual_fp` \| `passphrase` \| `secp` \| `hashcat_fmt` |
| `--partial-help` | Document partial AES GPU mode |
| `--no-gui` | Prints usage (placeholder; use real flags above) |
| `--cmd doublesha256 <hex>` | Double-SHA256 helper |
| `--cmd aesdecrypt <iv> <key> <enc>` | AES decrypt helper |
| `--cmd privatekeytowif <priv>` | WIF from private key |

Exit codes: success typically `0`; parse/salvage may return `2` when no useful material found.

---

## 10. End-to-end scenarios

### A. Forgotten passphrase (healthy wallet.dat)

1. Extract → load wallet → note iterations.  
2. Passphrase Lab → recall words + years + case/leet → Generate → batch.  
3. If dict is huge → Hashcat Bridge → `-m 11300`.  
4. Results → confirm dual-verify → `decrypt_all_ckeys` → offline backup → wipe.

### B. Corrupt / truncated wallet

1. Salvage on the dump; export ranked candidates.  
2. If mkey carved with salt/iters → attempt passphrase / hashcat export if fields complete.  
3. If only ckeys → CUDA needs targets + pubkeys; Passphrase Lab needs mkey — reconstruct from better disk copy if possible.  
4. Document gaps in chain-of-custody notes.

### C. Partial AES key / cold-boot candidates

1. Extract (or salvage) so mkey/ckeys are targets.  
2. AES Partial → enter known hex prefix → Start PARTIAL CUDA **or** paste 64-hex keys → Try all.  
3. On hit → Results / FOUND_WALLET → dual-verify → multi-ckey.  
4. Do not extrapolate success to “we can brute unknown AES.”

---

## 11. Troubleshooting

| Symptom | Checks |
|---------|--------|
| No CUDA devices | Driver / GPU; parse/passphrase still usable |
| Magic BAD | Wrong file type, or use Salvage |
| Passphrase Lab disabled | Need structured mkey |
| Hashcat “(not found)” | Run `setup_forensics.bat` or install Hashcat on PATH; export still works |
| Spawn fails | Wordlist path, hash file written, antivirus blocking CreateProcess |
| Selftest fail | CUDA build mismatch; try `--experiment passphrase` / `secp` offline |
| PKCS OK but pubkey fail | Treat as false positive; do not move funds |
| Slow batch | High `nDeriveIterations`; use Hashcat GPU for large lists |
| Drop `.dat` ignored | Extension must be `.dat` (case-insensitive) |

Rebuild issues: see `build_cuda.bat` messages for missing `vcvars64` or CUDA Toolkit.

---

## 12. Limits / honesty (read before promising results)

1. **Passphrase recovery** is the primary practical path for encrypted Core wallets.  
2. **Partial AES** is valid only with constrained unknown bytes (prefix/suffix/candidates).  
3. **Random CUDA search** demonstrates capability and PoC — it is not a finishing strategy for unknown 256-bit keys.  
4. **Hashcat Bridge** is interop, not a built-in Hashcat UI with live stdout in this version (spawn opens a separate console).  
5. **BTCRecover / John / BIP39 labs** are not first-class GUI tabs in this build — use external tools with exported hashes where appropriate.  
6. Hibernation / pagefile analysis is **guidance + import** of user-supplied material only.  

---

## 13. Related docs

| Doc | Content |
|-----|---------|
| [QUICKSTART.md](QUICKSTART.md) | One-page start |
| [RECOVERY_RESEARCH.md](RECOVERY_RESEARCH.md) | Implanted features & dead ends |
| [HIBERNATION_FORENSICS.md](HIBERNATION_FORENSICS.md) | Authorized cold-boot / hibernation notes |
| [FORMAT.md](FORMAT.md) | mkey/ckey 48-byte layout, WIF pipeline |
| [CUDA.md](CUDA.md) | CUDA build / kernel notes |
| [../THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) | Third-party licenses |
| [../README.md](../README.md) | Product README |

---

*TrueScent — TrueWalletCollider Forensic Suite / Recovery Lab. Authorized recovery only.*
