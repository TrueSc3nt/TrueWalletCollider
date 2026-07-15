# TrueWalletCollider — Professional User Guide

**Product:** TrueWalletCollider Forensic Suite / Recovery Lab  
**Made by TrueScent** · Telegram: https://t.me/TrueScent  
**Audience:** Authorized wallet owners, business recovery operators, DFIR analysts  
**Platform:** Windows 10/11 x64 (CUDA optional; NVIDIA GPU for AES Partial / CUDA Crack)  
**Repo:** https://github.com/TrueSc3nt/TrueWalletCollider

This guide matches the **current** GUI tabs, CLI flags, `setup_forensics.bat` bundles, Breaker & Rebuild Lab, Verify, Case, Hashcat / John / BTCRecover bridges, and CPU SIMD status. It does not invent features.

---

## 1. Legal & honesty

| Rule | Meaning |
|------|---------|
| Authorized use only | Own wallets, business-owned assets, or DFIR under written authority |
| No unauthorized access | Imaging or cracking other people’s wallets without authority is illegal |
| Dual-verify before trust | PKCS padding alone can false-positive; prefer `pubkey_match` via secp256k1 |
| No AES-256 miracle | Full unknown-key search space is **2^256**. GPU shows research rates; it does not “break” AES |
| BIP39 often absent | Classic Bitcoin Core `wallet.dat` typically stores **no** BIP39 seed — Carve reports **NOT PRESENT** |
| Evidence hygiene | Export offline, then wipe local FOUND / scratch files |

In-app reminders: brand bar, **Lab Docs**, **Results** secure-erase checklist, and AUTHORIZED banners on cracker / case tabs.

---

## 2. Installation / portable layout

### 2.1 Disk layout

```
TrueWalletCollider/
  TrueWalletCollider.exe      # portable GUI + CLI
  setup_forensics.bat         # Hashcat + Python + BTCRecover + John → third_party/
  build_cuda.bat              # full CUDA+GUI rebuild
  rebuild_quick.bat           # incremental rebuild
  README.md
  THIRD_PARTY_NOTICES.md
  docs/
  data/                       # bip39_english.txt (setup may fetch)
  cases/                      # created by Case tab (gitignored)
  third_party/                # imgui, glfw, micro-ecc; crackers after setup
  cuda/
  src/
  samples/
```

Live `wallet.dat` files should stay outside the repo (gitignores `*.dat`).

### 2.2 Forensic bundles — `setup_forensics.bat`

Binaries are **large** and **not** committed to git. Integrate locally:

```bat
setup_forensics.bat
```

Steps (1/4 … 4/4):

1. **Hashcat** 6.2.6 → `third_party\hashcat\hashcat.exe`
2. **Embeddable Python** 3.12 → `third_party\python\python.exe` (+ pip / BTCRecover requirements best-effort)
3. **BTCRecover** → `third_party\btcrecover\btcrecover.py`
4. **John jumbo** (win x64) → `third_party\john\run\john.exe` (or `john\john.exe`)

Also: fetches `data\bip39_english.txt` if missing; writes:

| Artifact | Role |
|----------|------|
| `third_party\run_hashcat.bat` | Thin Hashcat launcher |
| `third_party\run_btcrecover.bat` | Python + BTCRecover launcher |
| `third_party\run_john.bat` | John launcher |
| `third_party\FORENSICS_STATUS.txt` | HASHCAT/PYTHON/BTCRECOVER/JOHN OK\|MISSING |

CLI twin: `TrueWalletCollider.exe --tools-status`

If downloads fail (no 7-Zip for `.7z`, network block, etc.), place official builds at the paths above and re-launch. **`$bitcoin$` export always works without bundles.**

### 2.3 CUDA

- **Running** AES Partial / CUDA Crack: NVIDIA GPU + working CUDA driver stack  
- **Building**: CUDA Toolkit 12.x/13.x + VS C++ + CMake (`build_cuda.bat`)  
- **CPU-only workflows**: Extract, Salvage, Passphrase Lab, Verify, Case, Hashcat export, John/BTCRecover (CPU), Tools (except GPU-dependent paths)

### 2.4 Architecture

Target: **Windows x64**. Brand bar shows runtime SIMD: `CPU: SSE2|AVX|AVX2|AVX-512 active (N KDF workers)`. That worker count drives Breaker orchestrator **Native KDF** parallelism.

---

## 3. First launch

```bat
cd C:\Users\YourName\Desktop\TrueWalletCollider
TrueWalletCollider.exe
```

Window: **TrueWalletCollider — Forensic Suite** · Made by TrueScent.

### Layout

| Column | Tabs (left → right order) |
|--------|---------------------------|
| **Left** | Extract · Salvage · Passphrase Lab · AES Partial · **Breaker & Rebuild** · Verify · Case · BTCRecover Lab · Hashcat Bridge · Results · Tools |
| **Right** | CUDA Crack · Console · Lab Docs |

Brand bar: product name, Forensic Suite subtitle, TrueScent credit, SIMD status line, Telegram link **https://t.me/TrueScent**.

**Drag-and-drop:** drop a `.dat` onto the window → loads into Extract.

---

## 4. Recommended case workflow

Use the **Case** tab (`cases/<id>/`) or manual folders:

```
cases\<matter_name>\
  evidence\     # read-only copies of wallet.dat / dumps
  hashes\       # wallet_hash.txt
  dicts\        # wordlists / tokenlists
  jobs\         # command notes
  results\      # FOUND / rebuild exports
  chain_of_custody.txt
```

Operator steps:

1. Case → Create case (title + operator); record authority in notes.  
2. Copy evidence; never modify the sole original.  
3. **Extract** → parse; note magic, iterations, archaeology.  
4. **Verify** → REAL / SUSPECT / FAKE / CORRUPT.  
5. Damaged → **Salvage** and/or Breaker → **Carve**.  
6. Forgotten password → Breaker **Break** and/or Passphrase Lab / Hashcat / John / BTCRecover.  
7. Partial key / cold-boot → **AES Partial** / CUDA Crack.  
8. Hit → Breaker **Rebuild** and/or Results dual-verify + `decrypt_all_ckeys`.  
9. Offline backup → Results secure erase.

Evidence hash: `certutil -hashfile evidence\wallet.dat SHA256`.

---

## 5. GUI reference (every major tab)

### 5.1 Extract

**Purpose:** Parse Bitcoin Core–style `wallet.dat`, review integrity signals, export, triage by iterations.

| Control / area | Behavior |
|----------------|----------|
| Open wallet.dat | File picker |
| Load PoC targets | Built-in research targets |
| Folder scan mode | Scan `*.dat`, sort **low-iter first**; load selected row |
| File / Size / Magic | `Magic: OK` or `BAD` + BDB note |
| Archaeology | Severity-colored flags (unencrypted keys, multi-mkey, plaintext scraps, low-iter, …) |
| Master key | Offset, encrypted48, salt, IV, CT, method, iterations, target_mkey; copy |
| CKeys | List + address / enc / pubkey; copy |
| Metadata | Tag / offset / note |
| Export TXT / JSON / ckeys | Analysis exports; `ckeys_export.txt` / `mkeys_export.txt` |

Also use **Verify** for an explicit REAL/FAKE/CORRUPT verdict (not only archaeology).

### 5.2 Salvage

**Purpose:** Carve candidates from damaged BDB or raw dumps.

| Control | Behavior |
|---------|----------|
| Import path + Browse | Dump / image fragment |
| salvage_file | File-oriented salvage |
| salvage_carve (raw bytes) | Byte-buffer carve |
| Heatmap | ASCII intensity by offset |
| Ranked ckeys | Score + note / address |
| Export salvage TXT/JSON | Report files |

CLI: `--salvage FILE`.

### 5.3 Passphrase Lab

**Requires:** Loaded wallet with structured **mkey**.

| Control | Behavior |
|---------|----------|
| Single passphrase + Try single | One `dual_verify_passphrase` |
| Dictionary file | Wordlist (GUI batch capped ~500k candidates when generating) |
| Simple mask | `?d` digit, `?l` lower, `?u` upper, `?s` symbol (e.g. `Pass?d?d?d`) |
| Recall token interview | Fragments, prefixes/suffixes, keyboard walks, case, leet, years |
| Generate candidates | Merge sources |
| Measure H/s | Host KDF throughput |
| Run batch dual_verify | Background thread + progress; Stop |
| ETA | iters × candidates ÷ measured H/s |

Hits populate Results dual-verify / recovered master hex. Candidates can feed Breaker orchestrator when present.

### 5.4 AES Partial

**Purpose:** Constrained AES search — **not** full 256-bit brute force.

| Control | Behavior |
|---------|----------|
| Hex prefix | Even length, 1..31 bytes → CUDA `MODE_PARTIAL` |
| Start PARTIAL CUDA | Needs wallet/targets + CUDA device |
| Cold-boot keys box | One 64-hex AES key per line; **Try all** on host |

In-tab honesty: passwords → Passphrase Lab / Hashcat / John / BTCRecover, not raw AES fantasy.

CLI doc: `--partial-help`. Sibling CLI: TrueMkeyCollider `--partial HEXPREFIX`.

### 5.5 Breaker & Rebuild Lab (TrueScent)

Title in UI: **TrueScent Wallet Breaker / Rebuild Lab**.

Sub-tabs:

#### 1 · Break (orchestrator)

Checkboxes:

| Option | Role |
|--------|------|
| Verify REAL/FAKE | Run forensic verify checklist |
| Carve | mkey/ckey + mnemonic scrap carve |
| Native KDF (CPU) | Parallel passphrase tries (worker count from SIMD status) |
| Hashcat -m 11300 | Spawn / stream Hashcat on exported `$bitcoin$` |
| John bitcoin | John `--format=bitcoin` |
| BTCRecover | Spawn BTCRecover with dict/tokenlist |
| CUDA partial hint | Prefer partial prefix path when set |
| Use CPU / Use GPU | Strategy gating |

Inputs: Dictionary / passwordlist, BTCRecover tokenlist, Partial AES prefix, Max native tries.  
**RUN ORCHESTRATOR** requires a loaded wallet. Pulls Passphrase Lab candidates / single passphrase when available. Log + step bullets show what ran and any hit (fills recovered master + dual-verify).

#### 2 · Carve

**Carve mkey/ckey + mnemonic scraps** over raw bytes (± parsed wallet).

- Counts: mkeys / ckeys / mnemonics  
- If classic Core-style and no BIP39 hits: banner **BIP39 seed: NOT PRESENT (normal for classic Bitcoin Core wallet.dat)**  
- Mnemonic hits show offset, word count, bip39 checksum OK/no, note, text  

Honesty: does **not** invent seeds for wallets that never stored one.

#### 3 · Rebuild

After master recovery (orchestrator, lab, or paste):

| Field | Meaning |
|-------|---------|
| Recovered master (64 hex) | AES master key |
| New passphrase | Password **you** choose for rematerialized mkey |
| New KDF iterations | Default suitable for method-0 style research re-encrypt |
| Export prefix | Writes `prefix.json` + `prefix.txt` |

**Rebuild package:** decrypt all keys → optional research mkey re-encrypt under new passphrase → WIF uncompressed/compressed + hex + JSON/TXT bundles. Copy JSON / Copy TXT.  
Explicitly: **not** a fake-balance scam wallet.

### 5.6 Verify

**Purpose:** Classify evidence as **REAL / SUSPECT / FAKE / CORRUPT**.

| Control | Behavior |
|---------|----------|
| Path or `$bitcoin$` / paste | File path, hash line, or mkey/ckey text |
| Browse wallet.dat | Picker |
| Verify loaded wallet | Checklist on current parse |
| Run verify | Auto-detects file vs `$bitcoin$` vs text |
| Verdict + table | Check / Pass / Detail |
| Copy report | Clipboard full text |

CLI: `--verify FILE` or `--verify "$bitcoin$..."`  
Exit codes: REAL `0`, SUSPECT `1`, CORRUPT `2`, FAKE `3`.

### 5.7 Case

**Purpose:** Evidence hygiene under `cases/<id>/`.

| Control | Behavior |
|---------|----------|
| Title / Operator | Case metadata |
| Create case | Allocates id, optional evidence path from loaded wallet |
| Open case combo | Load existing ids |
| Note + Append note | Timestamped notes |
| Add loaded wallet as artifact | Copy into case folder |
| Export evidence zip | PowerShell `Compress-Archive` to path |
| Summary child | Live case text |

### 5.8 BTCRecover Lab

Requires `setup_forensics.bat` (Python + BTCRecover). Shows MISSING paths until installed.

| Control | Behavior |
|---------|----------|
| Show --help (stream) | Streamed help into panel |
| wallet.dat / tokenlist / passwordlist | Browse + paths |
| BIP39 mode / Electrum / seedrecover.py | Mode toggles |
| Typos + typo max | Typo attack |
| mnemonic (optional) | For seedrecover-style paths |
| Extra CLI args | Passthrough |
| Build cmdline (copy) | Clipboard full command |
| Launch + stream / Stop | Background process + live output |

Authorized-use banner in-tab. BIP39 modes apply to **wallets/seeds that actually use BIP39** — not “magic Core seed unlock.”

### 5.9 Hashcat Bridge

| Control | Behavior |
|---------|----------|
| Tools status + Rescan | Hashcat / Python / BTCRecover / John paths |
| `$bitcoin$` line | Extended when first ckey+pubkey available |
| Copy / Write hash file | Default `wallet_hash.txt` |
| Wordlist | Optional `-a 0` list |
| Spawn hashcat (new console) | Detached console |
| Spawn + stream / Stop | Live output child |
| Spawn john --format=bitcoin | John on hash file |
| John + stream | Streamed John |

Manual reminder in-tab:

```text
hashcat -m 11300 -a 0 wallet_hash.txt wordlist.txt
```

CLI: `--export-hashcat FILE`; `--parse` may also write `wallet_hashcat.txt`.

### 5.10 Results

| Control | Behavior |
|---------|----------|
| FOUND_WALLET path | Default `FOUND_WALLET.txt`; open location |
| Last dual verify | OK/FAIL, PKCS flags, pubkey_match, master hex |
| Recovered master + decrypt_all_ckeys | Multi-ckey decrypt report + WIF via FOUND path |
| Secure-erase checklist | Operator bullets |
| Wipe FOUND + hit log | Zero overwrite + **Run secure erase** |

### 5.11 Tools (inner tab bar)

| Inner tab | Behavior |
|-----------|----------|
| **Pass/WIF** | Quick method-0 passphrase try; Verify WIF; Experiments (`dual_fp`, `passphrase`, `secp` → Console) |
| **BIP39** | Validate / inspect phrases using `data/bip39_english.txt` |
| **Brainwallet** | Phrase → key material helpers |
| **Base58/Bech32** | Encode/decode utilities |
| **Hex/Entropy** | Hex helpers + entropy notes |
| **Diff** | Compare two wallet.dat paths |
| **Strings** | Extract readable strings from loaded file / path |
| **Balance** | Optional HTTP balance lookup for addresses (operator-initiated) |
| **Triage** | Multi-wallet folder scan sorted by iterations (low first) |

All Tools panels show AUTHORIZED USE ONLY where applicable.

### 5.12 CUDA Crack (right column)

| Control | Behavior |
|---------|----------|
| CUDA device | From `CrackEngine::list_devices()` |
| Include mkey / ckeys | Target selection |
| Mode | Random, Sequential, Mixed |
| Blocks / Threads / Streams / Mixed span / VRAM | Grid + memory hints |
| Seq start / FOUND / Hit log paths | Files |
| Try AES key (64 hex) | Host decrypt |
| Selftest | PoC AES/WIF pipeline |
| START / STOP | Keys, rate, peak, HIT + WIF copy |

Honest scope: constrained research / partial windows — not finishing unknown 256-bit keys.

### 5.13 Console

Clear / Copy all. Primary feedback for load, salvage, cracks, orchestrator, experiments.

### 5.14 Lab Docs

In-app: experiment help, recommended workflow, hibernation/RAM guidance (**import only**, authorized), secure-erase reminder.

---

## 6. wallet.dat — extract, salvage, verify

### 6.1 Healthy path

1. Extract → Open / drop `.dat`.  
2. Confirm Magic OK, readable mkey (method, iters, salt, 96-hex enc), ckeys.  
3. Read archaeology; then **Verify** for an explicit verdict.  
4. Export JSON/TXT into case `results\`.

### 6.2 Damaged path

1. Salvage and/or Breaker Carve.  
2. Review heatmap / ranked ckeys / carve summary.  
3. Promote coherent mkey fields into Passphrase Lab / Hashcat export.

### 6.3 Integrity checklist

| Check | Expectation |
|-------|-------------|
| Size | Non-trivial |
| Magic | OK for BDB; BAD → salvage / wrong file |
| mkey enc | 96 hex (48 bytes) typical |
| salt / iters | Present; high iters → slower KDF |
| ckey enc | 96 hex typical |
| pubkey | 33 or 65 bytes hex typical |
| Dual-verify | Must pass before operational use |

---

## 7. Passphrase, Hashcat, John, BTCRecover, dual-verify

### 7.1 Passphrase Lab first

Best when you remember fragments. Recall → Generate → Measure H/s → batch. Or let Breaker **Native KDF** consume the same candidates.

### 7.2 Hashcat / John

1. Write hash from Hashcat Bridge (or `--export-hashcat`).  
2. `setup_forensics.bat` if spawning locally.  
3. Stream from GUI **or**:

```bat
third_party\run_hashcat.bat -m 11300 -a 0 wallet_hash.txt wordlist.txt
third_party\run_john.bat --format=bitcoin wallet_hash.txt
```

4. Paste cracked password into Passphrase Lab **Try single** to dual-verify.

### 7.3 BTCRecover

Use for tokenlists, typos, Electrum/BIP39 **when the wallet format matches**. Do not expect BIP39 recovery from classic Core-only files.

### 7.4 Dual-verify

Success decrypts mkey/ckey material and, when possible, checks recovered private key against stored **pubkey** (micro-ecc secp256k1). Prefer `pubkey_match` over PKCS-only.

---

## 8. AES partial / CUDA / FOUND_WALLET

| Scenario | Tab | Mode |
|----------|-----|------|
| Known prefix from dump | AES Partial | `MODE_PARTIAL` |
| Cold-boot full keys | AES Partial | Try all |
| Constrained research window | CUDA Crack | Mixed / sequential |
| Random rate experiment | CUDA Crack | Random (will not finish 2^256) |

On HIT: key + WIF in CUDA panel; `FOUND_WALLET.txt`; dual-verify when pubkeys present. Wipe via Results after case close.

---

## 9. CLI flags reference

| Flag | Action |
|------|--------|
| *(no args)* | Launch Forensic Suite GUI |
| `-h` / `--help` | Usage |
| `--tools-status` | Print Hashcat / Python / BTCRecover / John detection |
| `--verify FILE\|$bitcoin$…` | REAL/SUSPECT/FAKE/CORRUPT report |
| `--parse FILE` | TXT/JSON exports + optional `wallet_hashcat.txt` |
| `--export-hashcat FILE` | Print `$bitcoin$` (`-m 11300`) |
| `--salvage FILE` | Carve reports `.salvage.txt` / `.json` |
| `--selftest` | GPU+host PoC; then passphrase + secp experiments (`-d N`, `--found FILE`) |
| `--experiment NAME` | `help` \| `dual_fp` \| `passphrase` \| `secp` \| `hashcat_fmt` |
| `--partial-help` | Document partial AES GPU mode |
| `--no-gui` | Prints usage (placeholder) |

Exit codes: success typically `0`; parse/salvage may return `2` with no useful material; `--verify` uses verdict codes above; `--tools-status` may return `2` if both Hashcat and BTCRecover missing.

---

## 10. End-to-end scenarios

### A. Forgotten passphrase (healthy wallet.dat)

1. Extract → load → note iterations.  
2. Verify → expect REAL/SUSPECT (document).  
3. Breaker Break (Native KDF + optional Hashcat/John) **or** Passphrase Lab recall batch.  
4. On hit → Rebuild (new passphrase) and/or Results `decrypt_all_ckeys` → offline → wipe.

### B. Corrupt / truncated wallet

1. Salvage + Carve; export ranked candidates.  
2. If mkey + salt/iters complete → passphrase / hashcat.  
3. If only fragments → locate a better disk image; document gaps in Case notes.

### C. Partial AES / cold-boot

1. Extract or salvage so targets exist.  
2. AES Partial prefix **or** paste 64-hex keys → Try all.  
3. Hit → Results / Rebuild. Do not claim “we break unknown AES-256.”

### D. Multi-wallet triage

1. Extract folder scan **or** Tools → Triage (low iters first).  
2. Verify each candidate; Case-note priority.  
3. Attack weakest plausible first (low iters / known fragments).

---

## 11. Troubleshooting

| Symptom | Checks |
|---------|--------|
| No CUDA devices | Driver/GPU; CPU workflows still usable |
| Magic BAD | Wrong file or Salvage/Carve |
| Passphrase Lab disabled | Need structured mkey |
| Hashcat/John/BTCRecover missing | `setup_forensics.bat` or place binaries; `--tools-status` |
| Spawn fails | Paths, AV blocking CreateProcess, missing wordlist |
| BIP39 NOT PRESENT | Normal for classic Core — not a bug |
| PKCS OK, pubkey fail | False positive — do not move funds |
| Slow native batch | High `nDeriveIterations`; use Hashcat GPU for huge lists |
| Drop `.dat` ignored | Extension must be `.dat` |
| Rebuild write fail | Invalid master hex or export path permissions |

Build issues: `build_cuda.bat` messages for missing `vcvars64` / CUDA Toolkit.

---

## 12. Limits / honesty (read before promising results)

1. **Passphrase / KDF recovery** is the primary practical path for encrypted Core wallets.  
2. **Partial AES** is valid only with constrained unknown bytes (prefix / candidates).  
3. **Random CUDA search** demonstrates capability — it does not finish unknown 256-bit keys.  
4. **Hashcat Bridge / John / BTCRecover** are process bridges after `setup_forensics.bat`.  
5. **Classic Core wallet.dat usually has no BIP39 seed** — Carve says so; do not market seed miracles.  
6. **Rebuild** rematerializes owner keys under a new passphrase / WIF export — never ships fake balances.  
7. Hibernation / pagefile work is **guidance + import** of user-supplied material only.  
8. SIMD status advertises CPU capability for native KDF — not a new cryptographic break.

---

## 13. Related docs

| Doc | Content |
|-----|---------|
| [QUICKSTART.md](QUICKSTART.md) | One-page start |
| [RECOVERY_RESEARCH.md](RECOVERY_RESEARCH.md) | Implanted features & dead ends |
| [HIBERNATION_FORENSICS.md](HIBERNATION_FORENSICS.md) | Authorized cold-boot / hibernation notes |
| [FORMAT.md](FORMAT.md) | mkey/ckey layout, WIF pipeline |
| [CUDA.md](CUDA.md) | CUDA build / kernel notes |
| [../THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) | Third-party licenses |
| [../README.md](../README.md) | Product README |

---

*Made by TrueScent — TrueWalletCollider Forensic Suite. https://t.me/TrueScent — Authorized recovery only.*
