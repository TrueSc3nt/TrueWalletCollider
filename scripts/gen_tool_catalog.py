#!/usr/bin/env python3
"""Generate ToolCatalogData.inc + catalog stats from the Huge DFIR research list."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
entries: list[dict] = []


def add(
    eid,
    name,
    cat,
    kind,
    desc,
    url="",
    detect="",
    setup_key="",
    native_action="",
    notes="",
):
    entries.append(
        {
            "id": eid,
            "name": name,
            "category": cat,
            "kind": kind,
            "description": desc,
            "docs_url": url,
            "detect_hint": detect,
            "setup_key": setup_key,
            "native_action": native_action,
            "notes": notes,
        }
    )


# === NATIVE first-party ===
add("twc_extract", "TrueWalletCollider Extract", "Native", "native", "Parse wallet.dat BDB mkey/ckey + archaeology", native_action="extract")
add("twc_salvage", "Salvage Carver", "Native", "native", "Carve mkey/ckey from damaged dumps", native_action="salvage")
add("twc_passlab", "Passphrase Lab KDF", "Native", "native", "Method-0 EVP_BytesToKey SHA-512 dict/mask/recall", native_action="passlab")
add("twc_aes_partial", "CUDA AES Partial", "Native", "native", "GPU prefix/suffix AES master search", native_action="aes_partial")
add("twc_breaker", "Breaker & Rebuild Lab", "Native", "native", "Orchestrate crack paths + re-encrypt under new passphrase", native_action="breaker")
add("twc_outside", "Outside Box (23 modules)", "Native", "native", "VSS ghosts leftovers memory Two-Body Seed Mirage etc.", native_action="outside")
add("twc_verify", "Authenticity Verify", "Native", "native", "REAL/SUSPECT/FAKE/CORRUPT checklist", native_action="verify")
add("twc_case", "Case Manager", "Native", "native", "Evidence notes zip under cases/", native_action="case")
add("twc_bip39", "BIP39 Validator", "Native", "native", "Checksum validate 12-24 English mnemonics", native_action="bip39")
add("twc_brain", "Brainwallet SHA256", "Native", "native", "Passphrase SHA256 to WIF", native_action="brain")
add("twc_seed_mirage", "Seed Mirage Meter", "Native", "native", "Rank carved BIP39 vs wallet addresses", native_action="seed_mirage")
add("twc_csv_bridge", "Password Manager CSV Bridge", "Native", "native", "Chrome/Bitwarden/KeePass CSV to wordlist", native_action="csv_bridge")
add("twc_metamask_pipe", "MetaMask LevelDB Vault Pipe", "Native", "native", "Walk extension LevelDB dump vault JSON hash export hints", native_action="metamask")
add("twc_exodus_pipe", "Exodus SECO Intake", "Native", "native", "Locate seed.seco prepare Hashcat 28200 via exodus2hashcat", native_action="exodus")
add("twc_electrum_help", "Electrum Helper", "Native", "native", "Detect Electrum wallet files tip Hashcat 16600/21700/21800", native_action="electrum")
add("twc_mbox", "Email/Mbox Seed Scavenger", "Native", "native", "Scan mbox/eml/txt for BIP39 word runs", native_action="mbox")
add("twc_ocr_intake", "BIP39 OCR Text Intake", "Native", "native", "Validate OCR transcription files against BIP39 wordlist", native_action="ocr_intake")
add("twc_ext_walker", "Browser Extension Walker", "Native", "native", "Inventory MetaMask/Rabby/Phantom/Ronin LevelDB paths", native_action="ext_walker")
add("twc_sqlite_core", "SQLite Core Wallet Parse", "Native", "native", "Heuristic scan Core SQLite wallet for mkey/ckey strings", native_action="sqlite_core")
add("twc_memscan", "Volatility-style Dump Scan", "Native", "native", "User-supplied dump string/hex/BIP39 scavenger (no silent RAM)", native_action="memscan")
add("twc_addressdb", "AddressDB Builder Hook", "Native", "native", "Prep BTCRecover Address Database build folder + script", native_action="addressdb")
add("twc_hashcat_exp", "Hashcat Export -m 11300", "Native", "native", "Native bitcoin2john-style $bitcoin$ export", native_action="hash_export")

# === CRACKERS / SETUP ===
add("hashcat", "Hashcat", "Crackers", "setup", "GPU hash cracker modes 11300/Electrum/MetaMask/Exodus/ETH", "https://hashcat.net/hashcat/", "third_party/hashcat/hashcat.exe", "hashcat")
add("john", "John the Ripper Jumbo", "Crackers", "setup", "Rules + bitcoin2john + MPI", "https://www.openwall.com/john/", "third_party/john/run/john.exe", "john")
add("btcrecover", "BTCRecover (3rdIteration)", "Crackers", "setup", "Password+partial seed; extract scripts; OpenCL", "https://github.com/3rdIteration/btcrecover", "third_party/btcrecover/btcrecover.py", "btcrecover")
add("btcrecover_legacy", "gurnec/btcrecover (legacy)", "Crackers", "idea", "Original lineage — prefer 3rdIteration", "https://github.com/gurnec/btcrecover")
add("bitcoin2john", "bitcoin2john.py", "Crackers", "setup", "wallet.dat to $bitcoin$ (BDB+SQLite)", "https://github.com/openwall/john", "third_party/john/run/bitcoin2john.py", "john")
add("python_embed", "Embeddable Python 3.12", "Crackers", "setup", "Runtime for BTCRecover and Python extractors", "https://www.python.org/", "third_party/python/python.exe", "python")
add("pywallet", "pywallet", "Carvers", "setup", "Dump/recover corrupt wallet.dat raw disk --recover", "https://github.com/jackjack-jj/pywallet", "third_party/pywallet/pywallet.py", "pywallet")
add("pywallet_gsc", "Great-Software-Company pywallet", "Carvers", "setup", "Fork with auto-detect improvements", "https://github.com/Great-Software-Company/pywallet", "third_party/pywallet-gsc", "pywallet_gsc")
add("walletforge", "WalletForge", "Carvers", "experimental", "BDB page parse DER/mkey carve hashcat export", "https://github.com/morningstarnasser/WalletForge", "third_party/WalletForge", "walletforge")
add("ubwr", "Universal Bitcoin Wallet Reader", "Carvers", "experimental", "C++ BDB parse mkey/ckey keymeta export", "https://github.com/bekli23/Universal-Bitcoin-Wallet-Reader-Forensic-Tool-", "third_party/ubwr", "ubwr")
add("bitcoincarver", "BitcoinCarver", "Carvers", "experimental", "PhysicalDrive scan mkey/ckey Hashcat hashes", "https://github.com/Haniamin90/BitcoinCarver", "third_party/BitcoinCarver", "bitcoincarver")
add("keyelf", "key-elf", "Carvers", "experimental", "ASN.1 DER carve on raw media", "https://sourceforge.net/projects/key-elf/", "third_party/key-elf", "keyelf")
add("btc_recovery_skeptical", "btc_recovery (audit-needed)", "Crackers", "idea", "Multi-format claims — treat skeptical until audited", "https://github.com/vishwamartur/btc_recovery")
add("seedcat", "seedcat", "SeedGPU", "experimental", "Fast GPU BIP39 vs address/xpub wildcards", "https://github.com/seed-cat/seedcat", "third_party/seedcat", "seedcat")
add("hydra_cuda", "Hydra (Julienbxl)", "SeedGPU", "experimental", "CUDA BIP39 Electrum WIF BSGS bloom", "https://github.com/Julienbxl/Hydra", "third_party/Hydra", "hydra")
add("cuda_mnemonic", "CUDA_Mnemonic_Recovery", "SeedGPU", "experimental", "Multi-GPU BIP39 multi-coin Bloom/XOR", "https://github.com/XopMC/CUDA_Mnemonic_Recovery", "third_party/CUDA_Mnemonic_Recovery", "cuda_mnemonic")
add("wrecover", "wrecover", "SeedGPU", "idea", "Commercial GPU seed narrative — evaluate license")
add("bip39_brute", "bip39-brute WebGPU", "SeedGPU", "experimental", "Browser WebGPU BIP39/partial", "https://github.com/georg95/bip39-brute", "third_party/bip39-brute", "bip39_brute")
add("electrum_crack", "bitcoin_electrum_cracking", "SeedGPU", "experimental", "Electrum HMAC prefilter + PBKDF2 research", "https://github.com/ipsbruno3/bitcoin_electrum_cracking", "third_party/bitcoin_electrum_cracking", "electrum_crack")
add("metamask_pwn", "metamask_pwn", "Browser", "setup", "Extract vault JSON decryptor seed print", "https://github.com/cyclone-github/metamask_pwn", "third_party/metamask_pwn", "metamask_pwn")
add("hashcat_26620", "hashcat_26620_kernel", "Browser", "setup", "Dynamic-iter MetaMask PBKDF2 kernel", "https://github.com/cyclone-github/hashcat_26620_kernel", "third_party/hashcat_26620_kernel", "hashcat_26620")
add("mm_leveldb", "metamask-leveldb-forensic-tools", "Browser", "setup", "LevelDB to vault to Hashcat/BTCRecover", "https://github.com/alibabahalalmeat/metamask-leveldb-forensic-tools", "third_party/metamask-leveldb-forensic-tools", "mm_leveldb")
add("exodus2hashcat", "exodus2hashcat.py", "Browser", "setup", "Exodus seed.seco to mode 28200", "https://hashcat.net/hashcat/", "third_party/hashcat/tools/exodus2hashcat.py", "hashcat")
add("exodus_seco_dict", "Exodus-Seco-To-Passphrase", "Browser", "experimental", "Dictionary attack .seco", "https://github.com/KaratelSH/Exodus-Seco-To-Passphrase", "third_party/Exodus-Seco-To-Passphrase", "exodus_seco")
add("seed_sweep", "seed-sweep / SeedSweep", "OCREmail", "setup", "FS scan + Tesseract OCR BIP39", "https://github.com/freeide/seed-sweep", "third_party/seed-sweep", "seed_sweep")
add("img_seed_finder", "Image-Seed-Phrase-Finder", "OCREmail", "setup", "Batch OCR BIP39 validation", "https://github.com/Lahwom/Image-Seed-Phrase-Finder", "third_party/Image-Seed-Phrase-Finder", "img_seed")
add("seed_parser", "seed_parser", "OCREmail", "setup", "Multithreaded FS BIP39/privkey scan", "https://github.com/xironix/seed_parser", "third_party/seed_parser", "seed_parser")
add("seed_scanner", "seed-phrase-scanner", "OCREmail", "setup", "Multi-format / Discord export scanners", "https://github.com/Arien10/seed-phrase-scanner", "third_party/seed-phrase-scanner", "seed_scanner")
add("bip39_raw_engine", "BIP39RecoveryTool raw sector", "Carvers", "experimental", "Raw sector BIP39 sliding window + checksum", "https://github.com/mmediasoftwarelab/BIP39RecoveryTool-public", "third_party/BIP39RecoveryTool-public", "bip39_raw")
add("bulk_extractor", "bulk_extractor", "Carvers", "setup", "Byte-level feature extract bitcoin scanners", "https://github.com/simsong/bulk_extractor", "third_party/bulk_extractor", "bulk_extractor")
add("hdd_recovery", "hdd-recovery pipeline", "Carvers", "idea", "Orchestrates ddrescue TSK PhotoRec bulk_extractor pywallet", "https://github.com/joanmarcriera/hdd-recovery")
add("sleuthkit", "The Sleuth Kit", "DiskVSS", "setup", "FS analysis deleted recovery", "https://www.sleuthkit.org/", "third_party/sleuthkit", "sleuthkit")
add("autopsy", "Autopsy", "DiskVSS", "bridge", "GUI DFIR; iLEAPP/aLEAPP ingest", "https://www.sleuthkit.org/autopsy/")
add("autopsy_plugins", "Autopsy-Plugins (McKinnon)", "DiskVSS", "setup", "Atomic Wallet LevelDB VSS Volatility plugins", "https://github.com/markmckinnon/Autopsy-Plugins", "third_party/Autopsy-Plugins", "autopsy_plugins")
add("ileapp", "iLEAPP", "Mobile", "setup", "iOS artifact parse", "https://github.com/abrignoni/iLEAPP", "third_party/iLEAPP", "ileapp")
add("aleapp", "aLEAPP", "Mobile", "setup", "Android artifact parse", "https://github.com/abrignoni/ALEAPP", "third_party/aLEAPP", "aleapp")
add("vol3", "Volatility 3", "Memory", "setup", "Memory dumps windows.memmap strings", "https://github.com/volatilityfoundation/volatility3", "third_party/volatility3", "vol3")
add("blockbusters", "BlockBusters Vol plugins", "Memory", "experimental", "Experimental Vol plugins Python GC key hunt", "https://github.com/joezbub/blockchain-forensics", "third_party/blockchain-forensics", "blockbusters")
add("vshadow_rs", "vshadow-rs", "DiskVSS", "experimental", "Cross-platform VSS from E01/raw", "https://github.com/jupyterj0nes/vshadow-rs", "third_party/vshadow-rs", "vshadow_rs")
add("vscexplorer", "VSCExplorer", "DiskVSS", "experimental", "GUI VSS on E01 + BitLocker", "https://github.com/ph1nx/Volume-Shadow-Copy-Explorer", "third_party/VSCExplorer", "vscexplorer")
add("libvshadow", "libvshadow / vshadowmount", "DiskVSS", "experimental", "Classic VSS mount (libyal)", "https://github.com/libyal/libvshadow", "third_party/libvshadow", "libvshadow")
add("photorec", "PhotoRec / TestDisk", "Carvers", "setup", "Carving / partition repair portable", "https://www.cgsecurity.org/", "third_party/testdisk", "photorec")
add("foremost", "foremost / scalpel", "Carvers", "idea", "Signature carve classics")
add("plaso", "Plaso / log2timeline", "DiskVSS", "setup", "Super timeline", "https://github.com/log2timeline/plaso", "third_party/plaso", "plaso")
add("kape", "KAPE", "DiskVSS", "bridge", "Targeted Windows artifact collection (Kroll)", "https://www.kroll.com/")
add("rekall", "Rekall (archived)", "Memory", "idea", "Legacy memory — prefer Volatility3")
add("ian_coleman", "Ian Coleman BIP39", "Research", "bridge", "Offline derivation reference not a cracker", "https://github.com/iancoleman/bip39")
add("walletsrecovery", "walletsrecovery.org", "Research", "bridge", "Derivation path encyclopedia", "https://walletsrecovery.org/")

COMMERCIAL = [
    ("cellebrite", "Cellebrite UFED/PA/Crypto Analyzer", "Parses wallet apps/addresses — not Core AES crack", "https://cellebrite.com/"),
    ("magnet_axiom", "Magnet AXIOM", "Cross-source artifacts cloud linkage", "https://www.magnetforensics.com/"),
    ("magnet_graykey", "Magnet Graykey + TRM BLOCKINT", "Mobile Crypto Triage — on-chain intel not crack", "https://www.magnetforensics.com/"),
    ("belkasoft", "Belkasoft X", "Disk/mobile/cloud/memory unified", "https://belkasoft.com/"),
    ("msab", "MSAB XRY", "Mobile extraction", "https://www.msab.com/"),
    ("oxygen", "Oxygen Forensic Detective", "Cloud + WhatsApp backup decrypt paths", "https://www.oxygen-forensic.com/"),
    ("xways", "X-Ways Forensics", "Deep disk/VSS carving excellence", "https://www.x-ways.net/"),
    ("encase", "OpenText EnCase", "Classic imaging and review", "https://www.opentext.com/"),
    ("ftk", "Exterro FTK", "Classic imaging and review", "https://www.exterro.com/"),
    ("getdata", "GetData Forensic", "Imaging / review suite", "https://www.getdata.com/"),
    ("passware", "Passware Kit", "Bitcoin Core v20+ recovery commercial GPU", "https://www.passware.com/"),
    ("elcomsoft_edpr", "Elcomsoft EDPR", "Distributed Bitcoin Core / Electrum GPU farms", "https://www.elcomsoft.com/"),
    ("elcomsoft_eift", "Elcomsoft iOS Forensic Toolkit", "Device access pathways to apps", "https://www.elcomsoft.com/"),
    ("gmdsoft", "GMDSOFT", "Advanced mobile forensics", "https://www.gmdsoft.com/"),
    ("recovery_cat", "Recovery CAT", "Proprietary email/OCR/browser seed class", ""),
]
for eid, name, desc, url in COMMERCIAL:
    add(
        eid,
        name,
        "CommercialLE",
        "commercial",
        desc,
        url,
        notes="Install separately — Integration Hub detects configured path. Never pirate. TWC covers local hash extract/crack for Core/vaults when possible.",
    )

ONCHAIN = [
    ("chainalysis", "Chainalysis Reactor / Wallet Scan", "Post-recovery labeling — not local AES", "https://www.chainalysis.com/"),
    ("elliptic", "Elliptic", "On-chain attribution", "https://www.elliptic.co/"),
    ("trm", "TRM Labs", "On-chain risk / attribution", "https://www.trmlabs.com/"),
    ("crystal", "Crystal Blockchain", "On-chain attribution", "https://crystalblockchain.com/"),
    ("maltego", "Maltego + blockchain transforms", "OSINT graphing", "https://www.maltego.com/"),
]
for eid, name, desc, url in ONCHAIN:
    add(eid, name, "OnChain", "commercial", desc, url, notes="On-chain labeling ONLY after addresses/keys exist. Not a cracker.")

add("ophcrack", "ophcrack", "Password", "idea", "Windows LM/NT peripheral then wallet files")
add("hc_rules", "Hashcat rules (dive/best64/Hob0)", "Password", "setup", "Rule files with Hashcat bundle", "https://hashcat.net/wiki/", "third_party/hashcat/rules", "hashcat")
add("pack", "PACK", "Password", "experimental", "Password Analysis and Cracking Kit", detect="third_party/PACK", setup_key="pack")
add("cupp", "CUPP", "Password", "setup", "Profile-driven wordlists", "https://github.com/Mebus/cupp", "third_party/cupp", "cupp")
add("mentalist", "mentalist", "Password", "experimental", "GUI wordlist generator", detect="third_party/mentalist", setup_key="mentalist")
add("kwprocessor", "Kwprocessor", "Password", "setup", "Keyboard-walk combinator", "https://github.com/hashcat/kwprocessor", "third_party/kwprocessor", "kwprocessor")
add("prince", "princeprocessor", "Password", "setup", "PRINCE combinator attack", "https://github.com/hashcat/princeprocessor", "third_party/princeprocessor", "prince")
add("cewl", "CeWL", "Password", "setup", "Custom PII harvest from sites/exports", "https://github.com/digininja/CeWL", "third_party/CeWL", "cewl")
add("passllm", "PassLLM / PassGPT wordlists", "Password", "idea", "Academic password models feed Hashcat -a 0 NEVER seed entropy")
add("onlinehashcrack", "OnlineHashCrack", "Password", "idea", "Outsourced GPU — usually avoid for real seeds")

add("ftk_imager", "FTK Imager", "Imaging", "bridge", "Acquisition")
add("guymager", "Guymager", "Imaging", "idea", "Linux acquisition")
add("ddrescue", "ddrescue", "Imaging", "bridge", "Bad-sector imaging")
add("dc3dd", "dc3dd", "Imaging", "idea", "Forensic imaging")
add("shadowexplorer", "ShadowExplorer", "DiskVSS", "bridge", "Live VSS GUI", "https://www.shadowexplorer.com/")

qf = [
    ("qf_extract_bcmkey", "BTCRecover extract-bitcoincore-mkey", "Crackers"),
    ("qf_seedrecover", "BTCRecover seedrecover", "SeedGPU"),
    ("qf_pywallet_dump", "pywallet --dumpwallet", "Carvers"),
    ("qf_pywallet_recover", "pywallet --recover", "Carvers"),
    ("qf_photorec_sig", "PhotoRec custom wallet.dat signature", "Carvers"),
    ("qf_testdisk", "TestDisk partition revive", "DiskVSS"),
    ("qf_tsk_blkls", "Sleuth Kit blkls unallocated scan", "DiskVSS"),
    ("qf_autopsy_atomic", "Autopsy Atomic_Wallet plugin", "DiskVSS"),
    ("qf_autopsy_leveldb", "Autopsy LevelDB parser plugin", "DiskVSS"),
    ("qf_kape_btc", "KAPE targets Bitcoin Electrum Chrome Ext", "DiskVSS"),
    ("qf_plaso_wallet", "Plaso timeline wallet.dat write", "DiskVSS"),
    ("qf_vol_pslist", "Volatility3 windows.pslist", "Memory"),
    ("qf_vol_memmap", "Volatility3 windows.memmap --dump", "Memory"),
    ("qf_vol_yara", "Volatility strings + BIP39 YARA", "Memory"),
    ("qf_hxd", "HxD process memory", "Memory"),
    ("qf_prochack", "Process Hacker / Sysinternals dump", "Memory"),
    ("qf_thunderbird", "Thunderbird maildir BIP39 regex", "OCREmail"),
    ("qf_gmail_mbox", "Gmail Takeout mbox scraper", "OCREmail"),
    ("qf_pst", "Outlook PST libpff + seed scan", "OCREmail"),
    ("qf_whatsapp_ocr", "WhatsApp export OCR seed photos", "OCREmail"),
    ("qf_keepass2john", "KeePass2john", "Password"),
    ("qf_bitwarden", "bitwarden/vaultwarden hash paths", "Password"),
    ("qf_1password", "1Password OPVault extractors", "Password"),
    ("qf_credman", "Windows Credential Manager (authorized)", "Password"),
    ("qf_chrome_login", "Chrome Login Data mutate to wallet passwords", "Password"),
    ("qf_firefox_key4", "Firefox key4.db", "Password"),
    ("qf_bitlocker", "BitLocker recovery then VSS", "DiskVSS"),
    ("qf_veracrypt", "VeraCrypt container then wallets", "DiskVSS"),
    ("qf_truecrypt", "TrueCrypt legacy containers", "DiskVSS"),
    ("qf_filevault", "Mac FileVault wallet paths", "DiskVSS"),
    ("qf_timemachine", "Time Machine local snapshots", "DiskVSS"),
    ("qf_apfs", "APFS snapshots", "DiskVSS"),
    ("qf_drivefs", "Google DriveFS hydrate", "DiskVSS"),
    ("qf_onedrive", "OneDrive NTFS reparse hydrate", "DiskVSS"),
    ("qf_icloud_photos", "iCloud Photo Library seed screenshots", "OCREmail"),
    ("qf_recycle", "Recycle Bin wallet.dat", "DiskVSS"),
    ("qf_prefetch", "Prefetch/Amcache Electrum ran", "DiskVSS"),
    ("qf_jumplists", "Jumplists recent wallet paths", "DiskVSS"),
    ("qf_shellbags", "Shellbags AppData Bitcoin", "DiskVSS"),
    ("qf_usn", "NTFS USN Journal wallet.dat", "DiskVSS"),
    ("qf_sqlite_wal", "SQLite WAL/journal Core wallets", "Carvers"),
    ("qf_leveldb_manifest", "LevelDB MANIFEST/CURRENT recovery", "Browser"),
    ("qf_snappy", "Snappy decompress LevelDB blocks", "Browser"),
    ("qf_idb_exodus", "IndexedDB Exodus extension", "Browser"),
    ("qf_brave_edge", "Brave/Edge Chromium extension IDs", "Browser"),
    ("qf_safari_ext", "Safari WebExtension storage", "Browser"),
    ("qf_asar", "Electron asar Exodus/Atomic", "Browser"),
    ("qf_coinomi", "Coinomi backup password BTCRecover", "Mobile"),
    ("qf_blockchain18800", "Blockchain.com mode 18800", "Crackers"),
    ("qf_dogechain", "Dogechain / MultiDoge extract", "Crackers"),
    ("qf_bip38", "BIP38 paper wallet attack queue", "Crackers"),
    ("qf_bip39_25", "BIP39 25th-word passphrase GPU", "SeedGPU"),
    ("qf_slip39", "SLIP39 threshold recovery", "SeedGPU"),
    ("qf_electrum_extra", "Electrum extra words", "SeedGPU"),
    ("qf_anagram", "Descramble 12-word anagram tokenlist", "SeedGPU"),
    ("qf_typo_kbd", "Typo keyboard-adjacency password rules", "Password"),
    ("qf_cewl_social", "CeWL on owner blog/social exports", "Password"),
    ("qf_prince_pw", "Prince attack predictable passphrases", "Password"),
    ("qf_hc_combinator", "Hashcat combinator word1 word2", "Password"),
    ("qf_hc_mask", "Mask attack remembered pattern", "Password"),
    ("qf_tokenlist", "BTCRecover tokenlist likely pieces", "Crackers"),
    ("qf_addr_bloom", "Address bloom from explorer CSV", "SeedGPU"),
    ("qf_xpub_first", "Xpub-first recovery seedcat", "SeedGPU"),
    ("qf_multi_path", "Multi-derivation BIP44/49/84/86", "SeedGPU"),
    ("qf_taproot", "Taproot path awareness", "SeedGPU"),
    ("qf_sol_path", "Solana path CUDA_Mnemonic", "SeedGPU"),
    ("qf_ton_path", "TON path CUDA_Mnemonic", "SeedGPU"),
    ("qf_sweep_new", "Post-recovery sweep to new wallet", "Research"),
    ("qf_airgap", "Air-gap checklist UI", "Native"),
    ("qf_hash_only", "Hash-only trustless cloud-crack extract", "Crackers"),
    ("qf_hiber_bip39", "Hibernation carved BIP39", "Memory"),
    ("qf_pagefile", "swapfile / pagefile.sys", "Memory"),
    ("qf_vmem", "VMware .vmem / VirtualBox .sav", "Memory"),
    ("qf_docker", "Docker volume leftover wallets", "DiskVSS"),
    ("qf_wsl", "WSL ext4.vhdx Linux Electrum", "DiskVSS"),
    ("qf_adb", "Android adb backup residual", "Mobile"),
    ("qf_mmkv", "MMKV Phantom/Trust parse", "Mobile"),
    ("qf_rctasync", "RCTAsyncLocalStorage Exodus iOS", "Mobile"),
    ("qf_shared_prefs", "shared_prefs XML Trust/BlueWallet", "Mobile"),
    ("qf_android_ks", "Android Keystore limitations honesty", "Mobile"),
    ("qf_ios_keychain", "iOS Keychain specialized ops", "Mobile"),
    ("qf_qr_seed", "QR seed photo ZXing decode", "OCREmail"),
    ("qf_steel_ocr", "Steel plate OCR preprocessing", "OCREmail"),
    ("qf_levenshtein", "Damaged mnemonic Levenshtein corrector", "SeedGPU"),
    ("qf_multi_lang", "Multilingual BIP39 lists", "SeedGPU"),
    ("qf_shamir", "Shamir Soft share reconstruction", "SeedGPU"),
    ("qf_multisig", "Multisig descriptor recovery", "Native"),
    ("qf_specter", "Specter / Sparrow wallet formats", "Crackers"),
    ("qf_wasabi", "Wasabi wallet file password", "Crackers"),
    ("qf_samourai", "Samourai/Ashigaru vault research", "Mobile"),
    ("qf_phoenix", "Phoenix/Mutiny LN seeds", "Mobile"),
    ("qf_bluewallet", "BlueWallet SQLite artifacts", "Mobile"),
    ("qf_mycelium", "Mycelium external storage backups", "Mobile"),
    ("qf_trezor_logs", "KeepKey/Trezor Suite logs metadata", "Research"),
    ("qf_m_media", "M Media BIP39 commercial (OSS engine)", "SeedGPU"),
    ("qf_gmu_cina", "GMU CINA mobile wallet path dictionary", "Mobile"),
    ("qf_stealer_glue", "Stealer-log password glue to wallet.dat", "Password"),
    ("qf_entropy_ui", "Entropy remaining honesty calculator", "Native"),
    ("qf_local_vs_chain", "Local recovery vs on-chain UX distinction", "Native"),
    ("qf_hc_eth", "Hashcat ETH keystore 15600/15700/16300", "Crackers"),
    ("qf_hc_mm", "Hashcat MetaMask 26600/26620", "Browser"),
    ("qf_hc_exodus", "Hashcat Exodus 28200", "Browser"),
    ("qf_hc_electrum", "Hashcat Electrum 16600/21700/21800", "Crackers"),
    ("qf_hc_bc", "Hashcat Blockchain.com 12700/15200/18800", "Crackers"),
]
for eid, name, cat in qf:
    add(
        eid,
        name,
        cat,
        "idea",
        "Research catalog quickfire — " + name + ". May map to native/setup/bridge peers above.",
        notes="Listed so nothing from the DFIR research dump is omitted from the Tool Bay.",
    )

TOP25 = [
    "TOP25: MetaMask LevelDB to 26620",
    "TOP25: Exodus seco to 28200",
    "TOP25: BitcoinCarver/key-elf/pywallet recover",
    "TOP25: Volatility3 wallet presets",
    "TOP25: seedcat or Hydra partial BIP39",
    "TOP25: CUDA_Mnemonic multi-GPU UI",
    "TOP25: Electrum HMAC prefilter",
    "TOP25: OCR paper/screenshot seeds",
    "TOP25: Email scavenger Thunderbird/mbox/PST",
    "TOP25: bulk_extractor Bitcoin scanners",
    "TOP25: Passware/EDPR parity harness",
    "TOP25: aLEAPP/iLEAPP + GMU paths",
    "TOP25: vshadow-rs AppData Bitcoin delta",
    "TOP25: KeePass/Bitwarden extract expand",
    "TOP25: LevelDB multi-extension walker",
    "TOP25: Address Database generator",
    "TOP25: SLIP39 share recovery UX",
    "TOP25: Blockchain.com dual-password automation",
    "TOP25: Ethereum UTC keystore ingestion",
    "TOP25: BIP38 specialized runner",
    "TOP25: PassLLM distilled wordlist pipe",
    "TOP25: Pagefile/hiberfil BIP39 carve",
    "TOP25: Cloud sync DB parsers",
    "TOP25: Autopsy ingest plugin for TWC",
    "TOP25: Post-unlock optional balance check",
]
for i, name in enumerate(TOP25, 1):
    add(
        f"top{i:02d}",
        name,
        "Research",
        "idea",
        f"Priority integration from research Top 25 #{i}",
        notes="Tracked in Universal Tool Bay so Top 25 are never docs-only.",
    )


def cpp_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def kind_enum(k: str) -> str:
    return {
        "native": "ToolKind::Native",
        "setup": "ToolKind::SetupFetch",
        "bridge": "ToolKind::Bridge",
        "commercial": "ToolKind::Commercial",
        "experimental": "ToolKind::Experimental",
        "idea": "ToolKind::Idea",
    }[k]


def cat_enum(c: str) -> str:
    return {
        "Native": "ToolCategory::Native",
        "Crackers": "ToolCategory::Crackers",
        "Carvers": "ToolCategory::Carvers",
        "SeedGPU": "ToolCategory::SeedGPU",
        "Browser": "ToolCategory::Browser",
        "Mobile": "ToolCategory::Mobile",
        "Memory": "ToolCategory::Memory",
        "DiskVSS": "ToolCategory::DiskVSS",
        "OCREmail": "ToolCategory::OCREmail",
        "Password": "ToolCategory::Password",
        "CommercialLE": "ToolCategory::CommercialLE",
        "OnChain": "ToolCategory::OnChain",
        "Research": "ToolCategory::Research",
        "Imaging": "ToolCategory::Imaging",
    }[c]


def main():
    out_json = ROOT / "scripts" / "_catalog_entries.json"
    out_inc = ROOT / "src" / "wallet" / "ToolCatalogData.inc"
    out_json.write_text(json.dumps(entries, indent=1), encoding="utf-8")

    lines = [
        "// Auto-generated by scripts/gen_tool_catalog.py — do not edit by hand.",
        f"// Catalog entry count: {len(entries)}",
        "static void tool_catalog_fill(std::vector<CatalogEntry>& out) {",
        "  out.clear();",
        f"  out.reserve({len(entries)});",
    ]
    for e in entries:
        lines.append("  {")
        lines.append("    CatalogEntry e;")
        lines.append(f'    e.id = "{cpp_escape(e["id"])}";')
        lines.append(f'    e.name = "{cpp_escape(e["name"])}";')
        lines.append(f"    e.category = {cat_enum(e['category'])};")
        lines.append(f"    e.kind = {kind_enum(e['kind'])};")
        lines.append(f'    e.description = "{cpp_escape(e["description"])}";')
        lines.append(f'    e.docs_url = "{cpp_escape(e.get("docs_url") or "")}";')
        lines.append(f'    e.detect_hint = "{cpp_escape(e.get("detect_hint") or "")}";')
        lines.append(f'    e.setup_key = "{cpp_escape(e.get("setup_key") or "")}";')
        lines.append(f'    e.native_action = "{cpp_escape(e.get("native_action") or "")}";')
        lines.append(f'    e.notes = "{cpp_escape(e.get("notes") or "")}";')
        lines.append("    out.push_back(std::move(e));")
        lines.append("  }")
    lines.append("}")
    out_inc.write_text("\n".join(lines) + "\n", encoding="utf-8")

    kinds = {}
    for e in entries:
        kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
    print(f"COUNT={len(entries)}")
    print("kinds:", kinds)
    print("wrote", out_inc)


if __name__ == "__main__":
    main()
