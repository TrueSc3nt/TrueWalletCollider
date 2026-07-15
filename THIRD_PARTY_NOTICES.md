# Third-party notices — TrueWalletCollider

This product includes or optionally downloads third-party software. Licenses below are summaries; see each project for full text.

## Bundled in repository / binary link

| Component | License | Notes |
|-----------|---------|--------|
| Dear ImGui | MIT | `third_party/imgui` |
| GLFW | zlib/libpng | `third_party/glfw` |
| micro-ecc | BSD-2-Clause | `third_party/micro-ecc` — secp256k1 dual-verify |
| Bitcoin Core ctaes | MIT-style | `src/crypto/ctaes*` — see `docs/CTAES_COPYING.txt` |

## Optional: fetched by `setup_forensics.bat`

| Component | License | Location after setup |
|-----------|---------|----------------------|
| [Hashcat](https://hashcat.net/hashcat/) | MIT | `third_party/hashcat/` |

Hashcat binaries are **not** redistributed in the git tree (size). Run `setup_forensics.bat` on a machine with network access, or place an official Hashcat Windows build under `third_party\hashcat\` so `hashcat.exe` is discoverable by **Hashcat Bridge**.

## Related external tools (not bundled)

| Tool | Typical use with this suite |
|------|-----------------------------|
| John the Ripper (jumbo) | `--format=bitcoin` on exported `$bitcoin$` lines |
| BTCRecover | Seed/tokenlist workflows; feed hashes / wallet paths externally |
| TrueMkeyCollider | CUDA CLI sibling (`--partial`, `-ckeys`, `--cmd`) |

## Honesty

TrueWalletCollider does not claim ownership of Hashcat, John, or BTCRecover. The **Hashcat Bridge** tab exports Bitcoin Core–compatible hash lines and may spawn a local `hashcat.exe` for authorized recovery only.
