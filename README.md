# Neo-Matrix — Python Obfuscator

Neo-Matrix is a Python 3.10+ obfuscator that turns a readable script into a deeply obfuscated, self-protecting blob. It hides your code behind random keys, scrambled control flow, and an encrypted payload that refuses to run if the file is tampered with.

> Author: https://6cxl.lol — Repo: github.com/ktn1703/Neo

---

## What it does

The pipeline is roughly: clean the source → rename variables to random Chinese characters → hide constants behind XOR keys → stuff every statement into decoy try/except blocks → encrypt the whole compiled payload with a key derived from the file itself → glue it behind anti-hook and anti-debug guards.

### Key features

- **Keyed string & int obfuscation** — every literal is XORed with a fresh random key (different on every run) plus an offset, then reconstructed at runtime. Nothing appears in plaintext.
- **Variable mangling** — every declared name gets renamed to random 7–9 character Chinese tokens. Hard to read, hard to grep.
- **Control-flow decoys** — statements are wrapped in nested `try/raise MemoryError` chains with fake branches that only "work" when the real code runs.
- **Anti-pycdc** — the output injects crashing expressions so common decompilers choke instead of outputting clean source.
- **Anti-hook / anti-debug** — detects `gettrace`, `setprofile`, and `sys.monitoring` events, kills known debugger modules, and refuses to run under proxied environments.
- **Anti-dump / tamper-proof payload** — the real code is compiled, XORed with a keystream generated from `SHA256` of the file's own header bytes, then nested through zlib → lzma → bz2 → base85. Change a single byte and decryption silently fails.
- **Version lock** — the output only runs on the exact Python version it was built with.
- **Two output styles** — `mine` (mineral-themed names) and `legacy` (classic style).

---

## Usage

### Command line

```bash
python neo.py -f your_script.py -o output.py
```

Or

```
python neo.py
```

Options:

| Flag | Meaning |
|---|---|
| `-f, --file` | Path to the script to obfuscate |
| `-o, --output` | Output file (default: `neo-<name>`) |
| `-m, --mode` | 1 = light, 2 = full (default), 3 = mega |
| `--no-protect` | Skip anti-hook / anti-debug header |
| `--no-hide` | Skip builtin-hiding pass |
| `--no-more` | Skip variable renaming & advanced spam |
| `--banner` | Show logo even when using `-f` |
| `--style` | `mine` (default) or `legacy` |

### Examples

```bash
# Quick run, defaults (mode 2)
python neo.py -f bot.py

# Heavy obfuscation into a custom file
python neo.py -f bot.py -o secured.py -m 3 --banner

# Light pass, no guards (for debugging your own script)
python neo.py -f tool.py --no-protect --no-more -m 1
```

### Interactive mode

Just run `python neo.py` with no arguments and follow the prompts: drag your file in, pick a mode, then answer the `y/n` questions. The obfuscated script is saved automatically.

---

## Notes

- Requires **Python 3.10 or newer**.
- Output is locked to the Python version it was built on.
- Obfuscation makes code hard to reverse, not impossible. Always keep the original source safe.
- For HLS / VOD confusion, do not strip the payload markers — the keystream depends on the exact file bytes.
