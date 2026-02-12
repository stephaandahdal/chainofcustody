# Chain of Custody CLI

A Python command-line application for tracking digital evidence with a tamper-evident blockchain-style ledger.

Built in **November 2025**, this project models core chain-of-custody workflows: item intake, check-in/check-out, removal, history, and integrity verification.

## Why this project

Evidence handling needs clear traceability and strong integrity guarantees. This tool records each state transition as an immutable block linked by cryptographic hashes, so tampering or broken history can be detected quickly.

## Features

- Initialize a ledger with a genesis block
- Add evidence items to a case
- Check items in and out
- Remove items with reason tracking (`DISPOSED`, `DESTROYED`, `RELEASED`)
- Query cases, items, and historical actions
- Summarize current status for a case
- Verify full chain integrity and rule compliance

## Tech stack

- Python 3
- `argparse` for CLI command parsing
- `struct` for binary block encoding
- `hashlib` (SHA-256) for block linking
- `pycryptodome` (`Crypto.Cipher.AES`) for identifier encryption

## Project structure

- `main.py`: Core logic, command handlers, hashing/encryption, and CLI parser
- `Makefile`: Builds an executable wrapper script (`bchoc`)

## Quick start

### 1) Install dependency

```bash
python3 -m pip install pycryptodome
```

### 2) (Optional) Build executable wrapper

```bash
make
```

This creates `./bchoc`, which calls `main.py`.

### 3) Set required environment variables

```bash
export BCHOC_PASSWORD_CREATOR="creator-pass"
export BCHOC_PASSWORD_POLICE="police-pass"
export BCHOC_PASSWORD_LAWYER="lawyer-pass"
export BCHOC_PASSWORD_ANALYST="analyst-pass"
export BCHOC_PASSWORD_EXECUTIVE="executive-pass"

# Optional: custom blockchain file path (default: blockchain.bin)
export BCHOC_FILE_PATH="./blockchain.bin"
```

## Usage examples

Use either:
- `python3 main.py ...`
- `./bchoc ...` (after `make`)

Initialize:

```bash
python3 main.py init
```

Add an item:

```bash
python3 main.py add \
  -c 123e4567-e89b-12d3-a456-426614174000 \
  -i 101 \
  -g "OfficerA" \
  -p "$BCHOC_PASSWORD_CREATOR"
```

Check out / check in:

```bash
python3 main.py checkout -i 101 -p "$BCHOC_PASSWORD_POLICE"
python3 main.py checkin  -i 101 -p "$BCHOC_PASSWORD_POLICE"
```

Show history:

```bash
python3 main.py show history -c 123e4567-e89b-12d3-a456-426614174000 -p "$BCHOC_PASSWORD_POLICE"
```

Verify ledger integrity:

```bash
python3 main.py verify
```

## Notes

- Data is stored in a compact binary format (not JSON).
- UUID case IDs are encrypted before storage.
- Item IDs are encrypted before storage.
- `verify` checks hash-link consistency and invalid state transitions.

