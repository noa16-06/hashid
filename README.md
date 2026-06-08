# hashid

A command-line tool that identifies hash strings by prefix, length, and charset. Returns ranked candidates with confidence levels and reasoning.

## Features

- Prefix-based detection for modern password hashing schemes (Argon2, bcrypt, scrypt, yescrypt, phpass, Django, LDAP, ...)
- Unix crypt(3) formats (SHA-512, SHA-256, MD5)
- NetNTLMv1 / NetNTLMv2 challenge-response hashes
- MySQL323 and MySQL5 password hashes
- Traditional DES crypt
- Hex-based detection by length (MD5, SHA-1, SHA-256, SHA-512, BLAKE2b, Whirlpool, ...)
- Generic PHC string fallback
- JWT and Base64 blob hints (flags non-hashes)
- Confidence levels: `high` / `medium` / `low`
- Clean terminal output via [rich](https://github.com/Textualize/rich)

## Requirements

- Python 3.10+
- See `requirements.txt`

## Installation

```bash
git clone https://github.com/noa16-06/hashid.git
cd hashid
pip install -r requirements.txt
```

## Usage

```bash
python hashid.py <hash> [--top N]
```

### Arguments

| Argument | Description |
|---|---|
| `hash` | The hash string to identify. Wrap in single quotes if it contains `$`. |
| `--top N`, `-n N` | Show at most N candidates (default: 5). |

### Examples

```bash
# MD5 or NTLM (32 hex chars)
python hashid.py 5f4dcc3b5aa765d61d8327deb882cf99

# bcrypt
python hashid.py '$2b$12$somehashhere'

# Unix SHA-512 crypt
python hashid.py '$6$rounds=5000$somesalt$hashbody'

# Django PBKDF2
python hashid.py 'pbkdf2_sha256$260000$somesalt$hashbody'

# Limit output to top 3 candidates
python hashid.py 5f4dcc3b5aa765d61d8327deb882cf99 --top 3
```

### Example Output

```
              Candidates for: 5f4dcc3b5aa765d61d8327deb882cf99
┌───────────┬────────────┬──────────────────────────────────────────┐
│ algorithm │ confidence │ reason                                   │
├───────────┼────────────┼──────────────────────────────────────────┤
│ MD5       │ medium     │ 32 hex chars - most likely at this length│
│ NTLM      │ low        │ 32 hex chars - also possible at this leng│
│ MD4       │ low        │ 32 hex chars - also possible at this leng│
└───────────┴────────────┴──────────────────────────────────────────┘
```

## Confidence Levels

| Level | Meaning |
|---|---|
| `high` | Unambiguous prefix or format match |
| `medium` | Most common algorithm at this hex length |
| `low` | Possible but not definitive |