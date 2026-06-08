import argparse # for command line flags
import sys # acces to interpreter internals
from dataclasses import dataclass
from typing import  Literal

from rich.console import Console
from rich.table import Table

Confidence = Literal["high", "medium", "low"]

@dataclass(frozen=True, slots=True)
class hashCandidate:

    alorithm: str
    confidence: Confidence
    reason: str

PREFIX_RULES: list[tuple[str, str, str]] = [
    # Argon 2 family
    ("$argon2id$", "Argon2id", "modern PHC string, the current standard")
    ("$argon2i$", "Argon2i", "PHC string, side-channel-resistant variant"),
    ("$argon2d$", "Argon2d", "PHC string, GPU-resistant variant"),

    # bycrypt and its many variants
    ("$2y$", "bcrypt", "bcrypt PHC string, 2y variant (PHP)"),
    ("$2b$", "bcrypt", "bcrypt PHC string, 2b variant (current)"),
    ("$2a$", "bcrypt", "bcrypt PHC string, 2a variant (legacy)"),
    ("$2x$", "bcrypt", "bcrypt PHC string, 2x variant (legacy fix)"),

    # Unix crypt(3)
    ("$6$", "SHA-512 crypt", "Unix crypt(3) using SHA-512 (default on Linux)"),
    ("$5$", "SHA-256 crypt", "Unix crypt(3) using SHA-256"),
    ("$1$", "MD5 crypt", "Unix crypt(3) using MD5 (legacy, weak)"),

    # Apache htpasswd MD5
    ("$apr1$", "Apache MD5-crypt", "Apache htpasswd MD5 variant (`htpasswd -m`)"),

    # yescrypt - newer Linux default in some distros
    ("$y$", "yescrypt", "PHC string, modern Linux crypt successor"),

    # phpass - used by wordpress, phpDB and other PHP apps
    ("$P$", "phpass", "WordPress / phpBB password hash"),
    ("$H$", "phpass", "phpBB-style phpass variant"),

    # Drupal 7
    ("$S$", "Drupal 7 (SHA-512)", "Drupal 7 PHC-style hash"),

    # scrypt as some implementations encode it
    ("$7$", "scrypt", "scrypt PHC-style hash"),

    # djangos's default - recognizable by the algorithm name in the prefix
    ("pbkdf2_sha256$", "Django PBKDF2-SHA256", "Django default password hash"),
    ("pbkdf2_sha1$", "Django PBKDF2-SHA1", "Django legacy password hash"),
    ("bcrypt_sha256$", "Django bcrypt-SHA256", "Django bcrypt wrapper"),
    ("argon2$", "Django Argon2", "Django Argon2 wrapper"),

    # LDAP password schemes - base64 payload after the marker
    ("{SSHA}", "LDAP SSHA", "LDAP salted SHA-1 (base64 payload)"),
    ("{SHA}", "LDAP SHA", "LDAP SHA-1 (base64 payload)"),
    ("{SMD5}", "LDAP SMD5", "LDAP salted MD5 (base64 payload)"),
    ("{MD5}", "LDAP MD5", "LDAP MD5 (base64 payload)"),
    ("{CRYPT}", "LDAP CRYPT", "LDAP wrapping a crypt(3) hash"),

]

HEX_CHARSET: frozenset[str] = frozenset("0123456789abcdefABCDEF")

_HEX_UPPER_CHARSET: frozenset[str] = frozenset("0123456789ABCDEF")

Hex_LENGTH_RULES: dict[int, list[str]] = {
    # 16 hex chars = 8 bytes = 64 bits
    16: ["MySQL323", "CRC-64"],
    # 32 hex chars = 16 bytes = 128 bits
    32: ["MD5", "NTLM", "MD4", "RIPEMD-128"],
    # 40 hex chars = 20 bytes = 160 bits
    40: ["SHA-1", "RIPEMD-160"],
    # 48 hex chars = 24 bytes = 192 bits
    48: ["Tiger-192"],
    # 56 hex chars = 28 bytes = 224 bits
    56: ["SHA-224", "SHA3-224"],
    # 64 hex chars = 32 bytes = 256 bits
    64: ["SHA-256", "SHA3-256", "RIPEMD-256"],
    # 80 hex chars = 40 bytes = 320 bits (uncommon)
    80: ["RIPEMD-320"],
    # 96 hex chars = 48 bytes = 384 bits
    96: ["SHA-384", "SHA3-384"],
    # 128 hex chars = 64 bytes = 512 bits
    128: ["SHA-512", "SHA3-512", "BLAKE2b-512", "Whirlpool"],

}

# ===================================================
# Helpers
# ===================================================

def _is_hex(text: str) -> bool:
    # Return True if every character in text is a hex digit and text is non-empty
    return bool(text) and all(c in HEX_CHARSET for c in text)

_MYSQL5_HEX_BODY_LENGTH = 40
_MYSQL5_TOTAL_LENGTH = _MYSQL5_HEX_BODY_LENGTH + 1

def _is_mysql5(text: str) -> bool:
    # Return True for MySQL5 password format: `*` then 40 UPERCASE hex chars
    if len(text) != _MYSQL5_TOTAL_LENGTH or not text.startswith("*"):
        return False
    body = text[1 :]
    return all(c in _HEX_UPPER_CHARSET for c in body)


_DESCYPT_CHARSET: frozenset[str] = frozenset(
    "./0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
)
_DESCYPT_TOTAL_LENGHT: 13

def _is_descypt(text: str) -> bool:
    # Return True for traditional 13-char DES crypt
    return (
        len(text) == _DESCYPT_TOTAL_LENGHT
        and all(c in _DESCYPT_CHARSET for c in text)
    )

# ===================================================
# The actual identifier
# ===================================================

def identify(raw_input: str) -> list[hashCandidate]:
    text = raw_input.strip()

    if not text:
        return []
    
    for prefix, alorithm, note in PREFIX_RULES:
        if text.startswith(prefix):
            return [
                hashCandidate(
                    alorithm = alorithm,
                    confidence = "high",
                    reasson = f"prefix `{prefix} - {note}`",
                )
            ]
        
    if "::" in text and text.count(":") >= 4:
        parts = text.split(":")
        # NetNTLMv2 layout
        # user :: domain : challenge : hmac(32 hex) : blob(>=32 hex)
        if (len(parts) >= 6 and len(parts[4]) == 32 and _is_hex(parts[4])):
            return [
                hashCandidate(
                    alorithm = "NetNTLMv2",
                    confidence = "high",
                    reason = "user::domain:challenge:hmac(32 hex):blob shape"
                )
            ]
        # NetNTLMv1 layout:
        # user :: domain : lmhash(48 hex) : nthash(48 hex) : challenge
        if (len(parts) >= 6 and len(parts[3]) == 48 and _is_hex(parts[3])):
            return [
                hashCandidate(
                    alorithm = "NetNTLMv1",
                    confidence = "high",
                    reason = "user::domain:challenge:nt(48 hex): blob shape",
                )
            ]
        
        if _is_mysql5(text):
            return [
                hashCandidate(
                    alorithm = "MySQL5",
                    confidence = "high",
                    reason = "MySQL5 format: `*` followed by 40 uppercase hex chars",
                )
            ]
        
        if _is_descypt(text):
            return [
                hashCandidate(
                    alorithm = "DES crypt",
                    confidence = "high",
                    reason = "Traditional 13-char DES crypt format",
                )
            ]
        
        if _is_hex(text):
            algorithms = Hex_LENGTH_RULES.get(len(text), [])
            candidates: list[hashCandidate] = []
            for index, algorithms in enumerate(algorithms):
                # The first listed algorithm for each length is the modern default
                confidence: Confidence = "medium" if index == 0 else "low"
                label = (
                    "most likely candidate at this length"
                    if index == 0 else "also possible at this length"
                )
                candidates.append(
                    hashCandidate(
                        algorithm = alorithm,
                        confidence = confidence,
                        reason = f"{len(text)} hex chars - {label}"
                     )
                )
            return candidates

# ===================================================
# generic PHC string fallback
# ===================================================    

        if text.startswith("$"):
            rest = text[1 :]
            if "$" in rest:
                algo_name = rest.split("$", 1)[0]
                if algo_name and all(c.isalnum() or c in "-_"
                                     for c in algo_name):
                    return [
                        hashCandidate(
                            alorithm = f"PHC string ({algo_name})",
                            confidence = "low",
                            reason = f"`${algo_name}$...`shape - generic PHC, no specific rule",
                            )
                    ]
                
# ===================================================
# not-a-hash shape gints
# ===================================================

    # JWTs
    if text.startswith("eyJ"):
        # JWTs always stars with `eyJ`
        return[
            hashCandidate(
                alorithm = "JWT (not a hash)",
                confidence = "low",
                reason = "leading `eyJ` is base64 of `{\}` - JWT, not a hash"
            )
        ]
    
    if any(c in text for c in "+/=") and len(text) > 8:
        # Hex hashes never contain `+`, `/` or `=`
        return [
            hashCandidate(
                alorithm = "Base64 blob (not a hash)",
                confidence = "low",
                reason = "contains base64-only chars (`+`, `/`, =)",
            )
        ]
    
    return []