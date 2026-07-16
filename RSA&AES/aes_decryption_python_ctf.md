# AES Decryption in Python — CTF Plug-and-Play Toolkit

This sheet covers every AES mode exposed by **PyCryptodome**:

- ECB
- CBC
- CFB
- OFB
- CTR
- OpenPGP
- CCM
- EAX
- SIV
- GCM
- OCB

Install the library:

```bash
python -m pip install pycryptodome
```

> Import from `Crypto`, not `crypto` and not `Cryptodome`, unless you deliberately installed `pycryptodomex`.

---

## 1. First identify what you have

AES decryption normally needs some combination of:

| Item | Meaning |
|---|---|
| `key` | 16, 24, or 32 bytes for AES-128/192/256 |
| `ciphertext` | The encrypted bytes |
| `iv` | Usually 16 bytes; used by CBC, CFB, OFB |
| `nonce` | Used by CTR and authenticated modes |
| `tag` | Authentication tag for GCM, EAX, CCM, OCB, SIV |
| `aad` | Additional authenticated data; authenticated but not encrypted |
| `segment_size` | CFB segment size, commonly 8 or 128 bits |
| `initial_value` | Initial counter value for some CTR constructions |

Typical encodings:

```python
from base64 import b64decode

key = bytes.fromhex("001122...")
ciphertext = bytes.fromhex("aabbcc...")

key = b64decode("ABEi...")
ciphertext = b64decode("qrvM...")
```

For literal text keys:

```python
key = b"0123456789abcdef"  # exactly 16 bytes
```

Check lengths immediately:

```python
print("key:", len(key))
print("ciphertext:", len(ciphertext))
```

---

## 2. Padding helpers

ECB and CBC often use **PKCS#7 padding**. Stream-like modes normally do not.

```python
from Crypto.Util.Padding import unpad

plaintext = unpad(padded_plaintext, 16)
```

A safe helper:

```python
from Crypto.Util.Padding import unpad

def maybe_unpad(data: bytes, block_size: int = 16) -> bytes:
    try:
        return unpad(data, block_size)
    except ValueError:
        return data
```

Do not blindly remove bytes by doing this:

```python
# Fragile: only use when you know the padding format.
plaintext = plaintext[:-plaintext[-1]]
```

---

# 3. Universal AES decryptor

Change the values in `main()` and select a mode.

```python
from __future__ import annotations

from base64 import b64decode
from itertools import product
from typing import Optional

from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Util.Padding import unpad


def decode_value(value: str, encoding: str) -> bytes:
    encoding = encoding.lower()

    if encoding == "hex":
        return bytes.fromhex(value)
    if encoding in {"b64", "base64"}:
        return b64decode(value)
    if encoding in {"utf8", "text", "raw"}:
        return value.encode()

    raise ValueError(f"Unsupported encoding: {encoding}")


def remove_padding(data: bytes, padding: Optional[str]) -> bytes:
    if padding is None or padding.lower() == "none":
        return data

    if padding.lower() in {"pkcs7", "pkcs#7"}:
        return unpad(data, AES.block_size)

    if padding.lower() == "zero":
        return data.rstrip(b"\x00")

    raise ValueError(f"Unsupported padding: {padding}")


def decrypt_aes(
    *,
    mode: str,
    key: bytes,
    ciphertext: bytes,
    iv: bytes | None = None,
    nonce: bytes | None = None,
    tag: bytes | None = None,
    aad: bytes = b"",
    padding: str | None = None,
    segment_size: int = 128,
    initial_value: int = 0,
    mac_len: int | None = None,
    siv_aad_parts: tuple[bytes, ...] = (),
    ctr_full_block: bytes | None = None,
) -> bytes:
    mode = mode.upper()

    if len(key) not in (16, 24, 32) and mode != "SIV":
        raise ValueError("Normal AES keys must be 16, 24, or 32 bytes")

    if mode == "ECB":
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext = cipher.decrypt(ciphertext)

    elif mode == "CBC":
        if iv is None:
            raise ValueError("CBC requires iv")
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        plaintext = cipher.decrypt(ciphertext)

    elif mode == "CFB":
        if iv is None:
            raise ValueError("CFB requires iv")
        cipher = AES.new(
            key,
            AES.MODE_CFB,
            iv=iv,
            segment_size=segment_size,
        )
        plaintext = cipher.decrypt(ciphertext)

    elif mode == "OFB":
        if iv is None:
            raise ValueError("OFB requires iv")
        cipher = AES.new(key, AES.MODE_OFB, iv=iv)
        plaintext = cipher.decrypt(ciphertext)

    elif mode == "CTR":
        if ctr_full_block is not None:
            if len(ctr_full_block) != 16:
                raise ValueError("A full AES CTR counter block must be 16 bytes")

            counter = Counter.new(
                128,
                initial_value=int.from_bytes(ctr_full_block, "big"),
            )
            cipher = AES.new(key, AES.MODE_CTR, counter=counter)
        else:
            if nonce is None:
                nonce = b""

            cipher = AES.new(
                key,
                AES.MODE_CTR,
                nonce=nonce,
                initial_value=initial_value,
            )

        plaintext = cipher.decrypt(ciphertext)

    elif mode == "OPENPGP":
        if iv is None:
            raise ValueError(
                "For OpenPGP decryption, iv must be the 18-byte encrypted IV prefix"
            )
        cipher = AES.new(key, AES.MODE_OPENPGP, iv=iv)
        plaintext = cipher.decrypt(ciphertext)

    elif mode in {"GCM", "EAX", "CCM", "OCB"}:
        if nonce is None or tag is None:
            raise ValueError(f"{mode} requires nonce and tag")

        mode_constant = {
            "GCM": AES.MODE_GCM,
            "EAX": AES.MODE_EAX,
            "CCM": AES.MODE_CCM,
            "OCB": AES.MODE_OCB,
        }[mode]

        kwargs = {"nonce": nonce}
        if mac_len is not None:
            kwargs["mac_len"] = mac_len

        cipher = AES.new(key, mode_constant, **kwargs)

        if aad:
            cipher.update(aad)

        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    elif mode == "SIV":
        # AES-SIV keys are 32, 48, or 64 bytes.
        if len(key) not in (32, 48, 64):
            raise ValueError("AES-SIV keys must be 32, 48, or 64 bytes")
        if tag is None:
            raise ValueError("SIV requires tag")

        kwargs = {}
        if nonce is not None:
            kwargs["nonce"] = nonce

        cipher = AES.new(key, AES.MODE_SIV, **kwargs)

        for part in siv_aad_parts:
            cipher.update(part)

        plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    else:
        raise ValueError(f"Unsupported AES mode: {mode}")

    return remove_padding(plaintext, padding)


def main() -> None:
    # ---------------- CHANGE THESE ----------------
    MODE = "CBC"
    INPUT_ENCODING = "hex"

    KEY = "00112233445566778899aabbccddeeff"
    CIPHERTEXT = "00000000000000000000000000000000"

    IV = "00000000000000000000000000000000"
    NONCE = ""
    TAG = ""
    AAD = ""

    PADDING = "pkcs7"       # "pkcs7", "zero", or None
    SEGMENT_SIZE = 128      # CFB: usually 8 or 128
    INITIAL_VALUE = 0       # CTR
    MAC_LEN = None          # e.g. 16, when needed

    # For CTR challenges that provide one complete 16-byte counter block:
    CTR_FULL_BLOCK = ""
    # ---------------------------------------------

    key = decode_value(KEY, INPUT_ENCODING)
    ciphertext = decode_value(CIPHERTEXT, INPUT_ENCODING)

    iv = decode_value(IV, INPUT_ENCODING) if IV else None
    nonce = decode_value(NONCE, INPUT_ENCODING) if NONCE else None
    tag = decode_value(TAG, INPUT_ENCODING) if TAG else None
    aad = decode_value(AAD, INPUT_ENCODING) if AAD else b""
    ctr_full_block = (
        decode_value(CTR_FULL_BLOCK, INPUT_ENCODING)
        if CTR_FULL_BLOCK
        else None
    )

    plaintext = decrypt_aes(
        mode=MODE,
        key=key,
        ciphertext=ciphertext,
        iv=iv,
        nonce=nonce,
        tag=tag,
        aad=aad,
        padding=PADDING,
        segment_size=SEGMENT_SIZE,
        initial_value=INITIAL_VALUE,
        mac_len=MAC_LEN,
        ctr_full_block=ctr_full_block,
    )

    print("raw bytes:", plaintext)

    try:
        print("decoded:", plaintext.decode())
    except UnicodeDecodeError:
        print("hex:", plaintext.hex())


if __name__ == "__main__":
    main()
```

---

# 4. Minimal templates by mode

## AES-ECB

Requirements:

- Key
- Ciphertext
- Ciphertext length must be a multiple of 16

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = bytes.fromhex("...")
ciphertext = bytes.fromhex("...")

cipher = AES.new(key, AES.MODE_ECB)
plaintext = cipher.decrypt(ciphertext)

try:
    plaintext = unpad(plaintext, 16)
except ValueError:
    pass

print(plaintext)
```

Useful CTF clue: identical plaintext blocks produce identical ciphertext blocks.

---

## AES-CBC

Requirements:

- Key
- 16-byte IV
- Ciphertext
- Ciphertext length must be a multiple of 16

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = bytes.fromhex("...")
iv = bytes.fromhex("...")
ciphertext = bytes.fromhex("...")

cipher = AES.new(key, AES.MODE_CBC, iv=iv)
plaintext = cipher.decrypt(ciphertext)

try:
    plaintext = unpad(plaintext, 16)
except ValueError:
    pass

print(plaintext)
```

A common file format is:

```text
IV || ciphertext
```

Split it like this:

```python
blob = bytes.fromhex("...")

iv = blob[:16]
ciphertext = blob[16:]
```

---

## AES-CFB

Requirements:

- Key
- 16-byte IV
- Ciphertext
- Correct segment size

```python
from Crypto.Cipher import AES

key = bytes.fromhex("...")
iv = bytes.fromhex("...")
ciphertext = bytes.fromhex("...")

cipher = AES.new(
    key,
    AES.MODE_CFB,
    iv=iv,
    segment_size=128,
)

plaintext = cipher.decrypt(ciphertext)
print(plaintext)
```

Try both common values when the challenge does not specify the segment size:

```python
from Crypto.Cipher import AES

for segment_size in (8, 128):
    cipher = AES.new(
        key,
        AES.MODE_CFB,
        iv=iv,
        segment_size=segment_size,
    )
    plaintext = cipher.decrypt(ciphertext)
    print(segment_size, plaintext)
```

No padding is normally used.

---

## AES-OFB

Requirements:

- Key
- 16-byte IV
- Ciphertext

```python
from Crypto.Cipher import AES

key = bytes.fromhex("...")
iv = bytes.fromhex("...")
ciphertext = bytes.fromhex("...")

cipher = AES.new(key, AES.MODE_OFB, iv=iv)
plaintext = cipher.decrypt(ciphertext)

print(plaintext)
```

No padding is normally used.

---

## AES-CTR: nonce plus counter

Requirements:

- Key
- Nonce
- Initial counter value
- Correct byte order/layout

```python
from Crypto.Cipher import AES

key = bytes.fromhex("...")
nonce = bytes.fromhex("...")
ciphertext = bytes.fromhex("...")

cipher = AES.new(
    key,
    AES.MODE_CTR,
    nonce=nonce,
    initial_value=0,
)

plaintext = cipher.decrypt(ciphertext)
print(plaintext)
```

A common 16-byte layout is:

```text
nonce || counter
```

For example, an 8-byte nonce and an 8-byte big-endian counter:

```python
nonce = bytes.fromhex("0011223344556677")
initial_value = 0
```

### CTR with a complete 16-byte initial counter block

```python
from Crypto.Cipher import AES
from Crypto.Util import Counter

key = bytes.fromhex("...")
initial_counter_block = bytes.fromhex("...")
ciphertext = bytes.fromhex("...")

counter = Counter.new(
    128,
    initial_value=int.from_bytes(initial_counter_block, "big"),
)

cipher = AES.new(key, AES.MODE_CTR, counter=counter)
plaintext = cipher.decrypt(ciphertext)

print(plaintext)
```

### Little-endian CTR

Some CTFs deliberately use a little-endian counter:

```python
from Crypto.Cipher import AES
from Crypto.Util import Counter

counter = Counter.new(
    128,
    initial_value=0,
    little_endian=True,
)

cipher = AES.new(key, AES.MODE_CTR, counter=counter)
plaintext = cipher.decrypt(ciphertext)
print(plaintext)
```

No padding is normally used.

---

## AES-GCM

Requirements:

- Key
- Nonce
- Ciphertext
- Authentication tag
- Exact AAD, when used

```python
from Crypto.Cipher import AES

key = bytes.fromhex("...")
nonce = bytes.fromhex("...")
ciphertext = bytes.fromhex("...")
tag = bytes.fromhex("...")
aad = b""

cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

if aad:
    cipher.update(aad)

plaintext = cipher.decrypt_and_verify(ciphertext, tag)
print(plaintext)
```

Never replace `decrypt_and_verify()` with only `decrypt()` unless the challenge specifically asks you to ignore authenticity.

A common blob layout is:

```text
nonce || ciphertext || tag
```

Example for a 12-byte nonce and 16-byte tag:

```python
blob = bytes.fromhex("...")

nonce = blob[:12]
tag = blob[-16:]
ciphertext = blob[12:-16]
```

---

## AES-EAX

Requirements:

- Key
- Nonce
- Ciphertext
- Tag
- Exact AAD, when used

```python
from Crypto.Cipher import AES

key = bytes.fromhex("...")
nonce = bytes.fromhex("...")
ciphertext = bytes.fromhex("...")
tag = bytes.fromhex("...")
aad = b""

cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

if aad:
    cipher.update(aad)

plaintext = cipher.decrypt_and_verify(ciphertext, tag)
print(plaintext)
```

---

## AES-CCM

Requirements:

- Key
- Nonce, normally 7 to 13 bytes
- Ciphertext
- Tag
- Exact AAD, when used
- Correct tag length

```python
from Crypto.Cipher import AES

key = bytes.fromhex("...")
nonce = bytes.fromhex("...")
ciphertext = bytes.fromhex("...")
tag = bytes.fromhex("...")
aad = b""

cipher = AES.new(
    key,
    AES.MODE_CCM,
    nonce=nonce,
    mac_len=len(tag),
)

if aad:
    cipher.update(aad)

plaintext = cipher.decrypt_and_verify(ciphertext, tag)
print(plaintext)
```

Typical CCM tag lengths are even values from 4 through 16 bytes.

---

## AES-OCB

Requirements:

- Key
- Nonce
- Ciphertext
- Tag
- Exact AAD, when used

```python
from Crypto.Cipher import AES

key = bytes.fromhex("...")
nonce = bytes.fromhex("...")
ciphertext = bytes.fromhex("...")
tag = bytes.fromhex("...")
aad = b""

cipher = AES.new(
    key,
    AES.MODE_OCB,
    nonce=nonce,
    mac_len=len(tag),
)

if aad:
    cipher.update(aad)

plaintext = cipher.decrypt_and_verify(ciphertext, tag)
print(plaintext)
```

---

## AES-SIV

AES-SIV is different:

- The key must be 32, 48, or 64 bytes.
- The synthetic IV is returned as the authentication tag.
- A nonce is optional.
- Multiple AAD components may be supplied separately.
- A normal 16/24/32-byte AES key may therefore be too short for SIV.

```python
from Crypto.Cipher import AES

key = bytes.fromhex("...")          # 32, 48, or 64 bytes
ciphertext = bytes.fromhex("...")
tag = bytes.fromhex("...")
nonce = None                        # or bytes.fromhex("...")

kwargs = {}
if nonce is not None:
    kwargs["nonce"] = nonce

cipher = AES.new(key, AES.MODE_SIV, **kwargs)

# Repeat update() once for each original AAD component.
# cipher.update(b"header")
# cipher.update(b"filename")

plaintext = cipher.decrypt_and_verify(ciphertext, tag)
print(plaintext)
```

The order and separation of AAD components must match encryption.

These are not necessarily equivalent:

```python
cipher.update(b"one")
cipher.update(b"two")
```

```python
cipher.update(b"onetwo")
```

---

## AES-OpenPGP

PyCryptodome's OpenPGP mode uses an encrypted IV prefix.

A common blob layout is:

```text
18-byte encrypted IV || ciphertext
```

```python
from Crypto.Cipher import AES

key = bytes.fromhex("...")
blob = bytes.fromhex("...")

encrypted_iv = blob[:18]
ciphertext = blob[18:]

cipher = AES.new(
    key,
    AES.MODE_OPENPGP,
    iv=encrypted_iv,
)

plaintext = cipher.decrypt(ciphertext)
print(plaintext)
```

OpenPGP mode alone does not prove integrity. Real OpenPGP formats add additional packet structure and integrity mechanisms.

---

# 5. Brute-force common AES parameters

## Try common paddings

```python
from Crypto.Util.Padding import unpad

candidates = [plaintext]

try:
    candidates.append(unpad(plaintext, 16))
except ValueError:
    pass

candidates.append(plaintext.rstrip(b"\x00"))

for candidate in candidates:
    print(repr(candidate))
```

## Try key hashes

A challenge may derive an AES key from a password:

```python
from hashlib import md5, sha1, sha256

password = b"secret"

keys = {
    "raw padded": password.ljust(16, b"\x00")[:16],
    "MD5": md5(password).digest(),
    "SHA-1 first 16": sha1(password).digest()[:16],
    "SHA-256 first 16": sha256(password).digest()[:16],
    "SHA-256 full": sha256(password).digest(),
}

for name, key in keys.items():
    print(name, key.hex())
```

Do not assume this is secure password derivation. It is merely common in CTF code.

## Try IV locations

```python
possible_ivs = {
    "first 16": blob[:16],
    "last 16": blob[-16:],
    "all zero": bytes(16),
}

possible_ciphertexts = {
    "after first 16": blob[16:],
    "before last 16": blob[:-16],
    "whole blob": blob,
}
```

## Search for readable output

```python
import string

PRINTABLE = set(bytes(string.printable, "ascii"))

def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(byte in PRINTABLE for byte in data) / len(data)

def looks_interesting(data: bytes) -> bool:
    lowered = data.lower()

    markers = (
        b"flag{",
        b"ctf{",
        b"picoctf{",
        b"htb{",
        b"crypto{",
        b"{",
    )

    return (
        printable_ratio(data) > 0.85
        or any(marker in lowered for marker in markers)
    )
```

---

# 6. AES file decryptor

```python
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


KEY = bytes.fromhex("...")
IV = bytes.fromhex("...")

input_path = Path("encrypted.bin")
output_path = Path("decrypted.bin")

ciphertext = input_path.read_bytes()

cipher = AES.new(KEY, AES.MODE_CBC, iv=IV)
plaintext = cipher.decrypt(ciphertext)

try:
    plaintext = unpad(plaintext, 16)
except ValueError:
    pass

output_path.write_bytes(plaintext)
print(f"Wrote {len(plaintext)} bytes to {output_path}")
```

For a blob stored as `IV || ciphertext`:

```python
blob = input_path.read_bytes()
iv, ciphertext = blob[:16], blob[16:]
```

---

# 7. OpenSSL-compatible salted AES files

Files produced by commands such as old-style:

```bash
openssl enc -aes-256-cbc -salt ...
```

often start with:

```text
Salted__ || 8-byte salt || ciphertext
```

Legacy OpenSSL commonly used `EVP_BytesToKey`. Newer commands may use PBKDF2.

## Legacy `EVP_BytesToKey` helper

```python
from hashlib import md5
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


def evp_bytes_to_key(
    password: bytes,
    salt: bytes,
    key_len: int,
    iv_len: int,
) -> tuple[bytes, bytes]:
    material = b""
    previous = b""

    while len(material) < key_len + iv_len:
        previous = md5(previous + password + salt).digest()
        material += previous

    key = material[:key_len]
    iv = material[key_len:key_len + iv_len]
    return key, iv


blob = open("encrypted.bin", "rb").read()

if not blob.startswith(b"Salted__"):
    raise ValueError("Missing OpenSSL Salted__ header")

salt = blob[8:16]
ciphertext = blob[16:]
password = b"password"

key, iv = evp_bytes_to_key(password, salt, 32, 16)

cipher = AES.new(key, AES.MODE_CBC, iv=iv)
plaintext = unpad(cipher.decrypt(ciphertext), 16)

print(plaintext)
```

You must match the original digest and KDF parameters. Some OpenSSL versions or commands use SHA-256 or PBKDF2 instead.

---

# 8. Common errors and what they usually mean

## `ValueError: Incorrect AES key length`

Your decoded key is not:

- 16 bytes
- 24 bytes
- 32 bytes

For SIV, it must instead be:

- 32 bytes
- 48 bytes
- 64 bytes

Check whether you forgot to decode hex/base64.

```python
print(len(key), key)
```

A 32-character hex string decodes to 16 bytes.

---

## `ValueError: Data must be aligned to block boundary`

Common with ECB and CBC.

Likely causes:

- Ciphertext was decoded incorrectly.
- An IV, nonce, salt, or header is still attached.
- Ciphertext is truncated.
- The mode is wrong.

ECB and CBC ciphertext lengths must be multiples of 16.

```python
print(len(ciphertext), len(ciphertext) % 16)
```

---

## `ValueError: Padding is incorrect`

Likely causes:

- Wrong key
- Wrong IV
- Wrong mode
- Wrong ciphertext slice
- No PKCS#7 padding was used
- Data is corrupt

A padding error is useful evidence, not proof.

---

## `ValueError: MAC check failed`

For GCM/EAX/CCM/OCB/SIV, at least one of these is wrong:

- Key
- Nonce
- Ciphertext
- Tag
- AAD
- Tag length
- Data ordering

Do not simply ignore this error in normal cryptographic code.

---

## Output is random-looking but no error occurs

Unauthenticated modes can decrypt with the wrong parameters and still return bytes.

Check:

- Hex versus base64
- IV location
- CTR endian
- CTR initial counter
- CFB segment size
- Padding
- Key derivation
- Whether ciphertext includes nonce/tag/header

---

# 9. Fast mode-identification clues

| Clue | Modes to suspect |
|---|---|
| Repeated 16-byte ciphertext blocks | ECB |
| 16-byte IV and block-aligned ciphertext | CBC |
| Ciphertext can have any length; 16-byte IV | CFB or OFB |
| Nonce and counter | CTR |
| Nonce plus tag | GCM, EAX, CCM, or OCB |
| 32/48/64-byte key plus synthetic-IV tag | SIV |
| 18-byte encrypted-IV prefix | OpenPGP |
| `decrypt_and_verify` in source | Authenticated mode |
| `segment_size=8` or `128` | CFB |
| `Counter.new(...)` | CTR |
| `cipher.update(header)` | AAD in an authenticated mode |

---

# 10. Security mistakes that become CTF attacks

## Reused CTR nonce/counter

CTR encryption is:

```text
ciphertext = plaintext XOR keystream
```

If the same key and counter stream are reused:

```text
c1 XOR c2 = p1 XOR p2
```

```python
def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

p1_xor_p2 = xor_bytes(c1, c2)
```

With a known plaintext:

```python
keystream = xor_bytes(known_plaintext, known_ciphertext)
recovered = xor_bytes(target_ciphertext, keystream)
```

---

## Reused OFB keystream

The same two-time-pad logic applies when an OFB IV is reused with the same key.

---

## Reused GCM nonce

Nonce reuse in GCM is catastrophic:

- It reuses CTR keystream.
- It can expose relations between plaintexts.
- With enough structure, it may permit tag forgery.

For a basic known-plaintext recovery:

```python
keystream = xor_bytes(known_plaintext, known_ciphertext)
recovered_prefix = xor_bytes(target_ciphertext, keystream)
```

This only recovers bytes covered by the known keystream.

---

## CBC bit flipping

Changing ciphertext block `C[i-1]` changes the next plaintext block:

```text
P[i] = D(C[i]) XOR C[i-1]
```

To change known plaintext bytes into desired bytes:

```python
modified_previous = bytes(
    old_c ^ old_p ^ new_p
    for old_c, old_p, new_p in zip(
        previous_cipher_block,
        known_plain_block,
        desired_plain_block,
    )
)
```

The previous plaintext block becomes corrupted, but the targeted next block changes predictably.

For the first plaintext block, modify the IV instead.

---

## ECB block cut-and-paste

ECB encrypts each block independently. Entire ciphertext blocks can sometimes be rearranged to produce meaningful plaintext structures.

---

## Padding oracle

A CBC service that reveals whether padding is valid can leak plaintext one byte at a time.

The attack needs an oracle such as:

```python
def oracle(ciphertext: bytes) -> bool:
    ...
```

The important relation for one block is:

```text
P[i] = D(C[i]) XOR C[i-1]
```

Modify `C[i-1]` and observe whether the resulting `P[i]` has valid padding.

Use a dedicated script for real padding-oracle challenges because network retry logic and false positives matter.

---

# 11. Final CTF checklist

Before deciding AES "does not work," verify:

1. Did you decode hex/base64 into bytes?
2. Is the key the correct byte length?
3. Did you separate headers, salt, IV, nonce, ciphertext, and tag?
4. Is the selected mode correct?
5. Is the IV exactly 16 bytes where required?
6. Is the authenticated-mode nonce correct?
7. Is the tag sliced from the correct side and at the correct length?
8. Did you supply AAD before decryption?
9. Is CFB using the correct segment size?
10. Is CTR using the correct nonce/counter split?
11. Is the counter big-endian or little-endian?
12. Is the initial counter zero, one, or another supplied value?
13. Should padding be removed?
14. Was the key derived from a password?
15. Does the blob contain an OpenSSL or format-specific header?
16. Are the mode parameters reused in a way that creates an attack?
