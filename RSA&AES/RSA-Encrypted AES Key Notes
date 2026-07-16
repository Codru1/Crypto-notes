# RSA-Encrypted AES Key Notes

## Encryption line

```python
C_key = pow(aes_int, E, N)
```

This is Python's modular exponentiation:

```text
C_key = aes_int^E mod N
```

Where:

- `aes_int` is the AES key converted into an integer.
- `E` is the RSA public exponent, usually `65537`.
- `N` is the RSA modulus.
- `C_key` is the encrypted AES key.

The original AES key was converted to an integer using:

```python
aes_int = int.from_bytes(aes_key, "big")
```

---

## Why `pow()` cannot simply be reversed

Knowing:

```python
C_key
E
N
```

is not normally enough to directly recover:

```python
aes_int
```

RSA decryption requires the private exponent `d`.

To calculate `d`, we first need the prime factorization of `N`.

---

## Step 1: Calculate Euler's totient

Suppose:

```text
N = p₁^k₁ × p₂^k₂ × ...
```

Then:

```text
φ(N) = ∏ p^(k - 1)(p - 1)
```

This formula also works when the same prime appears multiple times.

Reusable function:

```python
from collections import Counter


def phi_from_factors(factors):
    phi = 1

    for p, exponent in Counter(factors).items():
        phi *= p ** (exponent - 1) * (p - 1)

    return phi
```

Example:

```python
factors = [3, 3, 5]

phi = phi_from_factors(factors)

print(phi)  # 24
```

This works because:

```text
N = 3² × 5
φ(N) = 3^(2-1)(3-1) × 5^(1-1)(5-1)
φ(N) = 3 × 2 × 1 × 4
φ(N) = 24
```

Repeated primes must remain in the list:

```python
factors = [p, p, q]  # Correct for N = p²q
factors = [p, q]     # Incorrect for N = p²q
```

---

## Step 2: Calculate the private exponent

The public exponent is:

```python
E = 0x10001
```

which is the same as:

```python
E = 65537
```

Calculate the private exponent:

```python
d = pow(E, -1, phi)
```

This finds the modular inverse of `E` modulo `φ(N)`:

```text
E × d ≡ 1 mod φ(N)
```

---

## Step 3: Decrypt the AES key integer

RSA encryption:

```python
C_key = pow(aes_int, E, N)
```

RSA decryption:

```python
aes_int = pow(C_key, d, N)
```

Mathematically:

```text
aes_int = C_key^d mod N
```

---

## Step 4: Convert the integer back to the AES key

The challenge used a 16-byte AES key:

```python
aes_key = secrets.token_bytes(16)
```

Convert the recovered integer back into exactly 16 bytes:

```python
aes_key = aes_int.to_bytes(16, "big")
```

Use exactly `16` so leading zero bytes are preserved.

---

## Reusable RSA key-recovery snippet

```python
from collections import Counter


def phi_from_factors(factors):
    phi = 1

    for p, exponent in Counter(factors).items():
        phi *= p ** (exponent - 1) * (p - 1)

    return phi


E = 65537
N = ...          # Original RSA modulus
C_key = ...      # Encrypted AES key
factors = [...]  # Every prime factor, including repetitions

phi = phi_from_factors(factors)

d = pow(E, -1, phi)

aes_int = pow(C_key, d, N)
aes_key = aes_int.to_bytes(16, "big")

print("phi(N):", phi)
print("Private exponent d:", d)
print("AES key:", aes_key.hex())
```

---

## Important mistake to avoid

If you changed `N` while factoring it:

```python
N //= p
```

then save the original value first:

```python
original_N = N
```

Use another variable while factoring:

```python
remaining = N
```

Then decrypt using:

```python
aes_int = pow(C_key, d, original_N)
```

Do not decrypt using `remaining`, because after successful factorization it will be:

```python
remaining == 1
```

---

## Flow to remember

```text
Prime factors of N
        ↓
Calculate φ(N)
        ↓
Calculate d = E⁻¹ mod φ(N)
        ↓
aes_int = C_key^d mod N
        ↓
aes_key = aes_int.to_bytes(16, "big")
```
