# Reversing `pow()` in Python — CTF Crypto Playbook

The usual target is:

```python
y = pow(x, e, n)
```

You know some or all of `y`, `e`, and `n`, and want to recover `x`.

There is no single universal inverse. The correct method depends on:

- Whether a modulus exists
- Whether the modulus is prime or composite
- Whether the modulus can be factored
- Whether `e` is invertible in the relevant exponent group
- Whether the answer is small or constrained
- Whether multiple equations reuse the same secret
- Whether the challenge accidentally removes modular wraparound

---

# 1. Decision tree

Start here.

```text
Is there no modulus?
    yes -> take an exact integer e-th root

Is x^e actually smaller than n?
    yes -> y is the ordinary integer x^e; take an exact root

Is n prime?
    yes:
        gcd(e, n - 1) = 1?
            yes -> invert e modulo n - 1
            no  -> there may be zero or multiple roots;
                   use modular-root methods

Is n composite and factored?
    yes:
        solve modulo each prime power
        combine all roots with CRT

Is n RSA-like and gcd(e, phi(n)) = 1?
    yes -> compute d = e^-1 mod phi(n), then x = y^d mod n

Is x known to be small or in a narrow interval?
    yes -> brute force, lift y + k*n, or use Coppersmith

Are there several equations involving the same x?
    yes -> check common modulus, broadcast, shared primes,
           related messages, and GCD tricks

Otherwise:
    reversing pow may be as hard as factoring or discrete logarithms
```

---

# 2. Helper functions

```python
from __future__ import annotations

from math import gcd, isqrt
from typing import Iterable

from sympy import integer_nthroot


def exact_nth_root(value: int, exponent: int) -> int | None:
    root, exact = integer_nthroot(value, exponent)
    return int(root) if exact else None


def inv(value: int, modulus: int) -> int:
    return pow(value, -1, modulus)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def int_to_bytes(value: int) -> bytes:
    if value == 0:
        return b"\x00"
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0

    g, x1, y1 = extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def signed_mod_pow(base: int, exponent: int, modulus: int) -> int:
    if exponent >= 0:
        return pow(base, exponent, modulus)

    return pow(pow(base, -1, modulus), -exponent, modulus)
```

Install useful libraries:

```bash
python -m pip install pycryptodome sympy gmpy2
```

---

# 3. Case A: no modulus

Given:

```python
y = x**e
```

Recover `x` with an exact integer root.

```python
from sympy import integer_nthroot

y = ...
e = ...

x, exact = integer_nthroot(y, e)

if exact:
    print("x =", x)
else:
    print("y is not a perfect e-th power")
```

With `gmpy2`:

```python
from gmpy2 import iroot

x, exact = iroot(y, e)
print(int(x), bool(exact))
```

Never use floating-point roots for large integers:

```python
# Wrong for large cryptographic integers:
x = round(y ** (1 / e))
```

---

# 4. Case B: modular exponentiation did not wrap

Even when the code says:

```python
y = pow(x, e, n)
```

if:

```text
x^e < n
```

then:

```text
y = x^e
```

as an ordinary integer.

```python
from sympy import integer_nthroot

x, exact = integer_nthroot(y, e)

if exact and pow(x, e, n) == y:
    print("Recovered:", x)
```

This is the classic unpadded small-exponent RSA mistake.

A useful size test:

```python
print("y bits:", y.bit_length())
print("n bits:", n.bit_length())
```

For RSA with small `e`, a short message can satisfy `m**e < n`.

---

# 5. Case C: search `x^e = y + k*n`

If modular reduction occurred only a small number of times:

```text
x^e = y + k*n
```

Try small `k`.

```python
from sympy import integer_nthroot

y = ...
e = ...
n = ...

MAX_K = 1_000_000

for k in range(MAX_K):
    candidate_power = y + k * n
    x, exact = integer_nthroot(candidate_power, e)

    if exact:
        x = int(x)

        if pow(x, e, n) == y:
            print("k =", k)
            print("x =", x)
            break
else:
    print("No root found in range")
```

This works when `x` is small enough that `k` stays manageable.

Estimate `k` when you know an upper bound `X`:

```python
max_k = (X**e - y) // n
```

---

# 6. Case D: prime modulus and invertible exponent

Suppose:

```text
y = x^e mod p
```

where `p` is prime and `x != 0`.

Nonzero values modulo `p` form a group of size:

```text
p - 1
```

If:

```text
gcd(e, p - 1) = 1
```

then `e` has an inverse modulo `p - 1`.

```python
from math import gcd

p = ...
e = ...
y = ...

if gcd(e, p - 1) != 1:
    raise ValueError("Exponent is not invertible modulo p - 1")

d = pow(e, -1, p - 1)
x = pow(y, d, p)

assert pow(x, e, p) == y
print(x)
```

Why it works:

```text
d*e = 1 + k(p-1)
x^(de) = x * (x^(p-1))^k = x mod p
```

by Fermat's little theorem.

The special case `x = 0` maps to `y = 0`.

---

# 7. Prime modulus when `gcd(e, p-1) > 1`

Now exponentiation is not one-to-one.

There may be:

- No roots
- Several roots

For moderate-size values, use SymPy:

```python
from sympy.ntheory.residue_ntheory import nthroot_mod

p = ...
e = ...
y = ...

roots = nthroot_mod(y, e, p, all_roots=True)

print("roots:", roots)

for x in roots:
    assert pow(x, e, p) == y
```

The number of nonzero roots, when roots exist, is often related to:

```python
g = gcd(e, p - 1)
```

A necessary condition for nonzero `y` to be an `e`-th power is:

```python
pow(y, (p - 1) // g, p) == 1
```

Check:

```python
from math import gcd

g = gcd(e, p - 1)

if y == 0:
    print("x = 0 is a root")
elif pow(y, (p - 1) // g, p) != 1:
    print("No nonzero e-th root exists")
else:
    print("A root may exist")
```

This condition is sufficient in the cyclic group modulo a prime.

---

# 8. Modular square roots

The most common non-invertible exponent is:

```python
y = pow(x, 2, p)
```

## Use SymPy

```python
from sympy import sqrt_mod

p = ...
y = ...

roots = sqrt_mod(y, p, all_roots=True)
print(roots)
```

For an odd prime, a nonzero quadratic residue normally has two roots:

```text
x and -x mod p
```

```python
root2 = (-root1) % p
```

## Fast formula when `p % 4 == 3`

```python
if p % 4 != 3:
    raise ValueError("This shortcut requires p % 4 == 3")

x = pow(y, (p + 1) // 4, p)

if pow(x, 2, p) == y:
    print(x, (-x) % p)
else:
    print("No square root")
```

## Legendre-symbol test

For odd prime `p` and nonzero `y`:

```python
legendre = pow(y, (p - 1) // 2, p)

if legendre == 1:
    print("quadratic residue")
elif legendre == p - 1:
    print("quadratic non-residue")
else:
    print("y is zero modulo p")
```

---

# 9. Tonelli-Shanks implementation

Use this when `p` is an odd prime and you want square roots without SymPy.

```python
def tonelli_shanks(n: int, p: int) -> int | None:
    """
    Return one square root of n modulo odd prime p,
    or None when no root exists.
    """
    n %= p

    if n == 0:
        return 0

    if p == 2:
        return n

    # Euler criterion
    if pow(n, (p - 1) // 2, p) != 1:
        return None

    # Fast case
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)

    # Write p - 1 = q * 2^s with q odd
    q = p - 1
    s = 0

    while q % 2 == 0:
        q //= 2
        s += 1

    # Find a quadratic non-residue z
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1

    m = s
    c = pow(z, q, p)
    t = pow(n, q, p)
    r = pow(n, (q + 1) // 2, p)

    while t != 1:
        i = 1
        t2i = pow(t, 2, p)

        while t2i != 1:
            t2i = pow(t2i, 2, p)
            i += 1

            if i == m:
                return None

        b = pow(c, 1 << (m - i - 1), p)
        r = (r * b) % p
        t = (t * b * b) % p
        c = (b * b) % p
        m = i

    return r


p = ...
y = ...

r = tonelli_shanks(y, p)

if r is None:
    print("No roots")
else:
    print(r, (-r) % p)
```

---

# 10. Solve via discrete logarithms

For prime `p`, choose a generator `g` and write:

```text
x = g^a
y = g^b
```

Then:

```text
e*a = b mod (p-1)
```

If you can compute:

```text
b = log_g(y)
```

you can solve the linear congruence for `a`.

This is mainly useful when `p - 1` is smooth or small enough for a discrete log.

```python
from math import gcd
from sympy import discrete_log, primitive_root

p = ...
e = ...
y = ...

g = primitive_root(p)
b = discrete_log(p, y, g)

modulus = p - 1
d = gcd(e, modulus)

if b % d != 0:
    print("No roots")
else:
    e_reduced = e // d
    b_reduced = b // d
    modulus_reduced = modulus // d

    a0 = (
        b_reduced
        * pow(e_reduced, -1, modulus_reduced)
    ) % modulus_reduced

    roots = {
        pow(g, a0 + k * modulus_reduced, p)
        for k in range(d)
    }

    roots = sorted(
        x for x in roots
        if pow(x, e, p) == y
    )

    print(roots)
```

For cryptographic-size safe groups, the discrete logarithm is intended to be hard.

---

# 11. Case E: RSA modulus with known factors

Suppose:

```text
n = p*q
y = x^e mod n
```

and `p`, `q` are known.

## Standard RSA case

When:

```text
gcd(e, phi(n)) = 1
```

compute the private exponent:

```python
from math import gcd

p = ...
q = ...
n = p * q
e = ...
y = ...

phi = (p - 1) * (q - 1)

if gcd(e, phi) != 1:
    raise ValueError("e is not invertible modulo phi(n)")

d = pow(e, -1, phi)
x = pow(y, d, n)

assert pow(x, e, n) == y
print(x)
```

For multi-prime RSA:

```python
from math import prod

primes = [p, q, r]
n = prod(primes)
phi = prod(prime - 1 for prime in primes)
```

For repeated prime factors, use:

```text
phi(p^k) = p^(k-1) * (p-1)
```

---

# 12. Use Carmichael's lambda instead of phi

For distinct odd primes:

```text
lambda(n) = lcm(p-1, q-1)
```

```python
from math import gcd, lcm

lam = lcm(p - 1, q - 1)

if gcd(e, lam) != 1:
    raise ValueError("e is not invertible modulo lambda(n)")

d = pow(e, -1, lam)
x = pow(y, d, n)
```

Using `lambda(n)` often gives the smallest correct exponent modulus.

---

# 13. RSA CRT decryption

This is equivalent to `pow(y, d, n)` but useful for learning and debugging.

```python
from Crypto.Util.number import inverse

p = ...
q = ...
n = p * q
e = ...
y = ...

dp = pow(e, -1, p - 1)
dq = pow(e, -1, q - 1)

mp = pow(y, dp, p)
mq = pow(y, dq, q)

q_inv = inverse(q, p)
h = ((mp - mq) * q_inv) % p
x = mq + h * q

assert x % p == mp
assert x % q == mq
assert pow(x, e, n) == y

print(x)
```

This assumes `e` is invertible modulo both `p-1` and `q-1`.

---

# 14. Composite modulus with multiple roots

If `e` is not invertible, solve modulo each factor and combine every root with CRT.

Example for square roots modulo `n = p*q`:

```python
from itertools import product
from sympy import sqrt_mod
from sympy.ntheory.modular import crt

p = ...
q = ...
n = p * q
y = ...

roots_p = sqrt_mod(y, p, all_roots=True)
roots_q = sqrt_mod(y, q, all_roots=True)

roots_n = []

for rp, rq in product(roots_p, roots_q):
    value, modulus = crt([p, q], [rp, rq])
    x = int(value % modulus)

    if pow(x, 2, n) == y % n:
        roots_n.append(x)

print(sorted(set(roots_n)))
```

For two distinct odd primes and an invertible quadratic residue, there are usually four roots modulo `n`.

General `e`-th roots:

```python
from itertools import product
from sympy.ntheory.modular import crt
from sympy.ntheory.residue_ntheory import nthroot_mod

p = ...
q = ...
e = ...
y = ...

roots_p = nthroot_mod(y, e, p, all_roots=True)
roots_q = nthroot_mod(y, e, q, all_roots=True)

roots = set()

for rp, rq in product(roots_p, roots_q):
    value, modulus = crt([p, q], [rp, rq])
    x = int(value % modulus)

    if pow(x, e, p * q) == y % (p * q):
        roots.add(x)

print(sorted(roots))
```

---

# 15. General CRT combiner

```python
from itertools import product
from sympy.ntheory.modular import crt


def combine_root_sets(
    moduli: list[int],
    root_sets: list[list[int]],
) -> list[int]:
    solutions = set()

    for residues in product(*root_sets):
        value, modulus = crt(moduli, residues)

        if value is not None:
            solutions.add(int(value % modulus))

    return sorted(solutions)
```

Usage:

```python
moduli = [p, q, r]
root_sets = [
    roots_mod_p,
    roots_mod_q,
    roots_mod_r,
]

roots_mod_n = combine_root_sets(moduli, root_sets)
```

---

# 16. Prime powers and Hensel lifting

If:

```text
n = p^k
```

you may need to lift roots modulo `p` to roots modulo `p^k`.

For:

```text
f(x) = x^e - y
```

a simple root `r mod p` satisfies:

```text
f(r) = 0 mod p
f'(r) != 0 mod p
```

where:

```text
f'(x) = e*x^(e-1)
```

Then the root normally lifts uniquely.

A simple one-digit-at-a-time lifting method:

```python
def hensel_lift_roots(
    roots_mod_p: list[int],
    p: int,
    power: int,
    exponent: int,
    target: int,
) -> list[int]:
    """
    Brute-force each new base-p digit.
    Good for learning and modest p.
    """
    roots = [root % p for root in roots_mod_p]
    modulus = p

    for _ in range(1, power):
        next_modulus = modulus * p
        lifted = []

        for root in roots:
            for digit in range(p):
                candidate = root + digit * modulus

                if (
                    pow(candidate, exponent, next_modulus)
                    == target % next_modulus
                ):
                    lifted.append(candidate)

        roots = sorted(set(lifted))
        modulus = next_modulus

    return roots
```

This becomes slow when `p` is large. Use algebraic Hensel lifting or a CAS for serious prime-power problems.

---

# 17. Brute force a small base

If `x` lies in a small range:

```python
y = ...
e = ...
n = ...

LOW = 0
HIGH = 1_000_000

for x in range(LOW, HIGH):
    if pow(x, e, n) == y:
        print("x =", x)
        break
else:
    print("No solution in range")
```

Use known flag structure:

```python
from Crypto.Util.number import bytes_to_long

prefix = bytes_to_long(b"flag{")
```

For full byte strings, brute-force only the unknown portion rather than the entire integer.

```python
from itertools import product
from string import printable

known_prefix = b"flag{"
known_suffix = b"}"
alphabet = b"0123456789abcdef"

for middle_tuple in product(alphabet, repeat=4):
    message = known_prefix + bytes(middle_tuple) + known_suffix
    x = int.from_bytes(message, "big")

    if pow(x, e, n) == y:
        print(message)
        break
```

---

# 18. Meet-in-the-middle for structured messages

Suppose the unknown is composed of two smaller parts and the equation can be rearranged into a separable form. A meet-in-the-middle attack can reduce:

```text
O(2^k)
```

work to roughly:

```text
O(2^(k/2))
```

The exact algebra depends on the challenge.

Typical pattern:

```python
left_table = {}

for left in possible_left_values:
    value = compute_left_expression(left)
    left_table[value] = left

for right in possible_right_values:
    target_value = compute_matching_expression(right)

    if target_value in left_table:
        print(left_table[target_value], right)
```

Plain RSA exponentiation does not automatically split this way, but custom CTF constructions often do.

---

# 19. Factor `n` first

For RSA-like problems, recovering `x` often reduces to factoring `n`.

## Trial division

```python
from math import isqrt

def trial_factor(n: int) -> int | None:
    if n % 2 == 0:
        return 2

    for candidate in range(3, isqrt(n) + 1, 2):
        if n % candidate == 0:
            return candidate

    return None
```

Only useful for small factors.

## Fermat factorization

Effective when `p` and `q` are close.

```python
from math import isqrt


def fermat_factor(n: int) -> tuple[int, int] | None:
    if n % 2 == 0:
        return 2, n // 2

    a = isqrt(n)

    if a * a < n:
        a += 1

    while True:
        b2 = a * a - n
        b = isqrt(b2)

        if b * b == b2:
            p = a - b
            q = a + b
            return p, q

        a += 1
```

Add a search limit in untrusted scripts.

## Pollard rho through SymPy

```python
from sympy import factorint

factors = factorint(n)
print(factors)
```

## Pollard p-1 clue

Useful when a prime factor `p` has smooth `p-1`.

```python
from sympy.ntheory.factor_ import pollard_pm1

factor = pollard_pm1(n, B=100_000)
print(factor)
```

---

# 20. Shared-prime GCD attack

If two RSA moduli reuse a prime:

```text
n1 = p*q1
n2 = p*q2
```

then:

```python
from math import gcd

p = gcd(n1, n2)

if 1 < p < n1:
    q1 = n1 // p
    q2 = n2 // p

    print("shared prime:", p)
```

For many moduli:

```python
from math import gcd

moduli = [...]

for i in range(len(moduli)):
    for j in range(i + 1, len(moduli)):
        factor = gcd(moduli[i], moduli[j])

        if 1 < factor < moduli[i]:
            print(i, j, factor)
```

After factoring, compute the private exponent normally.

---

# 21. GCD from an algebraic relation

A challenge may reveal values that are equal modulo an unknown factor.

If:

```text
A = B mod p
```

then:

```text
p divides A - B
```

So:

```python
from math import gcd

factor = gcd(A - B, n)
```

Examples:

```python
factor = gcd(pow(m, e, n) - c, n)
factor = gcd(a * b - c, n)
factor = gcd(x1 - x2, n)
```

For a sequence of modular powers:

```text
a_i = x^i mod p
```

the relation:

```text
a_i * a_(i+2) - a_(i+1)^2 = 0 mod p
```

means `p` divides each determinant-like value.

```python
from math import gcd

values = []

for i in range(len(sequence) - 2):
    relation = (
        sequence[i] * sequence[i + 2]
        - sequence[i + 1] ** 2
    )
    values.append(abs(relation))

candidate = 0

for value in values:
    candidate = gcd(candidate, value)

print(candidate)
```

The GCD may be:

- `p`
- A multiple of `p`
- Zero when all exact relations are zero
- Contaminated by extra common factors

Factor or validate the result.

---

# 22. Common-modulus attack

Same plaintext `m`, same modulus `n`, different exponents:

```text
c1 = m^e1 mod n
c2 = m^e2 mod n
```

If:

```text
gcd(e1, e2) = 1
```

find Bézout coefficients:

```text
a*e1 + b*e2 = 1
```

Then:

```text
m = c1^a * c2^b mod n
```

```python
from math import gcd


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0

    g, x1, y1 = extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def signed_mod_pow(base: int, exponent: int, modulus: int) -> int:
    if exponent >= 0:
        return pow(base, exponent, modulus)

    inverse = pow(base, -1, modulus)
    return pow(inverse, -exponent, modulus)


n = ...
e1 = ...
e2 = ...
c1 = ...
c2 = ...

g, a, b = extended_gcd(e1, e2)

if g != 1:
    raise ValueError("Exponents must be coprime for the direct attack")

m = (
    signed_mod_pow(c1, a, n)
    * signed_mod_pow(c2, b, n)
) % n

assert pow(m, e1, n) == c1
assert pow(m, e2, n) == c2

print(m)
```

Negative exponents require the ciphertext to be invertible modulo `n`. If inversion fails, the GCD may directly reveal a factor of `n`.

```python
from math import gcd

factor = gcd(c1, n)
```

---

# 23. Håstad broadcast attack

Same unpadded message `m`, same small exponent `e`, different pairwise-coprime moduli:

```text
c_i = m^e mod n_i
```

With at least `e` suitable moduli, CRT can reconstruct the exact integer `m^e`.

```python
from sympy import integer_nthroot
from sympy.ntheory.modular import crt

moduli = [n1, n2, n3]
ciphertexts = [c1, c2, c3]
e = 3

combined, combined_modulus = crt(moduli, ciphertexts)
combined = int(combined)

m, exact = integer_nthroot(combined, e)

if exact:
    m = int(m)
    print(m)
else:
    print("Root was not exact")
```

Requirements:

- Same exact message
- Same exponent
- No randomized secure padding
- Pairwise-coprime moduli
- Product of moduli large enough that `m^e` is reconstructed without wraparound

---

# 24. Common modulus with non-coprime exponents

If:

```text
g = gcd(e1, e2) > 1
```

Bézout gives:

```text
m^g mod n
```

rather than `m`.

You may then recover `m` if:

- `m^g < n`, so an exact root works
- The factors of `n` are known and modular `g`-th roots are computable
- Additional equations remove the ambiguity

```python
from math import gcd
from sympy import integer_nthroot

g = gcd(e1, e2)

# Use extended GCD on e1/g and e2/g to recover m^g mod n.
# Then attempt an exact g-th root if no wraparound occurred.
```

---

# 25. Wiener attack for small RSA private exponent

If `d` is unusually small, continued fractions of `e/n` may recover it.

```python
from math import isqrt


def continued_fraction(numerator: int, denominator: int) -> list[int]:
    terms = []

    while denominator:
        terms.append(numerator // denominator)
        numerator, denominator = (
            denominator,
            numerator % denominator,
        )

    return terms


def convergents(terms: list[int]):
    p_prev2, p_prev1 = 0, 1
    q_prev2, q_prev1 = 1, 0

    for term in terms:
        p = term * p_prev1 + p_prev2
        q = term * q_prev1 + q_prev2

        yield p, q

        p_prev2, p_prev1 = p_prev1, p
        q_prev2, q_prev1 = q_prev1, q


def wiener_attack(e: int, n: int) -> int | None:
    for k, d in convergents(continued_fraction(e, n)):
        if k == 0:
            continue

        # ed - 1 = k*phi
        if (e * d - 1) % k != 0:
            continue

        phi = (e * d - 1) // k
        s = n - phi + 1

        discriminant = s * s - 4 * n

        if discriminant < 0:
            continue

        root = isqrt(discriminant)

        if root * root != discriminant:
            continue

        if (s + root) % 2 != 0:
            continue

        p = (s + root) // 2
        q = (s - root) // 2

        if p * q == n:
            return d

    return None


d = wiener_attack(e, n)

if d is not None:
    m = pow(c, d, n)
    print(m)
```

Wiener's attack has mathematical bounds; it is not a generic small-`d` solver.

---

# 26. Related-message attacks

## Franklin-Reiter idea

If two RSA plaintexts are linearly related:

```text
m2 = a*m1 + b
```

and encrypted with the same small exponent and modulus:

```text
c1 = m1^e mod n
c2 = (a*m1+b)^e mod n
```

then the two modular polynomials share a root. Their polynomial GCD can reveal `m1`.

This is commonly solved in SageMath:

```python
# SageMath

ZmodN = Zmod(n)
R.<x> = PolynomialRing(ZmodN)

f1 = x^e - c1
f2 = (a*x + b)^e - c2

g = f1.gcd(f2)

print(g)
```

When the GCD is linear:

```text
x - m
```

read off the plaintext.

Polynomial arithmetic over `Z/nZ` can fail when a coefficient is not invertible. Sometimes that failure itself leaks a factor of `n`.

---

# 27. Coppersmith small-root attacks

Coppersmith methods recover small roots of modular polynomial equations.

Typical CTF patterns:

- Most bits of `x` are known
- A short suffix or prefix is unknown
- `x` is smaller than a bound
- Related RSA messages differ by a small value
- Part of `p` or `q` is known
- Partial private key exposure

Typical SageMath skeleton:

```python
# SageMath

N = ...
e = ...
c = ...

known = ...
shift = ...

PR.<x> = PolynomialRing(Zmod(N))
f = (known + x)^e - c

roots = f.small_roots(
    X=2^shift,
    beta=1.0,
)

print(roots)
```

The polynomial must model the exact encoding of the unknown bits.

Coppersmith is not magic brute force. Success depends on degree, modulus structure, and the root-size bound.

---

# 28. Known prefix or suffix

Suppose:

```text
m = known_prefix * 256^k + unknown
```

where `unknown < 256^k`.

```python
known_prefix_int = int.from_bytes(b"flag{known_", "big")
k = 8

base = known_prefix_int << (8 * k)
```

Then:

```text
m = base + x
0 <= x < 2^(8k)
```

This is a standard univariate Coppersmith setup for small enough `x`.

For a known suffix:

```text
m = x*256^k + known_suffix
```

Model that exact polynomial.

---

# 29. Recover a factor from known bits

When high or low bits of a prime factor are known:

```text
p = known_part + x
```

and `x` is sufficiently small, Coppersmith may recover `x` from:

```text
p divides n
```

Typical SageMath structure:

```python
# SageMath sketch

N = ...
known_high = ...
unknown_bits = ...

PR.<x> = PolynomialRing(Zmod(N))
f = known_high * 2^unknown_bits + x

roots = f.small_roots(
    X=2^unknown_bits,
    beta=0.5,
)

print(roots)
```

The exact successful bounds depend on how much of the factor is known.

---

# 30. Special structure in factors

CTF RSA factors are often generated with exploitable algebra.

Examples:

```text
q = p^2 + p + 1
q = next_prime(p)
q = a*p + b
p and q share many high bits
p - 1 is smooth
p and q are too close
```

Do not brute-force a 512-bit prime merely because the source says `getPrime(512)`.

Instead:

1. Write the algebraic relation.
2. Estimate bit lengths.
3. Substitute into `n`.
4. Solve the resulting integer polynomial or factor relation.
5. Validate candidate factors with `n % p == 0`.

Example:

```text
n = p * (p^2 + p + 1) * r
```

The challenge may leak enough information to isolate the structured factor, use a GCD, or derive a polynomial with a small root.

---

# 31. Recover a sequence base

Given successive powers modulo unknown prime `p`:

```text
a0 = x^k mod p
a1 = x^(k+1) mod p
a2 = x^(k+2) mod p
...
```

Relations eliminate `x`:

```text
a_i*a_(i+2) - a_(i+1)^2 = 0 mod p
```

Recover a multiple of `p`:

```python
from math import gcd

arr = [...]

g = 0

for i in range(len(arr) - 2):
    value = arr[i] * arr[i + 2] - arr[i + 1] ** 2
    g = gcd(g, abs(value))

print("GCD candidate:", g)
```

Factor `g`, then test prime candidates:

```python
from sympy import factorint, isprime

for candidate in factorint(g):
    if not isprime(candidate):
        continue

    if all(
        (
            arr[i] * arr[i + 2]
            - arr[i + 1] ** 2
        ) % candidate == 0
        for i in range(len(arr) - 2)
    ):
        print("possible p:", candidate)
```

Once `p` is known and `arr[0]` is invertible:

```python
x = arr[1] * pow(arr[0], -1, p) % p
```

because:

```text
a1 / a0 = x^(k+1) / x^k = x mod p
```

Validate:

```python
for i in range(len(arr) - 1):
    assert arr[i] * x % p == arr[i + 1]
```

---

# 32. Unknown exponent is a different problem

Given:

```python
y = pow(g, x, p)
```

and you want the exponent `x`, this is a **discrete logarithm**, not a modular root.

For small/moderate groups:

```python
from sympy import discrete_log

x = discrete_log(p, y, g)
print(x)
```

Baby-step giant-step:

```python
from math import isqrt


def bsgs(g: int, y: int, p: int) -> int | None:
    """
    Solve g^x = y mod p when a solution is in the expected group.
    Uses O(sqrt(p)) memory/time in the worst case.
    """
    m = isqrt(p - 1) + 1

    table = {}
    value = 1

    for j in range(m):
        table.setdefault(value, j)
        value = value * g % p

    factor = pow(pow(g, m, p), -1, p)
    gamma = y

    for i in range(m + 1):
        if gamma in table:
            x = i * m + table[gamma]

            if pow(g, x, p) == y:
                return x

        gamma = gamma * factor % p

    return None
```

For safe cryptographic groups, discrete log is supposed to be infeasible.

Check whether the group order is smooth; Pohlig-Hellman can then reduce the problem to smaller subgroups.

---

# 33. Reverse a negative modular exponent

Python allows:

```python
pow(a, -1, n)
```

when `a` is invertible modulo `n`.

More generally:

```python
pow(a, -k, n)
```

means:

```text
(a^-1)^k mod n
```

```python
result = pow(a, -k, n)
```

If it raises:

```text
ValueError: base is not invertible for the given modulus
```

then:

```python
from math import gcd

factor = gcd(a, n)
print(factor)
```

For RSA moduli, this can reveal a nontrivial factor.

---

# 34. Exploit invalid roots and validation failures

Always validate a recovered candidate:

```python
assert pow(candidate, e, n) == y % n
```

For byte messages, also check:

```python
message = int_to_bytes(candidate)
print(message)
```

Useful filters:

```python
def looks_like_flag(data: bytes) -> bool:
    lowered = data.lower()

    return any(
        marker in lowered
        for marker in (
            b"flag{",
            b"ctf{",
            b"crypto{",
            b"picoctf{",
            b"htb{",
        )
    )
```

When several modular roots exist, the flag format often identifies the correct one.

---

# 35. Multi-root decoder

```python
def int_to_bytes(value: int) -> bytes:
    length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, "big")


def rank_candidate(value: int) -> tuple[float, bytes]:
    data = int_to_bytes(value)

    printable = sum(
        32 <= byte <= 126 or byte in (9, 10, 13)
        for byte in data
    )

    ratio = printable / len(data)
    return ratio, data


roots = [...]

for root in sorted(roots, key=lambda x: rank_candidate(x)[0], reverse=True):
    ratio, data = rank_candidate(root)
    print(f"{ratio:.2%}", repr(data))
```

---

# 36. Rabin cryptosystem

Rabin encryption is:

```text
c = m^2 mod n
```

with:

```text
n = p*q
```

Decrypt by finding square roots modulo `p` and `q`, then combining them. This produces four candidates.

When:

```text
p % 4 == 3
q % 4 == 3
```

the roots are easy:

```python
from itertools import product
from sympy.ntheory.modular import crt

p = ...
q = ...
n = p * q
c = ...

rp = pow(c, (p + 1) // 4, p)
rq = pow(c, (q + 1) // 4, q)

roots_p = [rp, (-rp) % p]
roots_q = [rq, (-rq) % q]

candidates = set()

for xp, xq in product(roots_p, roots_q):
    value, modulus = crt([p, q], [xp, xq])
    candidates.add(int(value % modulus))

for candidate in candidates:
    print(candidate, int_to_bytes(candidate))
```

Rabin needs redundancy or formatting to identify the intended plaintext.

---

# 37. Low public exponent plus known padding structure

Textbook RSA may encode:

```text
m = prefix || unknown || suffix
```

and use small `e`.

Approaches:

- Exact root if `m^e < n`
- Search `c + k*n`
- Brute-force very short unknown sections
- Coppersmith for a sufficiently small unknown
- Franklin-Reiter when two related encodings are encrypted

Secure randomized padding such as OAEP is designed to prevent these attacks when correctly implemented.

---

# 38. Faulty RSA signatures

RSA signatures also use modular exponentiation:

```text
s = m^d mod n
```

A faulty CRT signature may leak a factor.

If `s_good` and `s_faulty` are signatures on the same message:

```python
from math import gcd

factor = gcd(s_good - s_faulty, n)
print(factor)
```

Another Bellcore-style relation can use:

```python
factor = gcd(pow(s_faulty, e, n) - m, n)
```

A nontrivial GCD factors `n`.

---

# 39. Chosen-ciphertext multiplicativity

Textbook RSA is multiplicative:

```text
Enc(m1) * Enc(m2) = Enc(m1*m2) mod n
```

If an oracle decrypts chosen ciphertexts, choose invertible `r`:

```text
c' = c * r^e mod n
```

The oracle returns:

```text
m' = m*r mod n
```

Then:

```text
m = m' * r^-1 mod n
```

```python
from math import gcd
from secrets import randbelow

while True:
    r = randbelow(n - 2) + 2

    if gcd(r, n) == 1:
        break

blinded_ciphertext = c * pow(r, e, n) % n

# Send blinded_ciphertext to the permitted challenge oracle.
m_blinded = ...

m = m_blinded * pow(r, -1, n) % n
print(m)
```

Real RSA encryption uses padding specifically to prevent direct textbook manipulation.

---

# 40. Smooth-order groups

For prime modulus `p`, the multiplicative group has order `p-1`.

If:

```text
p - 1
```

factors into small primes, then:

- Discrete logs may be easy via Pohlig-Hellman.
- Root extraction can be reduced to subgroup arithmetic.
- The challenge may expect factorization of the group order.

```python
from sympy import factorint

print(factorint(p - 1))
```

Likewise for elliptic-curve or custom groups, always inspect the group order.

---

# 41. Useful algebraic observations

## Same base, consecutive exponents

```text
a = x^k mod n
b = x^(k+1) mod n
```

If `a` is invertible:

```python
x = b * pow(a, -1, n) % n
```

If inversion fails:

```python
from math import gcd

factor = gcd(a, n)
print(factor)
```

## Known multiplier

```text
y = (a*x)^e mod n
```

If `a` is invertible and you can recover `a*x`, multiply by `a^-1`.

## Exponent factors

If:

```text
e = a*b
```

then:

```text
x^e = (x^a)^b
```

Sometimes the challenge leaks an intermediate root or makes one stage easy.

## Difference of powers

```text
x^a - x^b = x^b(x^(a-b)-1)
```

GCDs involving such expressions can reveal group-order information or factors.

---

# 42. Modular linear equations after taking logs

A general linear congruence:

```text
a*x = b mod m
```

has solutions only when:

```text
gcd(a, m) divides b
```

Solver:

```python
from math import gcd


def solve_linear_congruence(
    a: int,
    b: int,
    modulus: int,
) -> list[int]:
    d = gcd(a, modulus)

    if b % d != 0:
        return []

    a_reduced = a // d
    b_reduced = b // d
    modulus_reduced = modulus // d

    x0 = (
        b_reduced
        * pow(a_reduced, -1, modulus_reduced)
    ) % modulus_reduced

    return [
        (x0 + k * modulus_reduced) % modulus
        for k in range(d)
    ]
```

This is what appears after converting root extraction into exponent arithmetic in a cyclic group.

---

# 43. Full "try the easy cases" script

```python
from __future__ import annotations

from math import gcd
from sympy import integer_nthroot
from sympy.ntheory.residue_ntheory import nthroot_mod


def try_reverse_pow(
    y: int,
    e: int,
    n: int,
    *,
    prime_modulus: bool = False,
    max_lift: int = 100_000,
) -> set[int]:
    candidates: set[int] = set()

    # 1. No-wrap exact root
    root, exact = integer_nthroot(y, e)

    if exact:
        root = int(root)

        if pow(root, e, n) == y % n:
            candidates.add(root)

    # 2. Small modular lifts
    for k in range(1, max_lift + 1):
        root, exact = integer_nthroot(y + k * n, e)

        if exact:
            root = int(root)

            if pow(root, e, n) == y % n:
                candidates.add(root)

    # 3. Prime modulus, invertible exponent
    if prime_modulus and gcd(e, n - 1) == 1:
        d = pow(e, -1, n - 1)
        root = pow(y, d, n)

        if pow(root, e, n) == y % n:
            candidates.add(root)

    # 4. Prime modulus, general modular roots
    elif prime_modulus:
        try:
            roots = nthroot_mod(y, e, n, all_roots=True)

            for root in roots:
                root = int(root)

                if pow(root, e, n) == y % n:
                    candidates.add(root)
        except (ValueError, NotImplementedError):
            pass

    return candidates


y = ...
e = ...
n = ...

candidates = try_reverse_pow(
    y,
    e,
    n,
    prime_modulus=False,
    max_lift=10_000,
)

for candidate in sorted(candidates):
    print(candidate, int_to_bytes(candidate))
```

Do not set a huge `max_lift` without estimating whether the search is realistic.

---

# 44. SageMath mini-cheat-sheet

Run with:

```bash
sage solver.sage
```

## Modular inverse

```python
d = inverse_mod(e, modulus)
```

## Integer root

```python
root, exact = Integer(y).nth_root(e)
```

## Square roots modulo a prime

```python
R = Integers(p)
roots = R(y).sqrt(all=True)
```

## CRT

```python
x = crt([a, b], [p, q])
```

## Factorization

```python
factor(n)
```

## Discrete logarithm

```python
discrete_log(Mod(y, p), Mod(g, p))
```

## Polynomial GCD

```python
R.<x> = PolynomialRing(Zmod(n))
g = f1.gcd(f2)
```

## Small roots

```python
roots = f.small_roots(X=bound, beta=1.0)
```

SageMath is often the easiest environment for algebra-heavy CTF crypto.

---

# 45. What usually does not work

## Brute-forcing a random 512-bit base

A 512-bit space contains about:

```text
2^512
```

possibilities. That is not a realistic brute force.

Look for:

- Algebraic structure
- Small unknown pieces
- Reused values
- Factor leaks
- Smooth group order
- Close primes
- Shared primes
- Small exponents
- Missing padding
- Multiple related ciphertexts

## Floating-point roots

They lose precision on cryptographic integers.

## Inverting `e` modulo `n`

For:

```text
y = x^e mod p
```

the exponent is inverted modulo the group order, usually `p-1`, not modulo `p`.

For RSA, invert modulo `phi(n)` or `lambda(n)`, not modulo `n`.

## Assuming every modular root is unique

When `gcd(e, group_order) > 1`, several roots may exist.

## Ignoring zero and non-invertible values

Fermat/Euler group arguments apply to invertible elements. A failed modular inverse can reveal a factor.

---

# 46. Final checklist

When you see:

```python
pow(unknown, known_exponent, known_modulus)
```

ask:

1. Is the modulus prime?
2. Is the modulus factorable or already factored?
3. Is the exponent invertible modulo `p-1`, `phi(n)`, or `lambda(n)`?
4. Is the ciphertext an exact ordinary power?
5. Can I try `c + k*n` for small `k`?
6. Is the unknown base small or structurally constrained?
7. Are several ciphertexts using the same message?
8. Are several moduli sharing a prime?
9. Are exponents different but the modulus identical?
10. Is the same small exponent used across several moduli?
11. Are plaintexts linearly related?
12. Are some high or low bits known?
13. Are the factors close or algebraically related?
14. Is `p-1` or another group order smooth?
15. Does a failed inverse leak `gcd(value, n)`?
16. Are there successive modular powers that create determinant/GCD relations?
17. Is the unknown actually the exponent, making this a discrete-log problem?
18. Are there multiple roots, with a flag format selecting the right one?
19. Can a polynomial or small-root method model the unknown?
20. Have I validated every candidate with the original `pow()` equation?
