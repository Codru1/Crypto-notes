# Modular Arithmetic Notes for Crypto CTFs

These notes cover the topics shown in the screenshots:

- Greatest Common Divisor
- Extended GCD
- Modular arithmetic / congruences
- Finite fields
- Fermat's Little Theorem
- Modular inverses
- Quadratic residues
- Legendre symbol
- Python templates for solving CTF challenges

---

## 0. Python Commands to Memorize

```python
from math import gcd

x % n             # remainder of x divided by n
pow(a, b, n)      # a^b mod n, efficient
pow(a, -1, n)     # modular inverse of a mod n, Python 3.8+
gcd(a, b)         # greatest common divisor
```

For CTF crypto, always prefer:

```python
pow(a, b, n)
```

instead of:

```python
(a ** b) % n
```

because `pow(a, b, n)` is much faster for huge numbers.

---

# 1. Greatest Common Divisor, GCD

## Definition

The **greatest common divisor** of two positive integers `a` and `b` is the largest number that divides both of them.

It is written as:

```text
gcd(a, b)
```

Example:

```text
a = 12
b = 8

Divisors of 12: 1, 2, 3, 4, 6, 12
Divisors of 8:  1, 2, 4, 8

Common divisors: 1, 2, 4
Largest common divisor: 4

So gcd(12, 8) = 4
```

Python:

```python
from math import gcd

print(gcd(12, 8))  # 4
```

---

## Coprime Numbers

Two integers `a` and `b` are **coprime** if:

```text
gcd(a, b) = 1
```

Example:

```text
a = 11
b = 17

gcd(11, 17) = 1
```

So `11` and `17` are coprime.

Important facts:

```text
If a and b are both prime, they are coprime.
If a is prime and b < a, then a and b are coprime.
If a is prime and b > a, they are not necessarily coprime.
```

Why is the last one true?

Because `b` could be a multiple of `a`.

Example:

```text
a = 5
b = 10

gcd(5, 10) = 5
```

So they are **not** coprime.

---

## Euclidean Algorithm

The Euclidean Algorithm is a fast way to compute `gcd(a, b)`.

The rule is:

```text
gcd(a, b) = gcd(b, a mod b)
```

Repeat until the second number becomes `0`.

Example:

```text
gcd(12, 8)
= gcd(8, 12 mod 8)
= gcd(8, 4)
= gcd(4, 8 mod 4)
= gcd(4, 0)
= 4
```

Python implementation:

```python
def euclid_gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

print(euclid_gcd(12, 8))  # 4
```

Using Python's built-in function:

```python
from math import gcd

print(gcd(12, 8))  # 4
```

---

## Screenshot Challenge Answer

Challenge:

```text
gcd(66528, 52920)
```

Code:

```python
from math import gcd

print(gcd(66528, 52920))
```

Answer:

```text
1512
```

---

# 2. Extended GCD

## Main Idea

The **Extended Euclidean Algorithm** finds integers `u` and `v` such that:

```text
a*u + b*v = gcd(a, b)
```

This equation is called **Bézout's identity**.

Example:

```text
For a = 26513 and b = 32321:

26513*u + 32321*v = gcd(26513, 32321)
```

If `a` and `b` are prime and different, then:

```text
gcd(a, b) = 1
```

So we want:

```text
26513*u + 32321*v = 1
```

---

## Extended GCD Code

```python
def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0

    g, x1, y1 = extended_gcd(b, a % b)

    x = y1
    y = x1 - (a // b) * y1

    return g, x, y


a = 26513
b = 32321

g, u, v = extended_gcd(a, b)

print("gcd =", g)
print("u =", u)
print("v =", v)
print(a * u + b * v)
```

Output:

```text
gcd = 1
u = 10245
v = -8404
1
```

So:

```text
26513*10245 + 32321*(-8404) = 1
```

The screenshot asks for whichever of `u` and `v` is the lower number.

Answer:

```text
-8404
```

---

## Why Extended GCD Matters in Crypto

Extended GCD is used to calculate **modular inverses**.

If:

```text
a*x + m*y = 1
```

then:

```text
a*x ≡ 1 mod m
```

So:

```text
x ≡ a^(-1) mod m
```

This is extremely important in RSA because the private exponent `d` is calculated as:

```text
d ≡ e^(-1) mod phi(n)
```

---

# 3. Modular Arithmetic 1

## What Does `mod` Mean?

`a mod n` means the remainder after dividing `a` by `n`.

Example:

```text
11 mod 6 = 5
```

because:

```text
11 = 6*1 + 5
```

Python:

```python
print(11 % 6)  # 5
```

---

## Congruence

When we write:

```text
a ≡ b mod n
```

it means:

```text
a and b have the same remainder when divided by n
```

Example:

```text
11 ≡ 5 mod 6
```

because:

```text
11 % 6 = 5
5 % 6 = 5
```

---

## Clock Arithmetic Example

Modular arithmetic is like clock arithmetic.

On a 12-hour clock:

```text
4 + 9 = 13
13 mod 12 = 1
```

So:

```text
4 + 9 ≡ 1 mod 12
```

Also:

```text
5 - 7 = -2
-2 mod 12 = 10
```

So:

```text
5 - 7 ≡ 10 mod 12
```

---

## Screenshot Challenge Answer

Challenge:

```text
11 ≡ x mod 6
8146798528947 ≡ y mod 17
```

Code:

```python
x = 11 % 6
y = 8146798528947 % 17

print(x)
print(y)
print(min(x, y))
```

Output:

```text
5
4
4
```

The challenge asks for the smaller of `x` and `y`.

Answer:

```text
4
```

---

# 4. Modular Arithmetic 2: Finite Fields

## Integers Modulo `p`

If `p` is prime, the integers modulo `p` form a **finite field**, written as:

```text
F_p
```

The elements are:

```text
0, 1, 2, ..., p - 1
```

Example:

```text
F_7 = {0, 1, 2, 3, 4, 5, 6}
```

All calculations stay inside the field by reducing modulo `p`.

Example:

```text
5 + 6 = 11
11 mod 7 = 4
```

So in `F_7`:

```text
5 + 6 = 4
```

Python:

```python
p = 7
print((5 + 6) % p)  # 4
```

---

## Field vs Ring

If the modulus is prime, we get a **field**.

```text
mod p, where p is prime -> field
```

If the modulus is not prime, we get a **ring**.

```text
mod n, where n is composite -> ring
```

This matters because in a field, every non-zero element has a multiplicative inverse.

---

## Additive and Multiplicative Identities

The additive identity is `0`:

```text
a + 0 = a
```

The multiplicative identity is `1`:

```text
a * 1 = a
```

These are different because they belong to different operations.

---

## Additive Inverse

The additive inverse of `a` is the number that makes:

```text
a + b ≡ 0 mod p
```

Example in `mod 7`:

```text
3 + 4 = 7 ≡ 0 mod 7
```

So the additive inverse of `3 mod 7` is `4`.

Python:

```python
p = 7
a = 3
b = (-a) % p
print(b)  # 4
```

---

## Multiplicative Inverse

The multiplicative inverse of `a` is the number that makes:

```text
a * b ≡ 1 mod p
```

Example in `mod 7`:

```text
3 * 5 = 15 ≡ 1 mod 7
```

So:

```text
3^(-1) mod 7 = 5
```

Python:

```python
print(pow(3, -1, 7))  # 5
```

---

# 5. Fermat's Little Theorem

## The Theorem

If `p` is prime and `a` is not divisible by `p`, then:

```text
a^(p-1) ≡ 1 mod p
```

This is called **Fermat's Little Theorem**.

There is also a related form:

```text
a^p ≡ a mod p
```

---

## Small Examples

Let:

```text
p = 17
```

Then:

```python
print(pow(3, 17, 17))  # 3
print(pow(5, 17, 17))  # 5
print(pow(7, 16, 17))  # 1
```

Why?

Because:

```text
3^17 ≡ 3 mod 17
5^17 ≡ 5 mod 17
7^16 ≡ 1 mod 17
```

---

## Screenshot Challenge Answer

Challenge:

```text
p = 65537
Calculate 273246787654^65536 mod 65537
```

Since `65537` is prime and `273246787654` is not divisible by `65537`, Fermat's Little Theorem says:

```text
a^(p-1) ≡ 1 mod p
```

Here:

```text
p - 1 = 65536
```

So the answer is:

```text
1
```

Code:

```python
p = 65537
a = 273246787654

print(pow(a, p - 1, p))  # 1
```

---

# 6. Modular Inverting

## What Is a Modular Inverse?

The inverse of `g mod p` is a number `d` such that:

```text
g*d ≡ 1 mod p
```

It is written as:

```text
g^(-1) mod p
```

Example:

```text
7 * 8 = 56
56 mod 11 = 1
```

So:

```text
7^(-1) mod 11 = 8
```

---

## Screenshot Challenge

Find:

```text
d = 3^(-1) mod 13
```

We need:

```text
3*d ≡ 1 mod 13
```

Try values:

```text
3 * 1 = 3 mod 13
3 * 2 = 6 mod 13
3 * 3 = 9 mod 13
3 * 4 = 12 mod 13
3 * 5 = 15 ≡ 2 mod 13
3 * 6 = 18 ≡ 5 mod 13
3 * 7 = 21 ≡ 8 mod 13
3 * 8 = 24 ≡ 11 mod 13
3 * 9 = 27 ≡ 1 mod 13
```

So:

```text
3^(-1) mod 13 = 9
```

Answer:

```text
9
```

Python:

```python
print(pow(3, -1, 13))  # 9
```

---

## Modular Inverse Using Fermat

If `p` is prime:

```text
a^(p-1) ≡ 1 mod p
```

Divide both sides by `a`:

```text
a^(p-2) ≡ a^(-1) mod p
```

So:

```text
a^(-1) mod p = a^(p-2) mod p
```

Example:

```python
p = 13
a = 3

print(pow(a, p - 2, p))  # 9
```

---

## Modular Inverse Template

```python
from math import gcd


def mod_inverse(a, m):
    if gcd(a, m) != 1:
        raise ValueError("inverse does not exist")
    return pow(a, -1, m)


print(mod_inverse(3, 13))  # 9
```

---

# 7. Quadratic Residues

## Main Idea

A number `x` is a **quadratic residue modulo p** if there exists some `a` such that:

```text
a^2 ≡ x mod p
```

In simple words:

```text
x has a square root modulo p
```

If no such `a` exists, then `x` is a **quadratic non-residue**.

---

## Example Modulo 29

The screenshot gives:

```text
p = 29
a = 11
```

Calculate:

```text
11^2 = 121
121 mod 29 = 5
```

So:

```text
11^2 ≡ 5 mod 29
```

That means `5` is a quadratic residue modulo `29`, and one square root of `5` is `11`.

The other root is:

```text
-11 mod 29 = 18
```

because:

```text
18^2 mod 29 = 5
```

So roots usually come in pairs:

```text
a and -a mod p
```

---

## Brute Force Square Roots

For small `p`, just try every value.

```python
def sqrt_mod_bruteforce(x, p):
    roots = []
    for a in range(p):
        if (a * a) % p == x:
            roots.append(a)
    return roots


p = 29
print(sqrt_mod_bruteforce(5, p))   # [11, 18]
print(sqrt_mod_bruteforce(18, p))  # []
```

If the list is empty, `x` is a quadratic non-residue.

---

## Screenshot Challenge Answer

Challenge:

```text
p = 29
ints = [14, 6, 11]
```

Find which integer is a quadratic residue and submit the smaller square root.

Code:

```python
def sqrt_mod_bruteforce(x, p):
    return [a for a in range(p) if (a * a) % p == x]


p = 29
ints = [14, 6, 11]

for x in ints:
    roots = sqrt_mod_bruteforce(x, p)
    print(x, roots)
```

Output:

```text
14 []
6 [8, 21]
11 []
```

So the quadratic residue is:

```text
6
```

Its roots are:

```text
8 and 21
```

The smaller root is:

```text
8
```

Answer:

```text
8
```

---

# 8. Legendre Symbol

## Why We Need It

Brute forcing square roots is fine when `p` is small.

But if `p` is huge, like a 1024-bit prime, brute force is impossible.

The **Legendre symbol** tells us whether `a` is a quadratic residue modulo an odd prime `p`.

It is written as:

```text
(a / p)
```

---

## Legendre Symbol Values

For an odd prime `p`:

```text
(a / p) =  1  if a is a quadratic residue and a ≠ 0 mod p
(a / p) = -1  if a is a quadratic non-residue mod p
(a / p) =  0  if a ≡ 0 mod p
```

---

## Euler's Criterion

The useful formula is:

```text
(a / p) ≡ a^((p-1)/2) mod p
```

In Python:

```python
def legendre_symbol(a, p):
    result = pow(a, (p - 1) // 2, p)

    if result == p - 1:
        return -1
    return result
```

Why check `p - 1`?

Because in modular arithmetic:

```text
-1 mod p = p - 1
```

So Python returns `p - 1` instead of `-1`.

---

## Multiplication Rules

The screenshot gives this pattern:

```text
Quadratic Residue     * Quadratic Residue     = Quadratic Residue
Quadratic Residue     * Quadratic Non-residue = Quadratic Non-residue
Quadratic Non-residue * Quadratic Non-residue = Quadratic Residue
```

Easy memory trick:

```text
Quadratic Residue     -> +1
Quadratic Non-residue -> -1
```

Then the rules become normal sign multiplication:

```text
(+1) * (+1) = +1
(+1) * (-1) = -1
(-1) * (-1) = +1
```

---

# 9. Tonelli-Shanks: Square Root Mod Prime

The Legendre symbol tells us whether a square root exists.

To actually calculate the square root modulo a large prime, use **Tonelli-Shanks**.

This works for odd prime `p`.

---

## Full Tonelli-Shanks Code

```python
def legendre_symbol(a, p):
    """Return 1 if a is QR mod p, -1 if non-residue, 0 if a = 0 mod p."""
    a %= p
    if a == 0:
        return 0

    result = pow(a, (p - 1) // 2, p)
    if result == p - 1:
        return -1
    return result


def tonelli_shanks(n, p):
    """Return one square root of n modulo odd prime p, or None if no root exists."""
    n %= p

    if n == 0:
        return 0

    if p == 2:
        return n

    if legendre_symbol(n, p) != 1:
        return None

    # Fast case: p ≡ 3 mod 4
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)

    # Write p - 1 = q * 2^s with q odd
    q = p - 1
    s = 0
    while q % 2 == 0:
        s += 1
        q //= 2

    # Find a quadratic non-residue z
    z = 2
    while legendre_symbol(z, p) != -1:
        z += 1

    m = s
    c = pow(z, q, p)
    t = pow(n, q, p)
    r = pow(n, (q + 1) // 2, p)

    while t != 1:
        i = 1
        temp = pow(t, 2, p)
        while temp != 1:
            temp = pow(temp, 2, p)
            i += 1
            if i == m:
                return None

        b = pow(c, 2 ** (m - i - 1), p)
        m = i
        c = pow(b, 2, p)
        t = (t * c) % p
        r = (r * b) % p

    return r
```

---

## Large Legendre Challenge Template

The final screenshot says the challenge gives:

```text
A 1024-bit prime p
10 integers
```

and asks you to:

```text
1. Find the quadratic residue.
2. Calculate its square root.
3. Submit the larger of the two roots.
```

The exact `p` and integer list are not visible in the screenshot, so paste them into this template:

```python
def legendre_symbol(a, p):
    a %= p
    if a == 0:
        return 0

    result = pow(a, (p - 1) // 2, p)
    if result == p - 1:
        return -1
    return result


def tonelli_shanks(n, p):
    n %= p

    if n == 0:
        return 0

    if p == 2:
        return n

    if legendre_symbol(n, p) != 1:
        return None

    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)

    q = p - 1
    s = 0
    while q % 2 == 0:
        s += 1
        q //= 2

    z = 2
    while legendre_symbol(z, p) != -1:
        z += 1

    m = s
    c = pow(z, q, p)
    t = pow(n, q, p)
    r = pow(n, (q + 1) // 2, p)

    while t != 1:
        i = 1
        temp = pow(t, 2, p)
        while temp != 1:
            temp = pow(temp, 2, p)
            i += 1

        b = pow(c, 2 ** (m - i - 1), p)
        m = i
        c = pow(b, 2, p)
        t = (t * c) % p
        r = (r * b) % p

    return r


p = ...
ints = [
    ...,
    ...,
]

for x in ints:
    if legendre_symbol(x, p) == 1:
        print("quadratic residue:", x)

        root1 = tonelli_shanks(x, p)
        root2 = (-root1) % p

        print("root 1:", root1)
        print("root 2:", root2)
        print("larger root / flag:", max(root1, root2))
```

---

# 10. All Screenshot Answers Visible

These are the answers for the visible challenge data in the screenshots.

| Topic | Challenge | Answer |
|---|---:|---:|
| GCD | `gcd(66528, 52920)` | `1512` |
| Extended GCD | lower of `u=10245`, `v=-8404` | `-8404` |
| Modular Arithmetic 1 | smaller of `11 mod 6` and `8146798528947 mod 17` | `4` |
| Modular Arithmetic 2 | `273246787654^65536 mod 65537` | `1` |
| Modular Inverting | `3^(-1) mod 13` | `9` |
| Quadratic Residues | smaller root of the QR from `[14, 6, 11] mod 29` | `8` |
| Legendre Symbol | needs hidden/cropped 1024-bit values | use template above |

---

# 11. CTF Checklist

When you see modular arithmetic in a crypto challenge, ask:

```text
1. Do I need a remainder? Use %.
2. Do I need a power modulo n? Use pow(a, b, n).
3. Do I need an inverse? Use pow(a, -1, n) or Extended GCD.
4. Is the modulus prime? Then Fermat's Little Theorem may help.
5. Do I need a square root modulo p? Check Legendre symbol first.
6. Is p huge? Use Tonelli-Shanks instead of brute force.
```

---

# 12. Mini Practice

## Practice 1

Calculate:

```text
23 mod 7
```

Python:

```python
print(23 % 7)
```

Answer:

```text
2
```

---

## Practice 2

Find:

```text
5^(-1) mod 11
```

Python:

```python
print(pow(5, -1, 11))
```

Answer:

```text
9
```

because:

```text
5 * 9 = 45 ≡ 1 mod 11
```

---

## Practice 3

Check whether `10` is a quadratic residue modulo `13`.

Python:

```python
def roots(x, p):
    return [a for a in range(p) if a*a % p == x]

print(roots(10, 13))
```

Output:

```text
[6, 7]
```

So `10` is a quadratic residue modulo `13`.

---

# 13. Final Summary

The most important ideas:

```text
mod means remainder
congruence means same remainder
gcd(a, b) checks common factors
gcd(a, b) = 1 means coprime
Extended GCD solves a*u + b*v = gcd(a, b)
modular inverse means a*x ≡ 1 mod p
Fermat: a^(p-1) ≡ 1 mod p when p is prime
quadratic residue means x has a square root mod p
Legendre symbol checks whether a square root exists
Tonelli-Shanks calculates the square root for large prime p
```
