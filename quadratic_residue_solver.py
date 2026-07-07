# ============================================================
# ONLY CHANGE THIS PART
# ============================================================

p = 41

ints = [
    5,
    6,
    7,
    8,
    9,
    10,
]

# ============================================================
# DO NOT NEED TO CHANGE ANYTHING BELOW
# ============================================================


def legendre_symbol(a, p):
    """
    Returns:
     1  -> a is a quadratic residue mod p
    -1  -> a is NOT a quadratic residue mod p
     0  -> a ≡ 0 mod p
    """
    a %= p

    if a == 0:
        return 0

    result = pow(a, (p - 1) // 2, p)

    if result == 1:
        return 1
    elif result == p - 1:
        return -1
    else:
        return 0


def tonelli_shanks(a, p):
    """
    Finds one square root of a mod p.
    Works for odd prime p.
    """
    a %= p

    if a == 0:
        return 0

    if p == 2:
        return a

    if legendre_symbol(a, p) != 1:
        return None

    # Fast shortcut when p % 4 == 3
    if p % 4 == 3:
        return pow(a, (p + 1) // 4, p)

    # Write p - 1 = q * 2^s, where q is odd
    q = p - 1
    s = 0

    while q % 2 == 0:
        q //= 2
        s += 1

    # Find a quadratic non-residue z
    z = 2
    while legendre_symbol(z, p) != -1:
        z += 1

    # Initialize variables
    m = s
    c = pow(z, q, p)
    t = pow(a, q, p)
    r = pow(a, (q + 1) // 2, p)

    # Main loop
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


def sqrt_mod_prime(a, p):
    """
    Returns both square roots of a mod p.
    Returns None if no square root exists.
    """
    a %= p

    if a == 0:
        return 0, 0

    if legendre_symbol(a, p) != 1:
        return None

    if p % 4 == 3:
        root1 = pow(a, (p + 1) // 4, p)
    else:
        root1 = tonelli_shanks(a, p)

    if root1 is None:
        return None

    root2 = (-root1) % p

    return root1, root2


def check_quadratic_residues(ints, p):
    print("Prime p:")
    print(p)
    print()

    print("p % 4 =", p % 4)

    if p % 4 == 3:
        print("Using shortcut: root = a^((p+1)//4) mod p")
    else:
        print("Using Tonelli-Shanks when square roots are needed")

    print()
    print("=" * 60)
    print()

    for a in ints:
        symbol = legendre_symbol(a, p)

        if symbol == 1:
            roots = sqrt_mod_prime(a, p)

            if roots is None:
                print("[!] Something went wrong finding roots for:")
                print(a)
                print()
                continue

            root1, root2 = roots

            print("[+] Quadratic residue found")
            print("a =", a)
            print("root 1 =", root1)
            print("root 2 =", root2)
            print("smaller root =", min(root1, root2))
            print("larger root  =", max(root1, root2))

            print("check root 1:", pow(root1, 2, p) == a % p)
            print("check root 2:", pow(root2, 2, p) == a % p)

        elif symbol == -1:
            print("[-] Not a quadratic residue")
            print("a =", a)

        else:
            print("[0] a ≡ 0 mod p")
            print("a =", a)
            print("roots = 0, 0")

        print()
        print("-" * 60)
        print()


# Run the checker
check_quadratic_residues(ints, p)
