from math import gcd

arr = [588, 665, 216, 113, 642, 4, 836, 114, 851, 492, 819, 237]

# Step 1: recover p
# Since arr[i], arr[i+1], arr[i+2] are successive powers:
# arr[i] * arr[i+2] - arr[i+1]^2 is divisible by p

g = 0

for i in range(len(arr) - 2):
    value = arr[i] * arr[i + 2] - arr[i + 1] ** 2
    g = gcd(g, abs(value))

p = g

# Step 2: recover x
# arr[1] = arr[0] * x mod p
# so x = arr[1] / arr[0] mod p
# modular division means multiplying by inverse

x = arr[1] * pow(arr[0], -1, p) % p

# Step 3: verify

for i in range(len(arr) - 1):
    assert arr[i] * x % p == arr[i + 1]

print("p =", p)
print("x =", x)
print(f"crypto{{{p},{x}}}")
