from math import gcd

N = ...
e1 = ...
e2 = ...
c1 = ...
c2 = ...

E = e1 * e2

x = (
    pow(7, E, N) * pow(c1, e2, N)
    - pow(3, E, N) * pow(c2, e1, N)
) % N

p = gcd(x, N)
q = N // p

print("p =", p)
print("q =", q)
print(f"crypto{{{p},{q}}}")

#N=p⋅q
#So if you can create a number that is divisible by p but not by q, then:
#gcd(that number,N)=p
