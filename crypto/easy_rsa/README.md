# babyrsa

Author: Rahul Chunduru

## Statement

This is just RSA for babies!

## Exploit

For co-primes a, n, pow(a, phi(n), n) = 1
if p, q are primes, phi(n) = (p - 1) * (q - 1)

Therefore, the inverse of pow(a, n - p - q, n) is a.

Given, 

```
p, q = getPrime(1024), getPrime(1024)
n = p*q
e = 0x10001
s = pow(557*p - 127*q, n - p - q, n)
c = pow(bytes_to_long(flag), e, n)
```

Factorise n as,
```
s_inv = inverse(s, n)
## compute p,q from s_inv = 557*p - 127*q mod n, p*q
phi = (p - 1) * (q - 1)
d = inverse(e, phi)
m = pow(c, d, n)
```
The flag is

```
DUCTF{e4sy_RSA_ch4ll_t0_g3t_st4rt3d}
```