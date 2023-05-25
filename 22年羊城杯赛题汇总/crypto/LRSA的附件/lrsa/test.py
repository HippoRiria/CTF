import gmpy2
from pwn import *
from hashlib import sha256
import string
from Crypto.Util.number import *
from random import *


from Crypto.Util.number import *
import gmpy2
from flag import flag

m=bytes_to_long(flag)

def getPQ(p,q):
    P=getPrime(2048)
    Q=getPrime(2048)
    t=(p*P-58*P+q)%Q
    assert (isPrime(Q))
    return P,Q,t

B=getRandomNBitInteger(11)
p=getPrime(B)
q=getPrime(B)
n=p*q
e=65537
c=pow(m,e,n)
P,Q,t=getPQ(p,q)

print("B=",B)
print("P*P*Q=",P*P*Q)
print("P*Q*Q=",P*Q*Q)
print("t=",t)
print("c=",c)



