import time
from Crypto.Hash import SHA256, TupleHash128
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Random.random import getrandbits
from Crypto.Util.number import getPrime
from Crypto.Util.number import size
from sympy import Function, Symbol, expand


print("input m you need please")
m = int(input())


print("input t1 you need please(1<=t1<=m)")
t1 = int(input())


print("input t2 you need please(1<=t2<=n)")
t2 = int(input())


print("input n you need please")
n = int(input())


print("input the length of K,(per unit is 16B)")
K_length = int(input())

# 1.randomly and uniformly choose m 256bits random numbers si，i = 1~m.compute main Key S = s1*s2*...*sm.


s = []
P = getPrime(256)  #P is f(x) mod P

time_key_manager = []

def key_manager_step_1(m,s):
    #print("the first step of key manager has already run")
    start1 = time.perf_counter()
    S = 1
    for i in range(m):
        s.append(getrandbits(256))
        S = S * s[i] #S is main key
    end1 = time.perf_counter()
    time_key_manager.append(end1 - start1)
    #print("the first step of key manager needs(time ms)",end1 - start1)
    #print("the first step of key manager has finished")
    return S

x = Symbol('x')
def key_manager_step_2(m):

    # 2.compute a polynomial p(x)=(x - s1) * (x - s2)*...*(x - sm)
    #print("the second step of key manager has already run")
    start2 = time.perf_counter()
    p = Function('p')(x)
    p = 1
    for i in range(m):
        p = p * (x - s[i])
    p = expand(p)
    end2 = time.perf_counter()
    time_key_manager.append(end2 - start2)
    #print("the second step of key manager needs",end2 - start2)
    #print("the second step of key manager has finished")
    return p

# 3.output the coefficient of the polynomial p(x) from m-1 to t1 in turn

def key_manager_step_3(m):
    #print("the third step of key manager has run")
    start3 = time.perf_counter()
    SS = []
    for i in range(m-1, t1 -1,-1): #output the coefficient
        SS.append(key_manager_step_2(m).coeff(x, i))
    end3 = time.perf_counter()
    time_key_manager.append(end3 - start3)
    #print("the third step of key manager needs",end3 - start3)
    #print("the third step of key manager has finished")
    return SS

# 4.randomly and uniformly choose t2-1 random number ai, construct a polynomial f(x)= s + a1*x +...+a(t2-1)x^(t2-1) mod p
#Shamir's Secret Sharing Scheme

def key_manager_step_4():

    #print("the fourth step of key manager has run")
    start4 = time.perf_counter()
    a = [0]
    f = Function('f')(x)
    f = key_manager_step_1(m,s)   #S is main key
    for i in range(1, t2):
        a.append(getrandbits(16))
        f += pow(x, i) * a[i]
    end4 = time.perf_counter()
    time_key_manager.append(end4 - start4)
    #print("the fourth step of key manager needs",end4 - start4)
    #print("the fourth step of key manager has finished")
    return a

# 5.compute secret share si=s+a1*i+...+a(t2-1)*i^(t2-1),i=1,2,3,...,n,output si

def key_manager_step_5():

    #print("the fifth step of key manager has run")
    start5 = time.perf_counter()


    si = key_manager_step_1(m,s)
    Si = []   #si save in Si[] after computing,it is convenient for later calculation

    for i in range(1, n+1):
        for j in range(1, t2):
            si = si + key_manager_step_4()[j] * pow(i, j)
        Si.append(si%P)
        si = key_manager_step_1(m,s)
        j = 1
    end5 = time.perf_counter()
    time_key_manager.append(end5 - start5)
    #print("the fifth step of key manager needs",end5 - start5)
    #print("the fifth step of key manager has finished")
    return Si

# 6.using main key s as the input of pseudorandom number generator,let the output as key,encrypt key set to be managed K.the length of K depends on user's input, then compute Enc(s,K)。

key_RSA = RSA.generate(4096)
private_key = key_RSA.exportKey()
public_key = key_RSA.public_key().exportKey()

length = size(key_manager_step_1(m, s))
S_bytes = str(key_manager_step_1(m, s) % P).encode()
IV = get_random_bytes(16)
IV_AES128 = get_random_bytes(16)
K = get_random_bytes(K_length * 16)

def key_manager_step_6():

    #print("the sixth step of key manager has run")



    #AES256
    start6 = time.perf_counter()
    h = SHA256.new()
    h.update(S_bytes)
    cipher = AES.new(h.digest(), AES.MODE_CBC, IV)  #AES-256
    C = cipher.encrypt(K)
    end6 = time.perf_counter()
    time_key_manager.append(end6 - start6)
    #print("the length of ciphertext (AES-256) is ",len(C))
    #print("encrypt needs (AES-256)",end6 - start6)


    #AES128

    start6_AES128 = time.perf_counter()
    h_AES128 = TupleHash128.new(digest_bytes=16)
    h_AES128.update(S_bytes)
    cipher_AES128 = AES.new(h_AES128.digest(), AES.MODE_CBC, IV_AES128)
    C_AES128 = cipher_AES128.encrypt(K)
    end6_AES128 = time.perf_counter()
    time_key_manager.append(end6_AES128 - start6_AES128)
    #print("the length of ciphertext (AES-128)",len(C_AES128))
    #print("encrypt needs (AES-128)",end6_AES128 - start6_AES128)

    #RSA
    start6_RSA = time.perf_counter()
    se_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(se_key)
    C_RSA = cipher_rsa.encrypt(K)
    end6_RSA = time.perf_counter()
    time_key_manager.append(end6_RSA - start6_RSA)
    #print("the length of ciphertext (RSA)",len(C_RSA))
    #print("encrypt needs (RSA)",end6_RSA-start6_RSA)
    #print("the sixth step of key manager has finished")

    se1_key = RSA.import_key(private_key)
    cipher1_rsa = PKCS1_OAEP.new(se1_key)
    K_RSA = cipher1_rsa.decrypt(C_RSA)


    List = [IV, C, IV_AES128, C_AES128, private_key, C_RSA, K]

    return List;

List = key_manager_step_6()