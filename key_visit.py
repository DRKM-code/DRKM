import time
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256, TupleHash128
from Crypto.PublicKey import RSA
from key_manager import t2, key_manager_step_5, m, s, P, key_manager_step_1, List, key_manager_step_6


#print(key_manager_step_6())

# key visit:
# 1.input t2 secret shares{si1,si2,...,si(t2)},compute wi(l)=(i1/(i1-il))*(i2/(i2-il))*...*(it2/(it2-il)),
# and compute s=wi1*si1+wi2*si2*...*wi(t2)*si(t2)

def key_visit_step_1():
    print("the first step of key visit has run")
    start7 = time.perf_counter()
    wi = [0, 1]
    for l in range(1, t2 + 1):
        for j in range(1, t2 + 1):
            if(l == j):
                continue
            else:
                wi[l] = wi[l] * j / (j - l)
        wi.append(1)
    #compute s
    S1 = 0    #S1 is computed s
    for i in range(1, t2 + 1):
        S1 += int(wi[i]) * key_manager_step_5()[i - 1]
    end7 = time.perf_counter()
    print("the first step of key visit needs",end7 - start7)
    print("the first step of key visit has finished")
    return S1

#2. decrypt and get the set of key,that is K = DEC(s,C)
h1 = SHA256.new()
def key_visit_step_2(h1):

    print("the second step of key visit has run")

    #AES256

    start8 = time.perf_counter()
    S1_bytes = str(key_visit_step_1() % P).encode()
    h1.update(S1_bytes)
    cipher1 = AES.new(h1.digest(), AES.MODE_CBC, List[0])
    K1 = cipher1.decrypt(List[1])
    end8 = time.perf_counter()
    print("decryption needs（AES-256）",end8 -start8)

    #AES128
    start8_AES128 = time.perf_counter()
    h1_AES128 = TupleHash128.new(digest_bytes=16)
    h1_AES128.update(S1_bytes)
    cipher1_AES128 = AES.new(h1_AES128.digest(), AES.MODE_CBC, List[0])
    K1_AES128 = cipher1_AES128.decrypt(List[3])
    end8_AES128 = time.perf_counter()
    print("decryption needs（AES-128）" ,end8_AES128 - start8_AES128)

    #RSA
    start8_RSA = time.perf_counter()
    se1_key = RSA.import_key(List[4])
    cipher1_rsa = PKCS1_OAEP.new(se1_key)
    K_RSA = cipher1_rsa.decrypt(List[5])
    end8_RSA = time.perf_counter()
    print("decryption needs（RSA）", end8_RSA - start8_RSA)
    print("the second step of key visit has finished")

key_visit_step_1()
key_visit_step_2(h1)




