import time
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from sympy import Symbol, Function
from key_visit import h1
import key_manager


#key recover
#1. input t1 secret shares

#2. construct a polynomial p1(x)=x**m+SS1*x**(m-1)+SS2*x**(m-2)+...+SS(m-t1)*x**t1

def key_recover_step_2():

    print("the second step of key recover has run")
    start_K_recover2 = time.perf_counter()
    x = Symbol('x')
    p1 = Function('p1')(x)
    p1 = x ** key_manager.m

    for i in range(key_manager.m - key_manager.t1):
        p1  += (key_manager.key_manager_step_3(key_manager.m)[i]) * pow(x, key_manager.m - i - 1)

    y1 = []  #the coefficient of p1 y1[0] is constant
    for i in range(key_manager.t1):
        y1.append(0)

    for i in range(key_manager.m - key_manager.t1):
        y1.append(key_manager.key_manager_step_3(key_manager.m)[key_manager.m - key_manager.t1 - i - 1])
    y1.append(1)

    end_K_recoer2 = time.perf_counter()
    print("the second step of key recover needs",end_K_recoer2 - start_K_recover2)
    print("the second step of key recover has finished")
    return y1
#3. solve t1-ary inear equations

#using Horner scheme to get Polynomial value

def key_recover_step_3and4():
    print("the third step of key recover has run")
    start_K_recover3and4 = time.perf_counter()
    def getresult(array, n, x):
        result = array[n-1]
        for i in range(n-1, 0, -1):
            result = array[i-1] + result * x
        return result
    array1 = [1,2,3,4]

    L = []  #value of equations

    for i in range(key_manager.t1):
        L.append(getresult(key_recover_step_2(), key_manager.m + 1, key_manager.s[i]))

    #solving t1-ary inear equations,the coefficient matrix is Vandermonde matrix

    V = [] #The first row of the inverse of the VanderMonde matrix
    #s_V numerator S_V denominator
    result = 0

    #4. get main key s = |a0|

    print("the fourth step of key recover has run")
    for i in range(key_manager.t1):
        s_V = pow(-1, key_manager.t1 - 1)
        S_V = 1
        for j in range(key_manager.t1):
            if(i == j):
                continue
            else:
                s_V *= key_manager.s[j]
                S_V *= (key_manager.s[i] - key_manager.s[j])
        result += s_V * L[i] / S_V
    if(result < 0):
        result = -1 * result

    end_K_recoer3and4 = time.perf_counter()
    print("the third and fourth of steps of key recover need",end_K_recoer3and4 - start_K_recover3and4)
    print("the third and fourth of steps of key recover have finished")

    return result

#5. decrypt and get the set of key, that is K = DEC(s,C)

def key_recover_step_5():

    print("the fifth step of key recover has run")
    start_K_recover5 = time.perf_counter()
    h_result = SHA256.new()
    result_bytes = str(key_recover_step_3and4() % key_manager.P).encode()
    h_result.update(result_bytes)
    cipher_result = AES.new(h1.digest(), AES.MODE_CBC, key_manager.key_manager_step_6()[0])
    K_result = cipher_result.decrypt(key_manager.key_manager_step_6()[1])
    end_K_recoer5 = time.perf_counter()

    print("the fifth step of key recover needs",end_K_recoer5 - start_K_recover5)
    print("the fifth step of key recover has finished")

key_recover_step_2()
key_recover_step_3and4()
key_recover_step_5()