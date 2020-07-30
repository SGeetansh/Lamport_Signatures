import hashlib
import secrets

#creation of keys
def keygen():
    skey = [[0]*255, [1]*255]
    for i in range(len(skey)):
        for j in range(len(skey[i])):
            skey[i][j] = bin(secrets.randbits(255))[2:]
            skey[i][j] = '0'*(255-len(skey[i][j])) + skey[i][j]

    pkey = [[0]*255, [1]*255]
    for i in range(len(pkey)):
        for j in range(len(pkey[i])):
            pkey[i][j] = bin(int(hashlib.sha256(skey[i][j].encode()).hexdigest(), 16))
    
    keypair = [skey, pkey]
    return keypair

#signature generation of the message
def signgen(message, skey):
    mhash = int(hashlib.sha256(message.encode()).hexdigest(), 16)
    signature = [0]*255

    for i in range(255):
        k = int(bin(mhash >> i & 1)[2:])
        signature[i] = skey[k][i]
    
    return signature

# Verification of signature
def verification(message, pkey, signature):
    mhash = int(hashlib.sha256(message.encode()).hexdigest(), 16)
    for i in range(255):
        k = int(bin(mhash >> i & 1)[2:])
        verify = bin(int(hashlib.sha256(str(signature[i]).encode()).hexdigest(), 16))
        if pkey[k][i] != verify:
            return False
    return True

keypair = keygen()
message = "I am god."
signature = signgen(message, keypair[0])
print(verification(message, keypair[1], signature))