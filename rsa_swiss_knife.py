import rsa

def gen():
    pub, priv = rsa.newkeys(1024)

    with open("myK.pub", "w") as f:
        f.write(str(pub.e) + "\n" + str(pub.n))
    with open("myK.priv", "w") as f:
        f.write(str(priv.n) + "\n" + str(priv.e) + "\n" +str(priv.d) + "\n" + str(priv.p) + "\n" + str(priv.q))
    return pub


def enc(message, pubFile):
    with open(pubFile, "r") as f:
        e = int(f.readline())
        n = int(f.readline())
        friend_pub = rsa.PublicKey(n, e)

    CT = rsa.encrypt(message.encode(), friend_pub).hex()
    return CT


def dec(enc_msg, privFile):
    with open(privFile, "r") as f:
        n = int(f.readline())
        e = int(f.readline())
        d = int(f.readline())
        p = int(f.readline())
        q = int(f.readline())
        myPriv = rsa.PrivateKey(n, e, d, p, q)

    OT = rsa.decrypt(bytes.fromhex(enc_msg), myPriv)
    return OT


def sign(message, privFile, hash_name):
    with open(privFile, "r") as f:
        n = int(f.readline())
        e = int(f.readline())
        d = int(f.readline())
        p = int(f.readline())
        q = int(f.readline())
        myPriv = rsa.PrivateKey(n, e, d, p, q)

    S = rsa.sign(message.encode(), myPriv, hash_name).hex()
    return S

def verify(message, signature, pubFile):
    with open(pubFile, "r") as f:
        e = int(f.readline())
        n = int(f.readline())
        friend_pub = rsa.PublicKey(n, e)

    S = rsa.verify(message.encode(), bytearray.fromhex(signature), friend_pub)
    return S

choice = int(input("Choose from RSA operations [0: generate 1: encrypt, 2: decrypt, 3: sign, 4: verify]: "))



if choice == 0:
    gen()
    print("Your pubKey is in 'myK.pub', private in 'myK.priv'")

elif choice == 1:
    message = input("Message to encrypt: ")
    pubFile = input("Name of file with public key: ")
    print("Encrypted message: " + str(enc(message, pubFile)))

elif choice == 2:
    enc_msg = input("Encrypted message: ")
    privFile = input("Name of file with private key: ")
    print("Decrypted message: " + str(dec(enc_msg, privFile)))

elif choice == 3:
    message = input("Message to sign: ")
    privFile = input("Name of file with private key: ")
    hash_name = input("Name of hash to hash your message: ")
    print("Your signature: " + str(sign(message, privFile, hash_name)))

elif choice == 4:
    message = input("Message to check: ")
    signature = input("Signature to verify: ")
    pubFile = input("Name of file with public key: ")
    print(verify(message, signature, pubFile))
else:
    print("abob")



