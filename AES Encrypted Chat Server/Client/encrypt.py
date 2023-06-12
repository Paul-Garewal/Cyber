
"""
Following code Sourced from https://www.delftstack.com/howto/python/python-aes-encryption/ which greatly helped with the AES encryption.

"""

#AES MODULES FOR ENCRYPTION
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random

BLOCK_SIZE = 16
pad = lambda s: bytes(s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE), 'utf-8')
unpad = lambda s : s[0:-ord(s[-1:])]
"""
Function: encrypt
args: (str) plain_text - text to be encrypted
      (int) key - encryption key 
encry
This function encrypts a message using AES.
"""
def encrypt(plain_text, key):
    private_key = hashlib.sha256(bytes(key.encode("utf-8"))).digest()
    plain_text = pad(plain_text)
    print("After padding:", plain_text)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(plain_text))

"""
Function: decrypt
args: (str) cipher_text - the encrypted text
      (int) key - decryption key 

This function decrypts a message using AES.
"""
def decrypt(cipher_text, key):
    private_key = hashlib.sha256(bytes(key.encode("utf-8"))).digest()
    cipher_text = base64.b64decode(cipher_text)
    iv = cipher_text[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(cipher_text[16:]))
message=input("Enter message to encrypt: ");
key = input("Enter encryption key: ")
encrypted_msg = encrypt(message, key)
print("Encrypted Message:", encrypted_msg)
decrypted_msg = decrypt(encrypted_msg, key)
print("Decrypted Message:", bytes.decode(decrypted_msg))
