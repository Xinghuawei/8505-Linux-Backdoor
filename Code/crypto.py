import base64
import math
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from binascii import hexlify, unhexlify


def aesEncrypt(msg):
    key = "compcompcompcomp".encode("utf8")
    iv = "IVIVIVIVIVIVIVIV".encode("utf8")
    cipher = AES.new(key, AES.MODE_CFB, iv)
    ciphertext = cipher.encrypt(msg)
    return iv + ciphertext



def aesDecrypt(ciphertext):
    key = "compcompcompcomp".encode("utf8")
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    msg = cipher.decrypt(ciphertext)
    return msg.decode("utf-8")

