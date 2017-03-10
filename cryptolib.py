#!/usr/bin/env python3

'''
##### CPSC 526 ASSIGNMENT 2 #########

    Submitted by: Pauline Telan
    10124075 T02

'''

import random, os, sys
from random import choice
import cryptography, hashlib
from cryptography.hazmat.primitives import padding, keywrap, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# randomly generates alphanumeric 32-char string key 
def generateKey():
    return ''.join(choice('0123456789ABCDEF') for i in range(32))

# b = bytes
# returns md5 hash of b in bytes
def md5hash(b):
    m = hashlib.md5()
    m.update(b)
    return m.digest()

# randomly generates 128-bit IV
def generateIV():
    return os.urandom(16)

# returns 'padsize'-bit padded version of dbytes
# dbytes = bytes, padsize = int (in bits)
def pad(dbytes, padsize):
    # create instance of padder
    padder = padding.PKCS7(padsize).padder()
    return padder.update(dbytes) + padder.finalize()
    
# returns key for aes
def makeKey(passw, keysize):
    # convert to bytes
    keysize = int(keysize/8)
    backend = default_backend()
    kdf = PBKDF2HMAC(hashes.SHA256(), length = keysize,salt = "bbbbbbbbbbbbbbbb".encode(), iterations=100000,backend = backend)
    
    key = kdf.derive(passw.encode())
    return key
    
# checks if pw is correct by comparing received hash to hash of iv in server 
def verifypass(received_hash_iv, iv):
    return received_hash_iv == md5hash(iv)


# encrypts plaintext and returns ciphertext in bytes
# based on parameter cipher
# plain, iv = bytes
# alg, key = string
def encrypt(plain, alg, key, iv):

    key_size = int(alg.strip("aes"))
    backend = default_backend()

    # pad plaintext to 128-bits
    padded_plain = pad(plain, 128)
    verifiedKey = makeKey(key, key_size)


    # encrypt
    cipher = Cipher(algorithms.AES(verifiedKey), modes.CBC(iv), backend)
    encryptor = cipher.encryptor()
    ctext_bytes = encryptor.update(padded_plain) + encryptor.finalize()
    return ctext_bytes

# returns decrypted version of ciphertext in bytes
# ciphertext, iv = bytes
# alg, key = string
def decrypt(ciphertext, alg, key, iv):
    
    print(len(ciphertext))

    key_size = int(alg.strip("aes"))
    backend = default_backend()

    verifiedKey = makeKey(key, key_size)
    # decrypt
    cipher = Cipher(algorithms.AES(verifiedKey), modes.CBC(iv), backend)
    decryptor = cipher.decryptor()
    plain = decryptor.update(ciphertext) + decryptor.finalize()
    # unpadder to get rid of excess padding from encryption process 
    unpadder = padding.PKCS7(128).unpadder()
    plain = unpadder.update(plain) + unpadder.finalize()
    
    return plain
