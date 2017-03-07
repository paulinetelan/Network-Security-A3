#!/usr/bin/env python3

'''
##### CPSC 526 ASSIGNMENT 2 #########

    Submitted by: Pauline Telan
    10124075 T02

'''

import random, os, sys
from random import choice
import cryptography
from cryptography.hazmat.primitives import padding, keywrap
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# randomly generates alphanumeric 32-char string key 
def generateKey():
    return ''.join(choice('0123456789ABCDEF') for i in range(32))

# checks if key > key_size and returns key of proper length
# by only taking first key_size bits
# key = string, key_size = integer
def verifyKey(key, key_size):
    ret = key.encode()
    # convert to bytes
    key_size = int(key_size/8)
    if len(key) > key_size:
        ret = key[:key_size]
        ret = ret.encode()
    elif len(key) < key_size:
        ret = pad(key.encode(), key_size)
    return ret


# randomly generates 128-bit IV
def generateIV():
    return os.urandom(16)

# returns 'padsize'-bit padded version of dbytes
# dbytes = bytes, padsize = int (in bits)
def pad(dbytes, padsize):
    # create instance of padder
    padder = padding.PKCS7(padsize).padder()
    return padder.update(dbytes) + padder.finalize()

# encrypts plaintext and returns ciphertext in bytes
# based on parameter cipher
# plain, iv = bytes
# alg, key = string
def encrypt(plain, alg, key, iv):

    key_size = int(alg.strip("aes"))
    backend = default_backend()

    # pad plaintext to 128-bits
    padded_plain = pad(plain, 128)
    verifiedKey = verifyKey(key, key_size)

    # encrypt
    cipher = Cipher(algorithms.AES(verifiedKey), modes.CBC(iv), backend)
    encryptor = cipher.encryptor()
    ctext_bytes = encryptor.update(padded_plain) + encryptor.finalize()
    return ctext_bytes

# returns decrypted version of ciphertext in bytes
# ciphertext, iv = bytes
# alg, key = string
def decrypt(ciphertext, alg, key, iv):

    key_size = int(alg.strip("aes"))
    backend = default_backend()

    verifiedKey = verifyKey(key, key_size)

    # decrypt
    cipher = Cipher(algorithms.AES(verifiedKey), modes.CBC(iv), backend)
    decryptor = cipher.decryptor()
    plain = decryptor.update(ciphertext) + decryptor.finalize()
    # unpadder to get rid of excess padding from encryption process 
    unpadder = padding.PKCS7(128).unpadder()
    plain = unpadder.update(plain) + unpadder.finalize()
    
    return plain