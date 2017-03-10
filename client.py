#!/usr/bin/env python3

'''
##### CPSC 526 ASSIGNMENT 2 #########

    Submitted by: Pauline Telan
    10124075 T02

    Usage: client command filename hostname:port cipher [key]

        command = write (for uploading) / read (for downloading)
        filename = file to be used by server
        hostname:port = address of server: port where server is listening
        cipher = aes256/aes128/none 
        key = key to be used for encryption (doesn't have to be specified if cipher=none)
'''

import sys, socket, shutil
import array, pickle, struct
import time
import cryptolib, hashlib

#### MAIN ####
if __name__ == "__main__":
    
    BUFFER_SIZE = 4194304
    
    # Disconnects client from server
    def disconnect():
        try:
            servsock.close()
            sys.exit()
        except:
            sys.exit()
    # Parse input
    input = sys.argv
    
    cmd = input[1].strip("'")
    filename = input[2].strip("'")
    serveradd = input[3].strip("'").split(":")
    cipher = input[4].strip("'")
    encrypted = False
    # initiate IV
    iv = ""
    if cipher != "none":
        encrypted = True
        key = input[5].strip("'")
        iv = cryptolib.generateIV()

    # Connect to server
    servsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servsock.connect((serveradd[0], int(serveradd[1])))

    # Send encryption algorithm and iv to server
    # iv = bytes
    # cipher = string
    param = [cipher, iv]
    servsock.sendall(pickle.dumps(param))

    # give server time to process array
    time.sleep(0.1)
    
    # password authentication
    if encrypted:
        iv_encrypted = cryptolib.encrypt(iv, cipher, key, iv)
        servsock.sendall(iv_encrypted)
        recvd_iv = servsock.recv(128)
        if recvd_iv != iv_encrypted:
            print("ERROR: Wrong password.")
            disconnect()
    
    cmdfilenamearr = pickle.dumps([cmd, filename])
    # if cipher, encrypt
    if encrypted:
        # encrypted hash of iv to check for password
        cmdfilenamearr = cryptolib.encrypt(cmdfilenamearr, cipher, key, iv)
    # send [cmd, filename] 
    # cmd and filename are in bytes
    servsock.sendall(cmdfilenamearr)
    
    # upload to server
    if cmd == "write":
        if encrypted:
            blocksize = BUFFER_SIZE - 16
        else:
            blocksize = BUFFER_SIZE
        try:
            data = sys.stdin.buffer.read(blocksize)
            while data:
                if encrypted:
                    data_send = cryptolib.encrypt(data, cipher, key, iv)
                else:
                    data_send = data
                print("lenth of data_send: %d"%len(data_send))
                servsock.sendall(data_send)
                data = sys.stdin.buffer.read(blocksize)
                
                
            # receive server response
            data = servsock.recv(128)
            if encrypted:
                data = cryptolib.decrypt(data, cipher, key, iv)
            print(data.decode("utf-8", "ignore"))
            
        except Exception as e:
            print("ERROR: {0}".format(e))

        
    # download from server 
    elif cmd == "read":
        try:
            data = servsock.recv(BUFFER_SIZE)
            while data:
                if encrypted:
                    data_recv = cryptolib.decrypt(data, cipher, key, iv)
                else:
                    data_recv = data
                sys.stdout.buffer.write(data_recv)
                if len(data) < BUFFER_SIZE:
                    break
                data = servsock.recv(BUFFER_SIZE)
        except Exception as e:
            print("ERROR: {0}".format(e))

    disconnect()
            
