#!/usr/bin/env python3

'''
##### CPSC 526 ASSIGNMENT 3 #########

    Submitted by: Pauline Telan 10124075 & Albert Luu
    T02
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
            sys.stderr.write("ERROR: Wrong password.\n")
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
        blocksize = BUFFER_SIZE
        if encrypted:
            blocksize = BUFFER_SIZE - 16
        try:
            data = sys.stdin.buffer.read(blocksize)
            while data:
                if encrypted:
                    data_send = cryptolib.encrypt(data, cipher, key, iv)
                else:
                    data_send = data
                servsock.sendall(data_send)
                data = sys.stdin.buffer.read(blocksize)

            # receive server response
            data = servsock.recv(128)
            if encrypted:
                data = cryptolib.decrypt(data, cipher, key, iv)
            sys.stderr.write(data.decode("utf-8", "ignore"))
            
        except Exception as e:
            sys.stderr.write("ERROR: {0}".format(e))

        
    # download from server 
    elif cmd == "read":
        try:
            # Receive data
            data = servsock.recv(BUFFER_SIZE)
            while data:
                if encrypted:
                    data_recv = cryptolib.decrypt(data, cipher, key, iv)
                else:
                    data_recv = data
                sys.stdout.buffer.write(data_recv)
                time.sleep(0.35)
                # checks for last block
                if len(data) < BUFFER_SIZE:
                    break
                data = servsock.recv(BUFFER_SIZE)

            sys.stderr.write(filename + " downloaded successfully.\n")
            sys.stderr.write("File transfer complete.\n")
            
        except Exception as e:
            sys.stderr.write("READ ERROR: {0}".format(e))

    disconnect()
            
