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
    
    # Disconnects client from server
    def disconnect():
        # close connection
        servsock.close()
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

    # Send "crypto cmd filename iv" to server
    # iv = bytes
    # cipher = string
    param = [cipher, iv]
    servsock.sendall(pickle.dumps(param))

    # give server time to process array
    time.sleep(0.1)

    cmdfilenamearr = [cmd, filename]
    # if cipher, encrypt
    if encrypted:
        cmd_encrypted = cryptolib.encrypt(cmd.encode(), cipher, key, iv)
        filename_encrypted = cryptolib.encrypt(filename.encode(), cipher, key, iv)
        # encrypted hash of iv to check for password
        iv_hash = cryptolib.encrypt(cryptolib.md5hash(iv), cipher, key, iv)
        cmdfilenamearr = [cmd_encrypted, filename_encrypted, iv_hash]
    
    # send [cmd, filename] 
    # cmd and filename are in bytes
    servsock.sendall(pickle.dumps(cmdfilenamearr))
    
    # receive server response
    data = servsock.recv(4)
    pass_ok = int.from_bytes(data, "big")
    # check if correct password
    if pass_ok == 0:
        print("_ERROR: Wrong key.")
        disconnect()

    # upload to server
    if cmd == "write":

        # TODO Fix this thing to send blocks instead of the whole file
        
        try:
            # read from stdin
            data = sys.stdin.read()

            # send data size to server
            data_size = len(data)
            servsock.sendall(data_size.to_bytes(4, "big"))

            # send data to server
            servsock.sendall(str.encode(data))

            # get server response
            s_resp = servsock.recv(4096)

            print(s_resp.decode("utf-8", "ignore"))

        except Exception as e:
            print("ERROR: {0}".format(e))

    # download from server 
    elif cmd == "read":
        try:
            # Get expected data size
            data = servsock.recv(4)
            data_size = int.from_bytes(data, "big")

            # Check if data is too big
            if shutil.disk_usage("/").free < data_size:
                print("ERROR: Insufficient disk space. File read failed.")
                disconnect()

            # Receive data
            data = servsock.recv(data_size)

            # print to stdout
            sys.stdout.buffer.write(data)
            print()

        except Exception as e:
            print("ERROR: {0}".format(e))

    disconnect()
            
