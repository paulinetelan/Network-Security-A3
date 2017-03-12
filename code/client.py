#!/usr/bin/env python3

'''
##### CPSC 526 ASSIGNMENT 3 #########

    Submitted by: Pauline Telan 10124075 & Albert Luu 10129499
    T02
'''

import sys, socket, shutil
import array, pickle, struct
import time
import cryptolib, hashlib

#### MAIN ####
if __name__ == "__main__":

    # returns size of incoming data size
    def recv_datasize():
        data_size_bytes = servsock.recv(4)
        data_recv_blocksize = int.from_bytes(data_size_bytes, 'big')
        return data_recv_blocksize
    
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
        time.sleep(0.1)
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

                # send data size to server
                data_size = len(data_send)
                servsock.sendall(data_size.to_bytes(4, 'big'))

                # send data
                servsock.sendall(data_send)
                data = sys.stdin.buffer.read(blocksize)

            # send fake EOF at the end of file
            send_eof = 0
            servsock.sendall(send_eof.to_bytes(4, 'big'))

            # receive server response
            data = servsock.recv(BUFFER_SIZE)
            if encrypted:
                data = cryptolib.decrypt(data, cipher, key, iv)
            sys.stderr.write(data.decode("utf-8", "ignore")+"\n")
            
        except Exception as e:
            sys.stderr.write("WRITE ERROR: {0}\n".format(e))
            
    # download from server 
    elif cmd == "read":
        try:
            # Receive data
            verif = servsock.recv(128)
            if encrypted:
                verif = cryptolib.decrypt(verif, cipher, key, iv)

            # if filename exists
            if verif.decode() == '0':
                 # receive data block size
                data_size = recv_datasize()
                # if file not empty
                if data_size != 0:
                    data = servsock.recv(data_size)
                    while len(data) < data_size:
                        data += servsock.recv(data_size - len(data))
                    while data:
                        if encrypted:
                            data_recv = cryptolib.decrypt(data, cipher, key, iv)
                        else:
                            data_recv = data

                        sys.stdout.buffer.write(data_recv)

                        # receive size of next block 
                        data_size = recv_datasize()
                        # check for eof
                        if data_size == 0:
                            break
                        data = servsock.recv(data_size)
                        while len(data) < data_size:
                            data += servsock.recv(data_size - len(data))

                    sys.stderr.write(filename + " downloaded successfully.\n")
                    sys.stderr.write("File transfer complete.\n")
            else:
                sys.stderr.write("SERVER ERROR: File not found")
        except Exception as e:
            sys.stderr.write("READ ERROR: {0}".format(e))

    disconnect()
            
