#!/usr/bin/env python3

'''
##### CPSC 526 ASSIGNMENT 3 #########

    Submitted by: Pauline Telan 10124075 & Albert Luu 10129499
    T02
'''

import sys, socket, os
import random, pickle
import time
from random import choice
# crypto functions
import cryptolib

#### MAIN ####
if __name__ == "__main__":

    # returns size of incoming data size
    def recv_datasize():
        data_size_bytes = connection.recv(4)
        data_recv_blocksize = int.from_bytes(data_size_bytes, 'big')
        return data_recv_blocksize
    
    BUFFER_SIZE = 4194304
    
    # Parse input
    port = int(sys.argv[1].strip("'"))

    # If key not given, randomly generate 32 char string
    if len(sys.argv) == 2:
        key = cryptolib.generateKey()
    else:
        key = sys.argv[2].strip("'")

    # Init socket 
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Set server address
    server_address = ('localhost', port)
    sock.bind(server_address)

    # listen for incoming connections
    sock.listen(1)

    # Loop for each client
    while True:
        print("Listening on port %d" % port)
        print("Using secret key: " + key)
        connection, client_address = sock.accept()
        print("Client " + client_address[0] + " connected.")

        # get parameters [cipher, iv(opt)]
        data = connection.recv(128)
        param = pickle.loads(data)
        
        # display iv if cipher specified
        iv_str = ''
        alg = param[0]
        encrypted = False
        if alg != 'none':
            encrypted = True
            iv = param[1]
            iv_str = "IV: "+ param[1].decode('utf-8', 'replace')
        
        print("Encryption: " + alg + " " + iv_str)
        
        # password authentication
        if encrypted:
            iv_encrypted = cryptolib.encrypt(iv, alg, key, iv)
            connection.sendall(iv_encrypted)
            recvd_iv = connection.recv(128)
            pass_ok = True
            if recvd_iv != iv_encrypted:
                print("ERROR: Wrong password.")
                pass_ok = False

        if (not encrypted) or pass_ok:
            try:
                # receive cmd + filename
                data = connection.recv(BUFFER_SIZE)
                blocksize = BUFFER_SIZE
                if encrypted:
                    data = cryptolib.decrypt(data, alg, key, iv)
                    blocksize = BUFFER_SIZE - 16
                data = pickle.loads(data)
                cmd = data[0]
                filename = data[1]
                
                if cmd == "write":
                    
                    message = "SERVER: " + filename + " uploaded successfully."
                    try:
                        # Open filename
                        f_obj = open(filename, "wb+")

                        # receive data block size
                        data_size = recv_datasize()
                        # if file not empty
                        if data_size != 0:
                            # Receive data
                            data = connection.recv(data_size)
                            while len(data) < data_size:
                                data += connection.recv(data_size - len(data))
                            counter = 0
                            while data:
                                counter += 1
                                print('recv block %d' % counter)
                                if encrypted:
                                    data_recv = cryptolib.decrypt(data, alg, key, iv)
                                else:
                                    data_recv = data
                                
                                f_obj.write(data_recv)
                                
                                # receive size of next block 
                                data_size = recv_datasize()
                                # client sends data_size = 0 if eof
                                if data_size == 0:
                                    break

                                data = connection.recv(data_size)
                                # keep receiving data until length matches data_size
                                while len(data) < data_size:
                                    data += connection.recv(data_size - len(data))

                            # Cleanup
                            f_obj.close()
                            print(filename + " uploaded successfully.")
                            print("File transfer complete.")
                        
                    except Exception as e:
                        print("WRITE ERROR: {0}".format(e))
                        message = "SERVER WRITE ERROR: {0}".format(e)
                        
                    finally:
                        message = message.encode()
                        if encrypted:
                            message = cryptolib.encrypt(message, alg, key, iv)
                        connection.sendall(message)
                
                elif cmd == "read":
                    try:
                        f_obj = open(filename, 'rb')

                        # send that file is found
                        message = "0".encode()
                        if encrypted:
                            message = cryptolib.encrypt(message, alg, key, iv)
                        connection.sendall(message)

                        # send data
                        data = f_obj.read(blocksize)
                        counter = 0
                        while data:
                            counter += 1
                            if encrypted:
                                data_send = cryptolib.encrypt(data, alg, key, iv)
                            else:
                                data_send = data
                            print("Sending block %d" % counter)

                            # send data size to server
                            data_size = len(data_send)
                            connection.sendall(data_size.to_bytes(4, 'big'))

                            # send data
                            connection.sendall(data_send)
                            data = f_obj.read(blocksize)

                        f_obj.close()
                    
                    # check if file exists
                    except FileNotFoundError:
                        message = "1".encode()
                        if encrypted:
                            message = cryptolib.encrypt(message, alg, key, iv)
                        connection.sendall(message)
                    except Exception as e:
                        print("ERROR: {0}".format(e))
            except Exception as e:
                # only breaks if wrong password is used
                print("ERROR: {0}".format(e))
                
            finally:
                connection.shutdown(1)
                connection.close()

