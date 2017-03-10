#!/usr/bin/env python3

'''
##### CPSC 526 ASSIGNMENT 2 #########

    Submitted by: Pauline Telan
    10124075 T02

'''

import sys, socket, os
import random, pickle
import time
from random import choice
# crypto functions
import cryptolib

#### MAIN ####
if __name__ == "__main__":
    
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
                if encrypted:
                    data = cryptolib.decrypt(data, alg, key, iv)
                data = pickle.loads(data)
                cmd = data[0]
                filename = data[1]
                
                if cmd == "write":
                    try:
                        # Open filename
                        f_obj = open(filename, "wb+")
                        
                        # Receive data
                        data = connection.recv(BUFFER_SIZE)
                        counter = 0
                        while data:
                            print("DERP %d %d" % (len(data), counter))
                            counter += 1
                            if encrypted:
                                data_recv = cryptolib.decrypt(data, alg, key, iv)
                            else:
                                data_recv = data
                            f_obj.write(data_recv)
                            time.sleep(0.35)
                            # checks for last block
                            if len(data) < BUFFER_SIZE:
                                break
                            data = connection.recv(BUFFER_SIZE)
            
                        print(filename + " uploaded successfully.")
                        message = "SERVER: " + filename + " uploaded successfully."
                        
                        # Cleanup
                        f_obj.close()
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
                    if encrypted:
                        blocksize = BUFFER_SIZE - 16
                    else:
                        blocksize = BUFFER_SIZE
                        
                    f_obj = open(filename, "rb")
                    try:
                        data = f_obj.read(blocksize)
                        while data:
                            if encrypted:
                                data_send = cryptolib.encrypt(data, alg, key, iv)
                            else:
                                data_send = data
                            print("lenth of data_send: %d"%len(data_send))
                            connection.sendall(data_send)
                            data = f_obj.read(blocksize)
                        f_obj.close()
                    except Exception as e:
                        print("ERROR: {0}".format(e))
            except Exception as e:
                # only breaks if wrong password is used
                print("ERROR: {0}".format(e))
                connection.sendall(bytearray("SERVER ERROR: Wrong key.", "utf-8"))
                
            finally:
                connection.shutdown(1)
                connection.close()

