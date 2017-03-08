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

        # get parameters [cipher, iv(opt)]
        data = connection.recv(4096)
        param = pickle.loads(data)
        # Display parameters
        print("Client " + client_address[0] + " connected.")
        # display iv if cipher specified
        iv_str = ''
        alg = param[0]
        encrypted = False
        if alg != 'none':
            encrypted = True
            iv = param[1]
            iv_str = "IV: "+ param[1].decode('utf-8', 'replace')
        
        print("Crypto: " + alg + " " + iv_str)
        
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
                data = connection.recv(4096)
                if encrypted:
                    data = cryptolib.decrypt(data, alg, key, iv)
                data = pickle.loads(data)
                cmd = data[0]
                filename = data[1]
                    
                print(cmd+filename)
        
                # only get past here if password is correct
                
                # if cmd = write, download file from client
                if cmd == "write":
                    try:
                        # Open filename
                        f_obj = open(filename, "wb+")
            
                        # Receive data
                        data = connection.recv(4096)
                        while data:
                            if encrypted:
                                data_recv = cryptolib.decrypt(data, alg, key, iv)
                            else:
                                data_recv = data
                            f_obj.write(data_recv)
                            # checks for last block
                            if len(data) < 4096:
                                break
                                
                            data = connection.recv(4096)
            
                        print(filename + " uploaded successfully.")
                        message = "SERVER: " + filename + " uploaded successfully."
                        if encrypted:
                            message = cryptolib.encrypt(message.encode(), alg, key, iv)
                        else:
                            message = message.encode()
                        # Cleanup
                        f_obj.close()
                        print("Done.")
            
                    except Exception as e:
                        print("ERROR: {0}".format(e))
                        message = "SERVER ERROR: {0}".format(e)
                        
                    # send appropriate message
                    finally:
                        connection.sendall(message)
            
                # else, send file to client
                elif cmd == "read":
                    if encrypted:
                        blocksize = 4080
                    else:
                        blocksize = 4096
                    try:
                        filereader = open(filename, 'rb+')
                        data = filereader.read(blocksize)
                        while (data):
                            if encrypted:
                                data_send = cryptolib.encrypt(data, alg, key, iv)
                            else:
                                data_send = data
                            connection.sendall(data_send)
                            data = filereader.read(blocksize)
                        filereader.close()
                    except Exception as e:
                        print("ERROR: {0}".format(e))
                        connection.sendall(bytearray("SERVER ERROR: {0}".format(e), "utf-8"))

            except Exception as e:
                
                # only breaks if wrong password is used
                print("ERROR: {0}".format(e))
                connection.sendall(bytearray("        SERVER ERROR: Wrong key.", "utf-8"))
                
            finally:
                connection.shutdown(1)
                connection.close()

