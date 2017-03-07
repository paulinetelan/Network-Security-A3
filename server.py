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
    server_address = ("localhost", port)
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
        iv_str = ""
        alg = param[0]
        encrypted = False
        if alg != "none":
            encrypted = True
            iv = param[1]
            iv_str = "IV: "+ param[1].decode("utf-8", "replace")
        
        print("Crypto: " + alg+ " "+ iv_str)

        try:
            # receive cmd + filename
            data = connection.recv(4096)
            data = pickle.loads(data)
            cmd = data[0]
            filename = data[1]
            # decrypt if cipher specified
            if encrypted:
                cmd = cryptolib.decrypt(data[0], alg, key, iv)
                filename = cryptolib.decrypt(data[1], alg, key, iv)
                cmd = cmd.decode("utf-8", "ignore")
                filename = filename.decode("utf-8", "ignore")

            # TODO encrypt all traffic from here on

            # if cmd = write, download file from client
            if cmd == "write":
                try:
                    # Open filename
                    f_obj = open(filename, "wb+")

                    # Get expected data size
                    data_size = int.from_bytes(connection.recv(4), "big")

                    # fixes issue with buffering
                    time.sleep(0.1)

                    # Receive data
                    data = connection.recv(data_size)

                    # Write data to file
                    f_obj.write(data)

                    print(filename + " uploaded successfully.")
                    # Send client success message
                    connection.sendall(bytearray("SERVER: " + filename + " uploaded successfully.", "utf-8"))

                    # Cleanup
                    f_obj.close()
                    print("Done.")

                except Exception as e:
                    print("ERROR: {0}".format(e))
                    connection.sendall(bytearray("SERVER ERROR: {0}".format(e), "utf-8"))

            # else, send file to client
            elif cmd == "read":
                try:
                    # send data size to server
                    data_size = os.stat(filename).st_size
                    data_size_bytes = data_size.to_bytes(4, "big")
                    connection.sendall(data_size_bytes)

                    # Open filename 
                    f_obj = open(filename, "rb+")

                    # Read file
                    f_data = f_obj.read()
                    
                    # send data to server
                    connection.sendall(f_data)

                    # Clean up
                    f_obj.close()
                except Exception as e:
                    print("ERROR: {0}".format(e))
                    connection.sendall(bytearray("SERVER ERROR: {0}".format(e), "utf-8"))

        except Exception as e:
            # only breaks if wrong password is used
            print("Wrong password.")
            connection.sendall(bytearray("SERVER ERROR: Wrong key.", "utf-8"))

        finally:
            connection.shutdown(1)
            connection.close()