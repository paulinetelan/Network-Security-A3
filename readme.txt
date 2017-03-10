CPSC 526 Assignment 3: Network data-transfer w/ Symmetric encryption

How to compile/run:

To run server:
    
    "python3 server.py [port] [key]"

    [port] = port number where server will be listening
    [key] = password used for encryption if client decides to use; if not provided, server will generate a random 32-character password
    
    Note: server is assumed to be running in localhost

To run client:

    "python3 client.py [cmd] [filename] [ip]:[port] [cipher] [key]"

    [cmd] = determines if client will be uploading/downloading data to/from server
            can either be read/write
    [filename] = if cmd is read, server will send contents of filename
                else, server will upload contents of stdout to filename
    [ip] = ip address of server
    [port] = port server is listening to
    [cipher] = specifies what encryption algorithm is used for communication
                can be none/aes128/aes256
    [key] = key to be used for encryption. not necessary if cipher=none

Communication Protocol description:

1) Client connects to server
2) Client sends [Cipher, IV] to server in the clear
3) Password authentication:
    a) Client sends encrypted IV to server and vice versa
    b) Both parties compare received encrypted IV to locally encrypted IV
    c) If the same, password checks out. Else, connection is terminated.
4) Client sends [cmd, filename] to server. If cipher is specified, this is encrypted.
5) If cmd=write
    a) client sends data in 4mb chunks to server
    b) server receives and processes data 
    c) once client has sent all data, server sends response to client and client displays this to console
6) If cmd=read
    a) server sends data in 4mb chunks to client
    b) client receives and processes data
7) connection is closed



