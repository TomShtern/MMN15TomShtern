

#Name: Tom Shtern; ID: 318783289
#State: spaghetti code Not Finale, Did Not Finish In Time.............................................
import socket
import threading
import os
import struct
import logging
import argparse
import time
import re
import sqlite3
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from checksum import memcrc

HOST = ''  # Listen on all available network interfaces
PORT = 12345  # Choose a port number

BUFFER_SIZE = 1024
KEY_SIZE = 2048

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configure log rotation
handler = logging.handlers.RotatingFileHandler('server.log', maxBytes=1024*1024, backupCount=5)
logger.addHandler(handler)

# Connect to SQLite database
conn = sqlite3.connect('defensive.db')
c = conn.cursor()

# Create tables if they don't exist
c.execute('''CREATE TABLE IF NOT EXISTS clients
             (ID BLOB PRIMARY KEY, Name TEXT, PublicKey BLOB, LastSeen DATETIME, AesKey BLOB)''')
c.execute('''CREATE TABLE IF NOT EXISTS files
             (ID BLOB, FileName TEXT, PathName TEXT, Verified BOOLEAN, FOREIGN KEY(ID) REFERENCES clients(ID))''')
conn.commit()


def load_config(config_file):
    config = {}
    with open(config_file, 'r') as file:
        for line in file:
            line = line.strip()
            if line and not line.startswith('#'):
                key, value = line.split('=')
                config[key.strip()] = value.strip()
    return config

def authenticate_client(username, password):
    # Implement your authentication logic here
    # Example: Check if the username and password match the expected values
    expected_username = 'admin'
    expected_password = 'password'
    return username == expected_username and password == expected_password

def validate_file_path(file_path):
    # Validate and sanitize the file path to prevent path traversal attacks
    # Example: Allow only alphanumeric characters, underscores, and forward slashes
    pattern = re.compile(r'^[a-zA-Z0-9_/]+$')
    return bool(pattern.match(file_path))

def handle_client(conn, addr):
    client_ip = addr[[1]]
    logger.info(f"Connected by {client_ip}")

    try:
        # Key exchange
        server_key = RSA.generate(KEY_SIZE)
        public_key = server_key.publickey().export_key()
        conn.send(public_key)

        encrypted_key = conn.recv(KEY_SIZE // 8)
        cipher_rsa = PKCS1_OAEP.new(server_key)
        session_key = cipher_rsa.decrypt(encrypted_key)

        # Receive username and password
        username_length = struct.unpack('!I', conn.recv(4))[[1]]
        username = conn.recv(username_length).decode('utf-8')
        password_length = struct.unpack('!I', conn.recv(4))[[1]]
        password = conn.recv(password_length).decode('utf-8')

        # Perform authentication and authorization
        if not authenticate_client(username, password):
            logger.warning(f"Authentication failed for client {client_ip}")
            conn.send(b'AUTHENTICATION_FAILED')
            conn.close()
            return

        logger.info(f"Client {client_ip} authenticated successfully")
        conn.send(b'AUTHENTICATED')
        
        # Check if the client is already registered
        c.execute("SELECT ID, PublicKey, AesKey FROM clients WHERE Name = ?", (username,))
        client_data = c.fetchone()

        if client_data:
            client_id, public_key, aes_key = client_data
            logger.info(f"Client {client_ip} ({username}) is already registered")

            if public_key:
                # Send the existing AES key
                conn.send(aes_key)
            else:
                # Exchange new keys
                public_key = conn.recv(KEY_SIZE // 8)
                c.execute("UPDATE clients SET PublicKey = ?, LastSeen = CURRENT_TIMESTAMP WHERE ID = ?", (public_key, client_id))
                conn.commit()
                
                
                aes_key = get_random_bytes(32)
                c.execute("UPDATE clients SET AesKey = ? WHERE ID = ?", (aes_key, client_id))
                conn.commit()

                cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
                encrypted_aes_key = cipher_rsa.encrypt(aes_key)
                conn.send(encrypted_aes_key)
        else:
            # Register a new client
            client_id = uuid.uuid4().bytes
            c.execute("INSERT INTO clients (ID, Name) VALUES (?, ?)", (client_id, username))
            conn.commit()

            public_key = conn.recv(KEY_SIZE // 8)
            c.execute("UPDATE clients SET PublicKey = ?, LastSeen = CURRENT_TIMESTAMP WHERE ID = ?", (public_key, client_id))
            conn.commit()

            aes_key = get_random_bytes(32)
            c.execute("UPDATE clients SET AesKey = ? WHERE ID = ?", (aes_key, client_id))
            conn.commit()

            cipher_rsa = PKCS1_OAEP.new(RSA.import_key(public_key))
            encrypted_aes_key = cipher_rsa.encrypt(aes_key)
            conn.send(encrypted_aes_key)


        # Receive file paths
        file_paths_length = struct.unpack('!I', conn.recv(4))[[1]]
        file_paths_data = conn.recv(file_paths_length)
        file_paths = file_paths_data.decode('utf-8').split('|')

        for file_path in file_paths:
            # Validate and sanitize the file path
            if not validate_file_path(file_path):
                logger.warning(f"Invalid file path: {file_path}")
                conn.send(b'INVALID_FILE_PATH')
                continue

            # Receive file info
            file_info = conn.recv(BUFFER_SIZE)
            if not file_info:
                break

            file_info = file_info.decode('utf-8').split('|')
            file_size = int(file_info[[2]])
            file_checksum = int(file_info[[3]])

            # Create directory if it doesn't exist
            directory = os.path.dirname(file_path)
            if not os.path.exists(directory):
                os.makedirs(directory)

            # Check if file transfer can be resumed
            received_size = 0
            if os.path.exists(file_path):
                received_size = os.path.getsize(file_path)
                conn.send(struct.pack('!I', received_size))
            else:
                conn.send(struct.pack('!I', 0))

            start_time = time.time()

            # Receive and decrypt file data
            with open(file_path, 'ab') as file:
                while received_size < file_size:
                    try:
                        data = conn.recv(BUFFER_SIZE)
                        cipher_aes = AES.new(session_key, AES.MODE_CBC, data[:16])
                        decrypted_data = unpad(cipher_aes.decrypt(data[16:]), AES.block_size)
                        file.write(decrypted_data)
                        received_size += len(decrypted_data)

                        # Send progress update
                        progress = (received_size / file_size) * 100
                        conn.send(struct.pack('!f', progress))
                    except (socket.error, struct.error) as e:
                        logger.error(f"Error receiving file data: {str(e)}")
                        conn.send(b'FILE_TRANSFER_ERROR')
                        break

            end_time = time.time()
            transfer_time = end_time - start_time

            # Verify checksum
            try:
                calculated_checksum = memcrc(open(file_path, 'rb').read())
                if calculated_checksum != file_checksum:
                    logger.error(f"Checksum verification failed for {file_path}")
                    conn.send(b'CHECKSUM_FAILED')
                else:
                    logger.info(f"File {file_path} received successfully")
                    conn.send(b'SUCCESS')
            except IOError as e:
                logger.error(f"Error reading file for checksum verification: {str(e)}")
                conn.send(b'CHECKSUM_VERIFICATION_ERROR')

            logger.info(f"File transfer complete for {file_path}. Transfer time: {transfer_time:.2f} seconds")

    except (socket.error, struct.error) as e:
        logger.error(f"Error during client communication: {str(e)}")
    finally:
        conn.close()

def start_server(config):
    max_connections = int(config['max_connections'])

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(max_connections)
        logger.info(f"Server listening on {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='File Transfer Server')
    parser.add_argument('-p', '--port', type=int, default=PORT, help='Server port')
    parser.add_argument('-c', '--config', default='config.txt', help='Configuration file')
    args = parser.parse_args()

    PORT = args.port
    config = load_config(args.config)

    start_server(config)

