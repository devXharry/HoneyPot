import os
import socket 
import threading
import paramiko

BIND_HOST = "127.0.0.1"
BIND_PORT = 2222
HOST_KEY_FILE = "honeypot_rsa.key"

class HoneypotAuthHandler(paramiko.ServerInterface):
    def __init__(self, client_ip, client_port):
        self.client_ip = client_ip
        self.client_port = client_port

    def check_auth_password(self, username, password):
        print(f"[AUTH ATTEMPT] {self.client_ip}:{self.client_port} | User: '{username}' | Pass: '{password}'")
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        fingerprint = key.get_fingerprint().hex()
        print(f"[KEY ATTEMPT] {self.client_ip}:{self.client_port} | User: '{username}' | Key: {key.get_name()} ({fingerprint})")
        return paramiko.AUTH_FAILED

def get_or_generate_host_key(key_path):
    if not os.path.exists(key_path):
        print(f"Generating new 2048-bit RSA key at {key_path}...")
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(key_path)
        return key
    print(f"[*] Loaded existing RSA key from {key_path}")
    return paramiko.RSAKey(filename=key_path)

def handle_ssh_client(client_socket, client_address, host_key):
    ip, port = client_address
    print(f"[+] Inbound TCP connection from {ip}:{port}")
    transport = None

    try:
        transport = paramiko.Transport(client_socket)
        transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
        transport.add_server_key(host_key)

        server_interface = HoneypotAuthHandler(ip, port)
        transport.start_server(server=server_interface)

        channel = transport.accept(20)
        if channel:
            channel.close()
    except Exception as e:
        print(f"[-] SSH handshake/auth error with {ip}:{port} -> {e}")
    finally:
        if transport:
            transport.close()
        client_socket.close()
        print(f"[-] Closed connection with {ip}:{port}")

def start_server():
    host_key = get_or_generate_host_key(HOST_KEY_FILE)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((BIND_HOST, BIND_PORT))
    server.listen(10)
    print(f"[*] SSH Honeypot listening on {BIND_HOST}:{BIND_PORT}..")

    while True:
        try:
            client_sock, client_addr = server.accept()
            worker = threading.Thread(target=handle_ssh_client, args=(client_sock, client_addr, host_key), daemon=True)
            worker.start()
        except KeyboardInterrupt:
            print(f"[*] Shutting down SSH server.")
            server.close()
            break
if __name__ == "__main__":
    start_server()