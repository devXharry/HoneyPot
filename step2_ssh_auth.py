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