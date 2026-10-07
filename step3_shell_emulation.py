import os
import paramiko
import socket
import threading

BIND_HOST = "127.0.0.1"
BIND_PORT = 2222
HOST_KEY_FILE = "honeypot_rsa.key"

class HoneypotShellHandler(paramiko.ServerInterface):
    def __init__(self, client_ip, client_port):
        self.client_ip = client_ip
        self.client_port = client_port
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        print(f"[AUTH SUCCESS] {self.client_ip}:{self.client_port} | User: '{username}' | Pass: {password}")    
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command):
        cmd_str = command.decode("utf-8", errors="replace")
        print(f"[EXEC COMMAND] {self.client_ip}:{self.client_port} -> '{cmd_str}'")
        channel.send(b"bash: command not found\r\n")
        channel.send_exit_status(127)
        channel.close()
        return True

def interactive_shell(channel, client_ip, client_port):
    prompt = b"root@srv-ubuntu:~#"
    channel.send(b"Linux srv-ubuntu 5.15.0-88-generic #98-ubuntu SMP x86_64\r\n\r\n" + prompt)

    buffer = " "
    while True:
        try:
            byte_chunk = channel.recv(1024)
            if not byte_chunk:
                break

            char = byte_chunk.decode("utf-8", errors="replace")
            for c in char:
                if c in ("\r", "\n"):
                    channel.send(b"\r\n")
                    cmd = buffer.strip()
                    if cmd:
                        print(f"[COMMAND CAPTURED] {client_ip}:{client_port} -> '{cmd}'")
                        if cmd in ("exit", "logout", "quit"):
                            channel.send(b"logout\r\n")
                            channel.clode()
                            return

                        if cmd == "id":
                            channel.send(b"uid=0(root) gid=0(root) groups=0(root)\r\n")
                        elif cmd == "whoami":
                            channel.send(b"root\r\n")
                        elif cmd == "uname -a":
                            channel.send(b"Linux srv-ubuntu 5.15.0-88-generic #98-Ubuntu SMP x86_64\r\n")
                        else:
                            channel.send(f"bash: {cmd}: command not found\r\n".encode("utf-8"))
                    buffer = ""
                    channel.send(prompt)
                elif c in ("\x7f", "\x08"):
                    if len(buffer) > 0:
                        buffer = buffer[:-1]
                        channel.send(b"\b \b")
                else:
                    buffer += c
                    channel.send(c.encode("utf-8"))
        except Exception:
            break
    channel.close()