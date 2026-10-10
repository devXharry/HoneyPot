import json
import os
import socket
import paramiko
import threading
from datetime import datetime, timezone

BIND_HOST = "127.0.0.1"
BIND_PORT = 2222
HOST_KEY_FILE = "honeypot_rsa.key"
LOG_FILE = "honeypot_events.jsonl"

log_lock = threading.Lock()

def log_event(event_type: str, client_ip: str, client_port: int, details: dict):
    """Formats and appends a single structured JSON event line to disk."""
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "src_ip": client_ip,
        "src_port": client_port,
        "details": details,
    }

    line = json.dumps(event)

    with log_lock:
        with open(LOG_FILE, "a", encoding="utf-8") as f:f.write(line +"\n")

    print(f'[{event_type.upper()} {client_ip}:{client_port} -> {details}]')


class HoneypotShellHandler(paramiko.ServerInterface):
    def __init__(self, client_ip: str, client_port: int):
        self.client_ip = client_ip
        self.client_port = client_port
        self.event = threading.Event()

    def check_auth_password(self, username: str, password: str) -> int:
        # Log intercepted credentials
        log_event(
            event_type="auth_attempt",
            client_ip=self.client_ip,
            client_port=self.client_port,
            details={
                "username": username,
                "password": password,
                "auth_method": "password",
            },
        )
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        log_event(
            event_type="auth_attempt",
            client_ip=self.client_ip,
            client_port=self.client_port,
            details={
                "username": username,
                "key_fingerprint": key.get_fingerprint().hex(),
                "key_name": key.get_name(),
                "auth_method": "publickey",
            },
        )
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes) -> bool:
        return True

    def check_channel_shell_request(self, channel) -> bool:
        self.event.set()
        return True

    def check_channel_exec_request(self, channel, command: bytes) -> bool:
        cmd_str = command.decode("utf-8", errors="replace")
        log_event(
            event_type="command_exec",
            client_ip=self.client_ip,
            client_port=self.client_port,
            details={"command": cmd_str, "interactive": False},
        )
        channel.send(b"bash: command not found\r\n")
        channel.send_exit_status(127)
        channel.close()
        return True


def interactive_shell(channel: paramiko.Channel, client_ip: str, client_port: int):
    prompt = b"root@srv-ubuntu:~# "
    channel.send(b"Linux srv-ubuntu 5.15.0-88-generic #98-Ubuntu SMP x86_64\r\n\r\n" + prompt)

    buffer = ""
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
                        log_event(
                            event_type="command_exec",
                            client_ip=client_ip,
                            client_port=client_port,
                            details={"command": cmd, "interactive": True},
                        )
                        if cmd in ("exit", "logout", "quit"):
                            channel.send(b"logout\r\n")
                            channel.close()
                            return

                        # Mock shell feedback
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


def handle_ssh_client(client_socket: socket.socket, client_address: tuple, host_key: paramiko.RSAKey):
    ip, port = client_address
    log_event("connection_opened", ip, port, {})
    transport = None

    try:
        transport = paramiko.Transport(client_socket)
        transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
        transport.add_server_key(host_key)

        server_interface = HoneypotShellHandler(ip, port)
        transport.start_server(server=server_interface)

        channel = transport.accept(20)
        if channel:
            server_interface.event.wait(10)
            interactive_shell(channel, ip, port)
    except Exception as e:
        log_event("session_error", ip, port, {"error": str(e)})
    finally:
        log_event("connection_closed", ip, port, {})
        if transport:
            transport.close()
        client_socket.close()


def get_or_generate_host_key(key_path: str):
    if not os.path.exists(key_path):
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(key_path)
        return key
    return paramiko.RSAKey(filename=key_path)


def start_server():
    host_key = get_or_generate_host_key(HOST_KEY_FILE)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((BIND_HOST, BIND_PORT))
    server.listen(10)
    print(f"[*] Honeypot with JSONL logging listening on {BIND_HOST}:{BIND_PORT}...")

    while True:
        try:
            client_sock, client_addr = server.accept()
            worker = threading.Thread(
                target=handle_ssh_client,
                args=(client_sock, client_addr, host_key),
                daemon=True,
            )
            worker.start()
        except KeyboardInterrupt:
            print("\n[*] Shutting down honeypot daemon.")
            server.close()
            break


if __name__ == "__main__":
    start_server()