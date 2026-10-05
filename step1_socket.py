import socket
import threading

BIND_HOST = "127.0.0.1"
BIND_PORT = 2222

def handle_client(client_socket, client_address):
    ip, port = client_address
    print(f"[*] Inbound connection accepted from {ip}:{port}")
    try:
        data = client_socket.recv(1024)
        if data:
            print(f"[*] Payload received from {ip}:{port} -> {data}")
    except Exception as e:
        print("[-] Socket read error on {ip}:{port} -> {e}")
    finally:
        client_socket.close()
        print(f"[-] Closed sonnnection with {ip}:{port}")

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((BIND_HOST, BIND_PORT))
    server.listen(5)
    print(f"[*] Listening for connection on {BIND_HOST} : {BIND_PORT}")

    while True:
        try:
            client_sock, client_addr = server.accept()
            worker = threading.Thread(target=handle_client, arg=(client_sock,client_addr), daemon=True)
            worker.start()

        except KeyboardInterrupt:
            print("\n[*] Shutting doen server socket.")
            server.close()
            break
if __name__ == "__main__":
    start_server()