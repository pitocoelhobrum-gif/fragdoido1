import socket
import threading
import struct

HOST = '0.0.0.0'
import os
# O Render vai definir a variável PORT, se não existir (no seu PC) ele usa 5000
PORT = int(os.environ.get("PORT", 5000))

# Senha de segurança (máximo 32 caracteres)
SENHA_SECRETA = "minha_senha_123"

remotos = {}
lock = threading.Lock()

def recv_exact(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def handle_client(conn, addr):
    try:
        # 1. Lê a senha (sempre 32 caracteres)
        senha_recebida = recv_exact(conn, 32)
        if not senha_recebida:
            conn.close()
            return

        senha_texto = senha_recebida.decode('utf-8').strip()
        
        if senha_texto != SENHA_SECRETA:
            print(f"[!] BLOQUEADO: Senha incorreta de {addr}")
            conn.close()
            return

        # 2. Lê o cabeçalho (R ou C + ID)
        header = recv_exact(conn, 5)
        if not header:
            conn.close()
            return

        role = header[0:1]
        client_id = struct.unpack('>I', header[1:5])[0]

        print(f"Nova conexão autenticada: {addr} | role={role} | id={client_id}")

        if role == b'R':  # Computador remoto
            with lock:
                remotos[client_id] = conn
            print(f"Remoto {client_id} registrado")

            while True:
                data = conn.recv(4096)
                if not data:
                    break

        elif role == b'C':  # Controlador
            with lock:
                remoto_conn = remotos.get(client_id)

            if remoto_conn is None:
                print(f"Remoto {client_id} não está online")
                conn.close()
                return

            print(f"Controlador conectado ao remoto {client_id}")

            def forward(src, dst):
                try:
                    while True:
                        data = src.recv(4096)
                        if not data:
                            break
                        dst.sendall(data)
                except:
                    pass
                finally:
                    try:
                        src.close()
                        dst.close()
                    except:
                        pass

            t1 = threading.Thread(target=forward, args=(conn, remoto_conn), daemon=True)
            t2 = threading.Thread(target=forward, args=(remoto_conn, conn), daemon=True)
            t1.start()
            t2.start()
            t1.join()
            t2.join()

    except Exception as e:
        print("Erro:", e)
    finally:
        conn.close()
        with lock:
            for k, v in list(remotos.items()):
                if v == conn:
                    del remotos[k]
                    print(f"Remoto {k} removido")

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(10)
        print(f"Relay rodando na porta {PORT}")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == '__main__':
    main()