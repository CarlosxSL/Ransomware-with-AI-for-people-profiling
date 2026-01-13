from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def generar_par_claves_ecc():
    """
    Genera un nuevo par de claves ECC (privada y pública).
    Guarda la privada en archivo y muestra la pública para hardcodear.
    """
    # Generar clave privada ECC con curva secp256r1 (misma que tienes)
    clave_privada = ec.generate_private_key(
        ec.SECP256R1(),
        default_backend()
    )
    
    # Guardar clave privada en archivo .pem
    pem_privada = clave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # Sin contraseña
    )
    
    with open('prikey.pem', 'wb') as f:
        f.write(pem_privada)
    print("✓ Clave privada guardada en: privkey.pem")
    
    # Extraer y guardar clave pública
    clave_publica = clave_privada.public_key()
    pem_publica = clave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    with open('pubkey.pem', 'wb') as f:
        f.write(pem_publica)
    print("✓ Clave pública guardada en: pubkey.pem")
    
    # Mostrar clave pública para hardcodear
    print("\n=== CLAVE PÚBLICA PARA HARDCODEAR ===")
    print(pem_publica.decode())
    
    return pem_privada.decode(), pem_publica.decode()

# Generar nuevas claves
generar_par_claves_ecc()
