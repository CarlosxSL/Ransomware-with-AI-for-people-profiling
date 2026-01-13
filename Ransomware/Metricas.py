import psutil
import os
import time
import logging
import json
import sys
from threading import Thread, Event
import matplotlib.pyplot as plt
from SistemaECIES import encryption

logging.basicConfig(
    filename='encriptacion_errores.log',
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

SAMPLE_INTERVAL = 0.05  # Reducido para capturar más datos
RESULTS_DIR = r"Resultados_3"
MIN_SAMPLES = 5  # Mínimo de muestras para generar gráfica

os.makedirs(RESULTS_DIR, exist_ok=True)

process = psutil.Process(os.getpid())
process.cpu_percent()

def monitor(stop, ram, cpu, t):
    """Monitorea el uso de recursos del sistema durante la encriptación."""
    start = time.perf_counter()
    while not stop.is_set():
        ram.append(process.memory_info().rss / 1024 / 1024)
        cpu.append(process.cpu_percent(interval=0.01))
        t.append(time.perf_counter() - start)
        time.sleep(SAMPLE_INTERVAL)

def encriptar_directorio(directorio):
    """
    Encripta todos los archivos en un directorio y monitorea el rendimiento.
    
    Args:
        directorio: Ruta del directorio a encriptar
        
    Returns:
        dict: Diccionario con métricas de rendimiento y archivos encriptados
    """
    if not os.path.exists(directorio):
        print(f"Error: El directorio '{directorio}' no existe")
        return None
    
    # Contar archivos a procesar
    total = len([f for root, _, names in os.walk(directorio) for f in names 
                 if not f.endswith(".enc") and not f.startswith(".tmp_enc_")])
    
    if total == 0:
        print(f"No hay archivos para encriptar en '{directorio}'")
        return None
    
    print(f"Iniciando encriptación de {total} archivo(s)...")
    
    ram, cpu, t = [], [], []
    stop = Event()
    
    # Capturar métricas iniciales
    ram.append(process.memory_info().rss / 1024 / 1024)
    cpu.append(process.cpu_percent(interval=0.01))
    t.append(0.0)
    
    monitor_thread = Thread(target=monitor, args=(stop, ram, cpu, t), daemon=True)
    start_total = time.perf_counter()
    monitor_thread.start()
    
    # Pequeña pausa para asegurar que el monitor capture datos
    time.sleep(0.05)
    
    try:
        files = encryption(directorio)
        ok = len(files)
    except Exception as e:
        logging.error(f"Error encriptando {directorio}: {str(e)}")
        ok = 0
        files = []
    
    # Esperar un poco antes de detener el monitor
    time.sleep(0.1)
    
    # Capturar métricas finales
    elapsed = time.perf_counter() - start_total
    ram.append(process.memory_info().rss / 1024 / 1024)
    cpu.append(process.cpu_percent(interval=0.01))
    t.append(elapsed)
    
    stop.set()
    monitor_thread.join(timeout=1.0)
    
    resultados = {
        "ram": ram,
        "cpu": cpu,
        "time": elapsed,
        "ok": ok,
        "total": total,
        "t": t,
        "archivos_encriptados": files
    }
    
    return resultados

def generar_grafica(resultados, nombre_categoria):
    """Genera gráfica de métricas solo si hay suficientes datos."""
    
    if len(resultados['t']) < MIN_SAMPLES:
        print(f"⚠ Tiempo de encriptación muy breve ({resultados['time']:.3f}s)")
        print(f"  No se generó gráfica (se requieren al menos {MIN_SAMPLES} muestras)")
        return False
    
    fig, ax1 = plt.subplots(figsize=(12, 6))
    
    ax1.set_xlabel('Tiempo (s)', fontsize=12)
    ax1.set_ylabel('RAM (MB)', color='#2E86AB', fontsize=12)
    ax1.plot(resultados["t"], resultados["ram"], color='#2E86AB', 
             linewidth=2, label='Uso RAM', marker='o', markersize=3)
    ax1.fill_between(resultados["t"], resultados["ram"], alpha=0.3, color='#2E86AB')
    ax1.tick_params(axis='y', labelcolor='#2E86AB')
    ax1.grid(True, alpha=0.3, linestyle='--')
    ax1.legend(loc='upper left')
    
    ax2 = ax1.twinx()
    ax2.set_ylabel('CPU (%)', color='#A23B72', fontsize=12)
    ax2.plot(resultados["t"], resultados["cpu"], color='#A23B72', 
             linewidth=2, label='Uso CPU', marker='s', markersize=3)
    ax2.fill_between(resultados["t"], resultados["cpu"], alpha=0.3, color='#A23B72')
    ax2.tick_params(axis='y', labelcolor='#A23B72')
    ax2.legend(loc='upper right')
    
    plt.title(f'Métricas de Encriptación - {nombre_categoria}', fontsize=14, fontweight='bold')
    fig.tight_layout()
    
    ruta_imagen = os.path.join(RESULTS_DIR, f'metricas_{nombre_categoria}.png')
    plt.savefig(ruta_imagen, dpi=300, bbox_inches='tight')
    plt.close()
    
    print(f"✓ Gráfica guardada: {ruta_imagen}")
    return True

def guardar_resultados(resultados, nombre_categoria):
    """Guarda métricas y lista de archivos encriptados en formato JSON."""
    
    metricas = {
        "archivos_totales": resultados['total'],
        "archivos_exitosos": resultados['ok'],
        "tiempo_total_segundos": round(resultados['time'], 4),
        "muestras_capturadas": len(resultados['ram']),
        "ram_promedio_mb": round(sum(resultados['ram'])/len(resultados['ram']), 2) if resultados['ram'] else 0,
        "ram_pico_mb": round(max(resultados['ram']), 2) if resultados['ram'] else 0,
        "cpu_promedio_porcentaje": round(sum(resultados['cpu'])/len(resultados['cpu']), 2) if resultados['cpu'] else 0,
        "cpu_pico_porcentaje": round(max(resultados['cpu']), 2) if resultados['cpu'] else 0,
        "tasa_exito_porcentaje": round((resultados['ok']/resultados['total'])*100, 2) if resultados['total'] > 0 else 0
    }
    
    # Guardar métricas
    ruta_metricas = os.path.join(RESULTS_DIR, f'metricas_{nombre_categoria}.json')
    with open(ruta_metricas, 'w', encoding='utf-8') as f:
        json.dump(metricas, f, indent=2, ensure_ascii=False)
    
    # Guardar lista de archivos encriptados
    if resultados['archivos_encriptados']:
        ruta_archivos = os.path.join(RESULTS_DIR, f'archivos_encriptados_{nombre_categoria}.json')
        with open(ruta_archivos, 'w', encoding='utf-8') as f:
            json.dump(resultados['archivos_encriptados'], f, indent=2, ensure_ascii=False)
    
    return metricas

def imprimir_resumen(metricas, nombre_categoria):
    """Imprime un resumen de las métricas en consola."""
    print(f"\n{'='*60}")
    print(f"RESUMEN - {nombre_categoria}")
    print(f"{'='*60}")
    print(f"Archivos procesados:  {metricas['archivos_exitosos']}/{metricas['archivos_totales']}")
    print(f"Tiempo total:         {metricas['tiempo_total_segundos']:.3f} segundos")
    print(f"Tasa de éxito:        {metricas['tasa_exito_porcentaje']:.2f}%")
    print(f"\nUso de RAM:")
    print(f"  - Promedio:         {metricas['ram_promedio_mb']:.2f} MB")
    print(f"  - Pico:             {metricas['ram_pico_mb']:.2f} MB")
    print(f"\nUso de CPU:")
    print(f"  - Promedio:         {metricas['cpu_promedio_porcentaje']:.2f}%")
    print(f"  - Pico:             {metricas['cpu_pico_porcentaje']:.2f}%")
    print(f"{'='*60}\n")

# Ejecución principal sin main ni argv
directorio_a_encriptar = "Archivos"  # Cambiar según sea necesario
categoria_nombre = "Cifrado_53GB"  # Sirve para nombrar archivos de resultados
resultados = encriptar_directorio(directorio_a_encriptar)

if resultados:
    metricas = guardar_resultados(resultados, categoria_nombre)
    imprimir_resumen(metricas, categoria_nombre)
    generar_grafica(resultados, categoria_nombre)







