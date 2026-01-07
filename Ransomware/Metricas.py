import psutil
import os
import time
import logging
from threading import Thread, Event
import matplotlib.pyplot as plt
from SistemaECIES import encryption

logging.basicConfig(
    filename='encriptacion_errores.log',
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

DIRS = {
    "pequeños": "ruta/carpeta_pequenos",
    "medianos": "ruta/carpeta_medianos",
    "grandes": "ruta/carpeta_grandes",
}
SAMPLE_INTERVAL = 0.1

process = psutil.Process(os.getpid())
process.cpu_percent()

def monitor(stop, ram, cpu, t):
    start = time.perf_counter()
    while not stop.is_set():
        ram.append(process.memory_info().rss / 1024 / 1024)
        cpu.append(process.cpu_percent(interval=0.1))
        t.append(time.perf_counter() - start)
        time.sleep(SAMPLE_INTERVAL)

results = {}

for category, folder in DIRS.items():
    if not os.path.exists(folder):
        print(f"Error: {folder} no existe")
        continue
    
    ram, cpu, t = [], [], []
    stop = Event()
    ok = total = 0
    total_size = 0
    file_times = []
    
    monitor_thread = Thread(target=monitor, args=(stop, ram, cpu, t))
    start_total = time.perf_counter()
    monitor_thread.start()
    
    for file in os.listdir(folder):
        path = os.path.join(folder, file)
        if not os.path.isfile(path):
            continue
        
        total += 1
        file_size = os.path.getsize(path)
        total_size += file_size
        
        file_start = time.perf_counter()
        try:
            success, blob, enc_path = encryption(path, del_orig=False)
            if success:
                ok += 1
                file_times.append(time.perf_counter() - file_start)
            else:
                logging.error(f"Fallo: {path}")
        except Exception as e:
            logging.error(f"Error {path}: {str(e)}")
    
    stop.set()
    monitor_thread.join()
    end_total = time.perf_counter()
    
    results[category] = {
        "ram": ram,
        "cpu": cpu,
        "time": end_total - start_total,
        "ok": ok,
        "total": total,
        "t": t,
        "total_size_mb": total_size / 1024 / 1024,
        "avg_file_time": sum(file_times) / len(file_times) if file_times else 0,
        "throughput": (total_size / 1024 / 1024) / (end_total - start_total) if end_total - start_total > 0 else 0
    }

# RESULTADOS
print("\n" + "="*60)
print("RESULTADOS DE ENCRIPTACIÓN")
print("="*60)

for cat, d in results.items():
    print(f"\nCategoría: {cat}")
    print(f"  Archivos totales: {d['total']}")
    print(f"  Archivos exitosos: {d['ok']}")
    print(f"  Tasa de éxito: {(d['ok']/d['total'])*100:.2f}%")
    print(f"  Tamaño total: {d['total_size_mb']:.2f} MB")
    print(f"  Tiempo total: {d['time']:.2f} s")
    print(f"  Tiempo promedio/archivo: {d['avg_file_time']:.3f} s")
    print(f"  Throughput: {d['throughput']:.2f} MB/s")
    print(f"  RAM promedio: {sum(d['ram'])/len(d['ram']):.2f} MB")
    print(f"  RAM pico: {max(d['ram']):.2f} MB")
    print(f"  CPU promedio: {sum(d['cpu'])/len(d['cpu']):.2f}%")
    print(f"  CPU pico: {max(d['cpu']):.2f}%")

# GRÁFICAS INDIVIDUALES
fig, axes = plt.subplots(2, len(results), figsize=(15, 8))

for idx, (cat, d) in enumerate(results.items()):
    # RAM
    axes[0, idx].plot(d["t"], d["ram"], color='#2E86AB', linewidth=2)
    axes[0, idx].fill_between(d["t"], d["ram"], alpha=0.3, color='#2E86AB')
    axes[0, idx].set_title(f"RAM - {cat}")
    axes[0, idx].set_xlabel("Tiempo (s)")
    axes[0, idx].set_ylabel("MB")
    axes[0, idx].grid(True, alpha=0.3)
    
    # CPU
    axes[1, idx].plot(d["t"], d["cpu"], color='#A23B72', linewidth=2)
    axes[1, idx].fill_between(d["t"], d["cpu"], alpha=0.3, color='#A23B72')
    axes[1, idx].set_title(f"CPU - {cat}")
    axes[1, idx].set_xlabel("Tiempo (s)")
    axes[1, idx].set_ylabel("%")
    axes[1, idx].grid(True, alpha=0.3)

plt.tight_layout()

# GRÁFICAS COMPARATIVAS
fig, axes = plt.subplots(2, 2, figsize=(14, 10))

categories = list(results.keys())
throughputs = [results[c]['throughput'] for c in categories]
avg_times = [results[c]['avg_file_time'] for c in categories]
ram_peaks = [max(results[c]['ram']) for c in categories]
cpu_peaks = [max(results[c]['cpu']) for c in categories]

axes[0, 0].bar(categories, throughputs, color='#06A77D')
axes[0, 0].set_title("Throughput por categoría")
axes[0, 0].set_ylabel("MB/s")
axes[0, 0].grid(True, alpha=0.3, axis='y')

axes[0, 1].bar(categories, avg_times, color='#F18F01')
axes[0, 1].set_title("Tiempo promedio por archivo")
axes[0, 1].set_ylabel("Segundos")
axes[0, 1].grid(True, alpha=0.3, axis='y')

axes[1, 0].bar(categories, ram_peaks, color='#2E86AB')
axes[1, 0].set_title("RAM pico")
axes[1, 0].set_ylabel("MB")
axes[1, 0].grid(True, alpha=0.3, axis='y')

axes[1, 1].bar(categories, cpu_peaks, color='#A23B72')
axes[1, 1].set_title("CPU pico")
axes[1, 1].set_ylabel("%")
axes[1, 1].grid(True, alpha=0.3, axis='y')

plt.tight_layout()
plt.show()

