"""
monitor_seguridad.py
---------------------
Script de snapshot del sistema orientado a detección de malware,
procesos sospechosos e intrusos (conexiones anómalas).

Uso:
    python monitor_seguridad.py

Salida:
    system_snapshot.json  -> snapshot completo (todos los procesos)
    alerts.json           -> solo los hallazgos marcados como sospechosos

Requisitos:
    pip install psutil
"""

import psutil
import json
import hashlib
import socket
import os
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Configuración de heurísticas (ajustable según el entorno a monitorear)
# ---------------------------------------------------------------------------

# Rutas típicas usadas por malware para ejecutarse (persistencia, evasión de UAC, etc.)
RUTAS_SOSPECHOSAS = [
    os.path.expandvars(r"%TEMP%").lower(),
    os.path.expandvars(r"%APPDATA%").lower(),
    os.path.expandvars(r"%PUBLIC%").lower(),
    r"\downloads\\",
    r"/tmp/",
    r"/dev/shm/",
]

# Puertos comúnmente asociados a C2 / backdoors / servicios que no deberían
# estar expuestos sin control (ajustar según tu política)
PUERTOS_SOSPECHOSOS = {4444, 1337, 31337, 6666, 6667, 12345, 54321}

# Nombres de procesos legítimos del sistema que, si aparecen con una ruta
# de ejecución distinta a la esperada, son señal de "process masquerading"
PROCESOS_CRITICOS_WINDOWS = {
    "svchost.exe": r"c:\windows\system32",
    "explorer.exe": r"c:\windows",
    "csrss.exe": r"c:\windows\system32",
    "lsass.exe": r"c:\windows\system32",
    "winlogon.exe": r"c:\windows\system32",
}

# Pseudo-procesos del kernel y binarios protegidos del SO: por diseño no
# tienen ruta de ejecutable legible ni usuario visible sin privilegios de
# administrador. NO deben marcarse como sospechosos solo por eso.
PROCESOS_SISTEMA_LEGITIMOS = {
    "system idle process", "system", "registry", "memory compression",
    "secure system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "fontdrvhost.exe",
    "wudfhost.exe", "dwm.exe", "lsaiso.exe",
}


def calcular_hash_archivo(ruta, algoritmo="sha256", bloque=65536):
    """Calcula el hash de un binario para poder compararlo contra
    listas de IOC (Indicadores de Compromiso) o VirusTotal."""
    if not ruta or not os.path.isfile(ruta):
        return None
    h = hashlib.new(algoritmo)
    try:
        with open(ruta, "rb") as f:
            while chunk := f.read(bloque):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return None


def obtener_conexiones(proc):
    """Extrae conexiones de red del proceso con detalle estructurado
    (no como string plano) para poder filtrarlas y analizarlas después."""
    conexiones = []
    try:
        for conn in proc.net_connections(kind="inet"):
            conexiones.append({
                "familia": str(conn.family),
                "tipo": str(conn.type),
                "direccion_local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                "direccion_remota": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                "estado": conn.status,
            })
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        pass
    return conexiones


def evaluar_sospecha(info):
    """Aplica un conjunto de heurísticas simples y devuelve la lista
    de razones por las que un proceso podría ser sospechoso."""
    razones = []
    ruta = (info.get("ruta_ejecutable") or "").lower()
    nombre = (info.get("nombre") or "").lower()
    es_proceso_sistema = nombre in PROCESOS_SISTEMA_LEGITIMOS

    # 1. Ejecutable ausente en disco (proceso empaquetado / borrado tras ejecutarse).
    #    Se excluyen los pseudo-procesos del kernel (System, Registry, etc.), que
    #    JAMÁS tienen ruta de ejecutable por diseño, no porque sean sospechosos.
    if info.get("ruta_ejecutable") is None and not es_proceso_sistema:
        razones.append("Sin ruta de ejecutable accesible (posible proceso oculto/eliminado)")

    # 2. Ejecutándose desde una ruta típicamente usada por malware
    if any(r in ruta for r in RUTAS_SOSPECHOSAS if r):
        razones.append("Ejecutándose desde una ruta comúnmente usada por malware (Temp/AppData/Downloads)")

    # 3. Suplantación de nombre de proceso crítico del sistema
    #    (aquí SÍ interesa comparar la ruta real, por eso no se excluye)
    if nombre in PROCESOS_CRITICOS_WINDOWS and ruta and PROCESOS_CRITICOS_WINDOWS[nombre] not in ruta:
        razones.append(f"Nombre de proceso crítico '{nombre}' ejecutándose desde ruta no estándar (posible masquerading)")

    # 4. Proceso sin nombre de usuario propietario.
    #    Sin privilegios de administrador, Windows oculta el usuario de TODOS los
    #    procesos protegidos del sistema — eso es normal, no es una alerta.
    #    Solo se marca si NO es un proceso de sistema conocido.
    if not info.get("usuario") and not es_proceso_sistema:
        razones.append("No se pudo determinar el usuario propietario del proceso (revisar con privilegios de administrador)")

    # 5. Conexiones hacia puertos sospechosos
    puertos_remotos = set()
    for c in info.get("conexiones", []):
        if c["direccion_remota"]:
            try:
                puertos_remotos.add(int(c["direccion_remota"].rsplit(":", 1)[1]))
            except (ValueError, IndexError):
                pass
    puertos_hallados = puertos_remotos & PUERTOS_SOSPECHOSOS
    if puertos_hallados:
        razones.append(f"Conexión saliente a puerto(s) típicamente asociados a C2/backdoor: {sorted(puertos_hallados)}")

    # 6. Volumen inusual de conexiones simultáneas (posible escaneo, exfiltración o botnet)
    if len(info.get("conexiones", [])) > 20:
        razones.append(f"Número inusualmente alto de conexiones de red simultáneas ({len(info['conexiones'])})")

    # 7. Alto consumo de CPU sostenido en un proceso sin ventana/interfaz visible
    if info.get("cpu_percent", 0) and info["cpu_percent"] > 80:
        razones.append(f"Consumo de CPU muy elevado ({info['cpu_percent']}%)")

    return razones


def get_system_snapshot():
    procesos = []
    campos = [
        "pid", "ppid", "name", "exe", "username", "cmdline",
        "create_time", "status", "cpu_percent", "memory_percent",
        "num_threads",
    ]

    for proc in psutil.process_iter(campos):
        try:
            info = proc.info
            ruta = info.get("exe")

            entrada = {
                "pid": info.get("pid"),
                "pid_padre": info.get("ppid"),
                "nombre": info.get("name"),
                "ruta_ejecutable": ruta,
                "hash_sha256": calcular_hash_archivo(ruta),
                "usuario": info.get("username"),
                "linea_comando": info.get("cmdline"),
                "fecha_inicio": datetime.fromtimestamp(
                    info["create_time"], tz=timezone.utc
                ).isoformat() if info.get("create_time") else None,
                "estado": info.get("status"),
                "cpu_percent": info.get("cpu_percent"),
                "memoria_percent": round(info.get("memory_percent") or 0, 2),
                "num_hilos": info.get("num_threads"),
                "conexiones": obtener_conexiones(proc),
            }

            entrada["sospechoso"] = False
            entrada["razones_alerta"] = evaluar_sospecha(entrada)
            if entrada["razones_alerta"]:
                entrada["sospechoso"] = True

            procesos.append(entrada)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return procesos


def es_administrador():
    """Detecta si el script corre con privilegios elevados (solo Windows)."""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return None  # No es Windows o no se pudo determinar


def main():
    admin = es_administrador()
    if admin is False:
        print("AVISO: no se está ejecutando como Administrador.")
        print("Algunos procesos protegidos del sistema no expondrán su usuario/ruta,")
        print("pero ya no se marcarán como sospechosos por esa sola razón.")
        print("Para un escaneo completo, ejecuta la terminal 'Como administrador'.\n")

    snapshot = {
        "metadata": {
            "host": socket.gethostname(),
            "fecha_escaneo": datetime.now(timezone.utc).isoformat(),
            "total_procesos": 0,
            "total_alertas": 0,
        },
        "procesos": [],
    }

    procesos = get_system_snapshot()
    snapshot["procesos"] = procesos
    snapshot["metadata"]["total_procesos"] = len(procesos)

    alertas = [p for p in procesos if p["sospechoso"]]
    snapshot["metadata"]["total_alertas"] = len(alertas)

    with open("system_snapshot.json", "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=4, ensure_ascii=False)

    with open("alerts.json", "w", encoding="utf-8") as f:
        json.dump(alertas, f, indent=4, ensure_ascii=False)

    print(f"Escaneo completado: {len(procesos)} procesos analizados.")
    print(f"Alertas generadas: {len(alertas)} -> revisa alerts.json")
    print("Snapshot completo guardado en system_snapshot.json")


if __name__ == "__main__":
    main()
