# 🛡️ Windows Threat Monitor

Herramienta de escritorio en Python para el monitoreo de procesos y detección de comportamiento sospechoso (malware, procesos intrusos, masquerading) en sistemas Windows.

Desarrollada como proyecto práctico dentro de mi formación en Ciberseguridad (ITSE — Instituto Técnico Superior Especializado).

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 📋 Descripción

**Windows Threat Monitor** combina un **sensor de escaneo** (`senor.py`) que recolecta un snapshot completo de los procesos activos del sistema, con una **interfaz gráfica** (`main_ui.py`) que visualiza los resultados, resalta procesos sospechosos y permite responder terminándolos directamente.

No reemplaza un EDR/antivirus real — es un proyecto educativo que demuestra el flujo completo de una herramienta de *threat detection*: recolección de datos → heurísticas de análisis → visualización → respuesta.

## ✨ Características

- **Recolección de metadatos por proceso:** PID, PPID, nombre, ruta del ejecutable, usuario propietario, línea de comandos, hash SHA256, uso de CPU/memoria, hilos y conexiones de red activas.
- **Motor de heurísticas de detección:**
  - Ejecutables sin ruta accesible en disco (posible proceso oculto o eliminado tras su ejecución)
  - Ejecución desde rutas típicamente usadas por malware (`Temp`, `AppData`, `Downloads`, `/tmp`)
  - *Process masquerading*: procesos con nombres de binarios críticos de Windows (`svchost.exe`, `lsass.exe`, `csrss.exe`, etc.) ejecutándose desde rutas no estándar
  - Conexiones salientes hacia puertos comúnmente asociados a C2/backdoors
  - Volumen anómalo de conexiones de red simultáneas
  - Consumo de CPU sostenido y elevado
  - Lista blanca de pseudo-procesos legítimos del sistema (`System`, `Registry`, `System Idle Process`) para evitar falsos positivos
- **Interfaz gráfica (Tkinter):**
  - Tabla completa de procesos con resaltado visual de alertas
  - Filtro de búsqueda por nombre, ruta o usuario
  - Vista de "solo sospechosos"
  - Panel de detalle que explica la razón exacta de cada alerta
  - Botón de respuesta activa: terminar un proceso (`taskkill /F`) con confirmación y protección contra terminar procesos críticos del sistema o el propio monitor
- **Exportación estructurada:** genera `system_snapshot.json` (snapshot completo) y `alerts.json` (solo hallazgos sospechosos), listos para integrarse en otros pipelines de análisis.

## 🖼️ Capturas de pantalla

> _Agrega aquí capturas de la interfaz una vez subida al repo (arrástralas al README en GitHub o colócalas en una carpeta `/screenshots`)._

## 🛠️ Stack tecnológico

| Componente        | Tecnología           |
|-------------------|-----------------------|
| Lenguaje          | Python 3.10+          |
| Recolección de datos | [psutil](https://pypi.org/project/psutil/) |
| Interfaz gráfica  | Tkinter                |
| Procesamiento de datos | pandas             |
| Empaquetado        | PyInstaller            |

## 📦 Instalación

```bash
git clone https://github.com/<tu-usuario>/windows-threat-monitor.git
cd windows-threat-monitor
python -m venv venv
.\venv\Scripts\Activate.ps1        # Windows PowerShell
pip install -r requirements.txt
```

## ▶️ Uso

Ejecutar solo el sensor de escaneo (genera los archivos JSON):

```bash
python senor.py
```

Ejecutar la interfaz gráfica completa:

```bash
python main_ui.py
```

> ⚠️ **Recomendado ejecutar como Administrador** en Windows para que el sensor pueda leer el usuario propietario de procesos protegidos del sistema (`lsass.exe`, `services.exe`, etc.). Sin privilegios elevados, esos datos no estarán disponibles, aunque el sensor ya no los marca como sospechosos solo por esa razón.

### Compilar como ejecutable (opcional)

```bash
pip install pyinstaller
pyinstaller --onefile senor.py
pyinstaller --onefile --windowed main_ui.py
```

Copia ambos `.exe` generados en `dist/` a la misma carpeta antes de ejecutarlos.

## 📁 Estructura del proyecto

```
windows-threat-monitor/
├── senor.py              # Sensor: escanea procesos y genera los JSON
├── main_ui.py             # Interfaz gráfica (Tkinter)
├── requirements.txt
├── system_snapshot.json   # Generado al ejecutar (no versionar)
├── alerts.json             # Generado al ejecutar (no versionar)
└── README.md
```

## ⚠️ Disclaimer

Este proyecto fue desarrollado con fines educativos como parte de mi formación en ciberseguridad. Las heurísticas de detección son reglas simples y no sustituyen soluciones EDR/antivirus comerciales. Úsalo bajo tu propia responsabilidad, especialmente la función de terminación de procesos (`taskkill`), que es una acción irreversible sobre el sistema.

## 👤 Autor

**Agustín Batista** — Estudiante de Técnico Superior en Ciberseguridad, ITSE
[LinkedIn](https://www.linkedin.com/) · Panamá

## 📄 Licencia

MIT — libre para usar, modificar y distribuir con atribución.
