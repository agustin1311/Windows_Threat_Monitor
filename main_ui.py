"""
main_ui.py
----------
Interfaz gráfica para "Windows Threat Monitor".
Ejecuta senor.py (el sensor de escaneo) y muestra el resultado de
system_snapshot.json en una tabla, resaltando en rojo los procesos
marcados como sospechosos.

Requisitos:
    pip install pandas
    (tkinter viene incluido con Python en Windows)
"""

import tkinter as tk
from tkinter import ttk, messagebox
import pandas as pd
import json
import subprocess
import os
import sys


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Windows Threat Monitor")
        self.geometry("1100x600")

        # Ruta base: funciona tanto ejecutado como .py como empaquetado (.exe)
        if getattr(sys, "frozen", False):
            self.base_path = os.path.dirname(sys.executable)
        else:
            self.base_path = os.path.dirname(os.path.abspath(__file__))

        self.sensor_path = os.path.join(self.base_path, "senor.py")
        self.json_path = os.path.join(self.base_path, "system_snapshot.json")

        # --- Barra superior: botón + búsqueda ---
        barra = tk.Frame(self)
        barra.pack(fill="x", padx=10, pady=10)

        self.btn_scan = tk.Button(barra, text="Actualizar Escaneo", command=self.ejecutar_y_cargar)
        self.btn_scan.pack(side="left")

        tk.Label(barra, text="Filtrar:").pack(side="left", padx=(20, 5))
        self.filtro_var = tk.StringVar()
        self.filtro_var.trace_add("write", lambda *_: self.aplicar_filtro())
        tk.Entry(barra, textvariable=self.filtro_var, width=30).pack(side="left")

        self.solo_sospechosos_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            barra, text="Mostrar solo sospechosos",
            variable=self.solo_sospechosos_var,
            command=self.aplicar_filtro
        ).pack(side="left", padx=20)

        self.btn_kill = tk.Button(
            barra, text="Terminar Proceso (taskkill)",
            command=self.terminar_proceso_seleccionado,
            bg="#c0392b", fg="white", state="disabled"
        )
        self.btn_kill.pack(side="right")

        # --- Tabla ---
        columns = ('PID', 'PPID', 'Nombre', 'Usuario', 'Ruta', 'Hash SHA256',
                   'CPU %', 'Mem %', 'Conexiones', 'Sospechoso')
        self.tree = ttk.Treeview(self, columns=columns, show='headings')

        anchos = {
            'PID': 60, 'PPID': 60, 'Nombre': 130, 'Usuario': 110,
            'Ruta': 220, 'Hash SHA256': 140, 'CPU %': 60, 'Mem %': 60,
            'Conexiones': 90, 'Sospechoso': 90
        }
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=anchos.get(col, 100))

        self.tree.tag_configure("sospechoso", background="#ffcccc")
        self.tree.pack(expand=True, fill='both', padx=10, pady=(0, 5))

        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.place(relx=1.0, rely=0.08, relheight=0.85, anchor="ne")

        # Al seleccionar una fila, mostrar detalle de por qué está marcada
        self.tree.bind("<<TreeviewSelect>>", self.mostrar_detalle)
        self.detalle_var = tk.StringVar(value="Selecciona un proceso para ver detalles / razones de alerta.")
        tk.Label(self, textvariable=self.detalle_var, anchor="w", justify="left",
                 wraplength=1060, fg="#900000").pack(fill="x", padx=10, pady=(0, 5))

        # --- Barra de estado ---
        self.status_var = tk.StringVar(value="Sin datos cargados todavía.")
        tk.Label(self, textvariable=self.status_var, anchor="w", relief="sunken").pack(fill="x", side="bottom")

        self.df = pd.DataFrame()
        self.razones_por_pid = {}

        # PIDs que NUNCA deben poder terminarse desde la UI (evita tumbar el sistema
        # o matar el propio script sin querer)
        self.pids_protegidos = {0, 4, os.getpid()}

        # Cargar datos existentes si ya hay un snapshot previo
        if os.path.exists(self.json_path):
            self.cargar_datos()

    def ejecutar_y_cargar(self):
        if not os.path.exists(self.sensor_path):
            messagebox.showerror("Error", f"No se encontró el sensor:\n{self.sensor_path}")
            return

        self.btn_scan.config(state="disabled", text="Escaneando...")
        self.update_idletasks()

        try:
            resultado = subprocess.run(
                [sys.executable, self.sensor_path],
                cwd=self.base_path,
                capture_output=True, text=True, timeout=120
            )
            if resultado.returncode != 0:
                messagebox.showerror(
                    "Error al ejecutar el sensor",
                    resultado.stderr or "El sensor terminó con un error desconocido."
                )
                return
        except subprocess.TimeoutExpired:
            messagebox.showerror("Error", "El sensor tardó demasiado y fue cancelado.")
            return
        finally:
            self.btn_scan.config(state="normal", text="Actualizar Escaneo")

        self.cargar_datos()

    def cargar_datos(self):
        if not os.path.exists(self.json_path):
            messagebox.showwarning("Aviso", "No se encontró system_snapshot.json todavía.")
            return

        with open(self.json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # senor.py guarda {"metadata": {...}, "procesos": [...]}
        procesos = data.get("procesos", data if isinstance(data, list) else [])
        metadata = data.get("metadata", {})

        self.df = pd.DataFrame(procesos)
        self.razones_por_pid = {
            p.get("pid"): p.get("razones_alerta", []) for p in procesos
        }

        self.aplicar_filtro()

        total = metadata.get("total_procesos", len(procesos))
        alertas = metadata.get("total_alertas", sum(1 for p in procesos if p.get("sospechoso")))
        fecha = metadata.get("fecha_escaneo", "N/D")
        self.status_var.set(f"Procesos: {total}  |  Alertas: {alertas}  |  Último escaneo: {fecha}")

    def aplicar_filtro(self):
        for i in self.tree.get_children():
            self.tree.delete(i)

        if self.df.empty:
            return

        df = self.df
        texto = self.filtro_var.get().strip().lower()
        if texto:
            mascara = df.apply(
                lambda fila: texto in str(fila.get("nombre", "")).lower()
                or texto in str(fila.get("ruta_ejecutable", "")).lower()
                or texto in str(fila.get("usuario", "")).lower(),
                axis=1
            )
            df = df[mascara]

        if self.solo_sospechosos_var.get():
            df = df[df.get("sospechoso", False) == True]  # noqa: E712

        for _, row in df.iterrows():
            conexiones = row.get("conexiones", [])
            n_conexiones = len(conexiones) if isinstance(conexiones, list) else 0
            es_sospechoso = bool(row.get("sospechoso", False))

            self.tree.insert(
                "", "end",
                values=(
                    row.get("pid"),
                    row.get("pid_padre"),
                    row.get("nombre"),
                    row.get("usuario"),
                    str(row.get("ruta_ejecutable") or "")[:40],
                    str(row.get("hash_sha256") or "N/D")[:16],
                    row.get("cpu_percent"),
                    row.get("memoria_percent"),
                    n_conexiones,
                    "SÍ" if es_sospechoso else "no",
                ),
                tags=("sospechoso",) if es_sospechoso else ()
            )

    def mostrar_detalle(self, _event):
        seleccion = self.tree.selection()
        if not seleccion:
            self.btn_kill.config(state="disabled")
            return

        valores = self.tree.item(seleccion[0], "values")
        pid = int(valores[0]) if valores[0] not in (None, "") else None
        razones = self.razones_por_pid.get(pid, [])
        if razones:
            self.detalle_var.set(f"PID {pid} — Razones de alerta: " + "; ".join(razones))
        else:
            self.detalle_var.set(f"PID {pid} — Sin alertas registradas.")

        # No permitir intentar terminar procesos protegidos (se deshabilita el botón)
        self.btn_kill.config(state="disabled" if pid in self.pids_protegidos else "normal")

    def terminar_proceso_seleccionado(self):
        seleccion = self.tree.selection()
        if not seleccion:
            return

        valores = self.tree.item(seleccion[0], "values")
        pid = int(valores[0])
        nombre = valores[2]

        if pid in self.pids_protegidos:
            messagebox.showwarning(
                "Acción bloqueada",
                f"El PID {pid} ({nombre}) es un proceso protegido del sistema o el propio "
                "monitor, y no se puede terminar desde aquí."
            )
            return

        confirmar = messagebox.askyesno(
            "Confirmar terminación de proceso",
            f"¿Seguro que quieres terminar el proceso?\n\n"
            f"PID: {pid}\nNombre: {nombre}\n\n"
            "Esta acción es inmediata y puede causar pérdida de datos no guardados "
            "o inestabilidad si el proceso es importante para el sistema.",
            icon="warning"
        )
        if not confirmar:
            return

        if sys.platform != "win32":
            messagebox.showerror(
                "No disponible",
                "taskkill es exclusivo de Windows. En este sistema operativo no se puede "
                "ejecutar esta acción."
            )
            return

        try:
            resultado = subprocess.run(
                ["taskkill", "/PID", str(pid), "/F"],
                capture_output=True, text=True, timeout=10
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            messagebox.showerror("Error", f"No se pudo ejecutar taskkill:\n{e}")
            return

        if resultado.returncode == 0:
            messagebox.showinfo("Proceso terminado", resultado.stdout.strip() or f"PID {pid} terminado.")
            # Quitar la fila de la tabla sin tener que re-escanear todo
            self.tree.delete(seleccion[0])
            if not self.df.empty:
                self.df = self.df[self.df["pid"] != pid]
            self.btn_kill.config(state="disabled")
        else:
            messagebox.showerror(
                "No se pudo terminar el proceso",
                resultado.stderr.strip() or resultado.stdout.strip()
                or "taskkill falló. Puede que necesites ejecutar el programa como Administrador."
            )


if __name__ == "__main__":
    app = App()
    app.mainloop()
