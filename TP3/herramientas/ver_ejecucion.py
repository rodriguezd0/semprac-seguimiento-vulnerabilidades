"""Visor de evidencia. Ejecuta el prototipo Java con sus entradas guionadas.

Desde TP3, después de compilar: python herramientas/ver_ejecucion.py
El visor muestra stdout sin modificarlo. No forma parte de la interfaz del sistema.
"""
from pathlib import Path
import subprocess
import sys
import tkinter as tk
from tkinter import ttk

BASE = Path(__file__).resolve().parents[1]
CLASES = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else BASE / "bin"
SESIONES = {
    "Administrador": "entrada_01_administrador.txt",
    "Cliente": "entrada_02_cliente.txt",
    "Errores de carga": "entrada_03_errores.txt",
}

raiz = tk.Tk()
raiz.title("TP3 - Ejecución de app.MenuConsola")
raiz.geometry("1420x820+30+30")
barra = ttk.Frame(raiz, padding=8)
barra.pack(fill="x")
ttk.Label(barra, text="Sesión").pack(side="left", padx=(0, 8))
sesion = ttk.Combobox(barra, values=list(SESIONES), state="readonly", width=24)
sesion.current(0)
sesion.pack(side="left")
estado = ttk.Label(barra)
estado.pack(side="right")
marco = ttk.Frame(raiz)
marco.pack(fill="both", expand=True)
salida = tk.Text(marco, wrap="none", font=("Consolas", 13), padx=12, pady=8,
                 background="white", foreground="#202020", state="disabled")
vertical = ttk.Scrollbar(marco, orient="vertical", command=salida.yview)
horizontal = ttk.Scrollbar(marco, orient="horizontal", command=salida.xview)
salida.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
vertical.pack(side="right", fill="y")
horizontal.pack(side="bottom", fill="x")
salida.pack(fill="both", expand=True)


def ejecutar():
    entrada = BASE / "entradas" / SESIONES[sesion.get()]
    resultado = subprocess.run(
        ["java", "-Dstdout.encoding=UTF-8", "-cp", str(CLASES), "app.MenuConsola", "-eco"],
        input=entrada.read_bytes(), capture_output=True, timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    texto = resultado.stdout.decode("utf-8") + resultado.stderr.decode("utf-8")
    salida.configure(state="normal")
    salida.delete("1.0", "end")
    salida.insert("1.0", texto)
    salida.configure(state="disabled")
    estado.configure(text=f"Java 21 | Código de salida {resultado.returncode}")
    marcador = {"Administrador": "Listado ordenado por puntaje", "Cliente": "Listado por número",
                "Errores de carga": "ACCESO DENEGADO."}[sesion.get()]
    posicion = salida.search(marcador, "1.0")
    if posicion:
        salida.yview(posicion)


ttk.Button(barra, text="Ejecutar", command=ejecutar).pack(side="left", padx=8)
raiz.after(100, ejecutar)
raiz.mainloop()
