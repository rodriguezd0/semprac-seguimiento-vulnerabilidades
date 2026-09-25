# -*- coding: utf-8 -*-
"""
Diagrama de casos de uso (UML) del Sistema de seguimiento de vulnerabilidades.
Autor: Rodríguez, Daniel Sebastián (VINF016869)
Se dibuja con coordenadas fijas para controlar la disposición: casos del
administrador en abanico a la izquierda, casos compartidos a la derecha junto
al cliente y los casos incluidos/extendidos en el centro.
Genera casos_uso.png y casos_uso.svg en la misma carpeta.
"""
import math
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Ellipse, Rectangle, Circle, FancyArrowPatch

AQUI = os.path.dirname(os.path.abspath(__file__))
plt.rcParams["font.family"] = "Calibri"

EW, EH = 22.0, 7.2          # ancho y alto de cada óvalo
ADM = (4.0, 40.0)           # posición del actor Administrador (centro del cuerpo)
CLI = (130.0, 40.0)         # posición del actor Cliente

# Casos del administrador en abanico (ángulo en grados respecto del actor)
R = 52.0
abanico = {
    "CU10": 68, "CU09": 53, "CU01": 38, "CU02": 23,
    "CU03": -21, "CU12": -37, "CU04": -52, "CU06": -67,
}
casos = {}
for cu, ang in abanico.items():
    a = math.radians(ang)
    casos[cu] = (ADM[0] + 9.0 + R * math.cos(a), ADM[1] + R * math.sin(a) * 1.04)

# Casos compartidos (cerca del cliente) y casos incluidos/extendidos (centro)
casos.update({
    "CU11": (103.0, 64.0), "CU05": (103.0, 40.0), "CU07": (103.0, 16.0),
    "CU08": (80.0, 51.5), "CU13": (80.0, 29.5),
})
nombres = {
    "CU01": "CU01 Gestionar\nactivos", "CU02": "CU02 Gestionar\nresponsables",
    "CU03": "CU03 Registrar\nvulnerabilidad", "CU04": "CU04 Asignar\nresponsable",
    "CU05": "CU05 Consultar\nvulnerabilidades", "CU06": "CU06 Cambiar\nestado",
    "CU07": "CU07 Consultar\nhistorial", "CU08": "CU08 Exportar\nlistado",
    "CU09": "CU09 Gestionar\nproyectos", "CU10": "CU10 Gestionar\nusuarios",
    "CU11": "CU11 Iniciar/cerrar\nsesión", "CU12": "CU12 Calcular\nCVSS",
    "CU13": "CU13 Verificar acceso\nal proyecto",
}
asoc_adm = ["CU10", "CU09", "CU01", "CU02", "CU03", "CU12", "CU04", "CU06", "CU11", "CU05", "CU07"]
asoc_cli = ["CU11", "CU05", "CU07"]
relaciones = [  # (origen, destino, estereotipo, etiqueta extra)
    ("CU12", "CU03", "«extend»", (1.8, -1.2)),
    ("CU08", "CU05", "«extend»", (1.5, 0.8)),
    ("CU05", "CU13", "«include»", (1.2, -3.4)),
    ("CU07", "CU13", "«include»", (2.2, 0.6)),
]


def borde(centro, hacia):
    """Punto del borde del óvalo en dirección a otro punto."""
    cx, cy = centro
    dx, dy = hacia[0] - cx, hacia[1] - cy
    t = 1.0 / math.sqrt((dx / (EW / 2)) ** 2 + (dy / (EH / 2)) ** 2)
    return cx + dx * t, cy + dy * t


def dentro(p, centro, margen=0.6):
    """True si el punto p cae dentro del óvalo agrandado por un margen."""
    return ((p[0] - centro[0]) / (EW / 2 + margen)) ** 2 + ((p[1] - centro[1]) / (EH / 2 + margen)) ** 2 < 1


def choques(a, b, excluir):
    """Casos de uso atravesados por el segmento a-b (control de prolijidad)."""
    res = []
    for cu, c in casos.items():
        if cu in excluir:
            continue
        for k in range(1, 200):
            t = k / 200
            p = (a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t)
            if dentro(p, c):
                res.append(cu)
                break
    return res


def actor(ax, x, y, nombre):
    ax.add_patch(Circle((x, y + 6.2), 1.6, fill=False, lw=1.1))
    ax.plot([x, x], [y + 4.6, y - 0.8], color="black", lw=1.1)
    ax.plot([x - 3.2, x + 3.2], [y + 2.8, y + 2.8], color="black", lw=1.1)
    ax.plot([x, x - 2.6], [y - 0.8, y - 5.2], color="black", lw=1.1)
    ax.plot([x, x + 2.6], [y - 0.8, y - 5.2], color="black", lw=1.1)
    ax.text(x, y - 7.3, nombre, ha="center", va="top", fontsize=11)


def main():
    fig, ax = plt.subplots(figsize=(11.4, 9.4))
    ax.set_xlim(-8, 139)
    ax.set_ylim(-19, 101)
    ax.set_aspect("equal")
    ax.axis("off")

    # Límite del sistema con su nombre
    ax.add_patch(Rectangle((16, -17), 104, 115, fill=False, lw=1.3))
    ax.text(68, 94.0, "Sistema de seguimiento de vulnerabilidades", ha="center",
            va="center", fontsize=12, fontweight="bold")

    avisos = []
    origen_adm = (ADM[0] + 3.5, ADM[1] + 2.8)
    origen_cli = (CLI[0] - 3.5, CLI[1] + 2.8)
    for cu in asoc_adm:
        fin = borde(casos[cu], origen_adm)
        ax.plot([origen_adm[0], fin[0]], [origen_adm[1], fin[1]], color="black", lw=0.9)
        avisos += [("ADM", cu, x) for x in choques(origen_adm, fin, {cu})]
    for cu in asoc_cli:
        fin = borde(casos[cu], origen_cli)
        ax.plot([origen_cli[0], fin[0]], [origen_cli[1], fin[1]], color="black", lw=0.9)
        avisos += [("CLI", cu, x) for x in choques(origen_cli, fin, {cu})]

    for o, d, estereotipo, desp in relaciones:
        a = borde(casos[o], casos[d])
        b = borde(casos[d], casos[o])
        flecha = FancyArrowPatch(a, b, arrowstyle="->", mutation_scale=13, lw=0.9,
                                 linestyle=(0, (4, 3)), color="black")
        ax.add_patch(flecha)
        mx, my = (a[0] + b[0]) / 2, (a[1] + b[1]) / 2
        ax.text(mx + desp[0], my + desp[1], estereotipo, fontsize=9.5, ha="left", va="bottom",
                bbox=dict(facecolor="white", edgecolor="none", pad=0.4))
        avisos += [(o, d, x) for x in choques(a, b, {o, d})]

    for cu, (x, y) in casos.items():
        ax.add_patch(Ellipse((x, y), EW, EH, facecolor="white", edgecolor="black", lw=1.0))
        ax.text(x, y, nombres[cu], ha="center", va="center", fontsize=9.4, linespacing=1.05)

    actor(ax, *ADM, "Administrador")
    actor(ax, *CLI, "Cliente")

    fig.savefig(os.path.join(AQUI, "casos_uso.png"), dpi=200, bbox_inches="tight", pad_inches=0.08)
    fig.savefig(os.path.join(AQUI, "casos_uso.svg"), bbox_inches="tight", pad_inches=0.08)
    print("choques:", avisos if avisos else "ninguno")
    for cu in sorted(casos):
        print(cu, tuple(round(v, 1) for v in casos[cu]))


if __name__ == "__main__":
    main()
