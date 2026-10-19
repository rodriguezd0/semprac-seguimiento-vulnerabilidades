# Seguimiento de vulnerabilidades por proyecto

Seminario de Práctica de Informática, Universidad Siglo 21  
Daniel Sebastián Rodríguez (VINF016869)

Aplicación de escritorio en Java, Swing y MySQL para registrar vulnerabilidades, calcular su severidad con CVSS 3.1 y seguir su corrección. El administrador gestiona la información y cada cliente consulta solamente los proyectos que tiene asignados.

## TP1. Definición y análisis del proyecto

- [Informe TP1 en PDF](TP1/RODRIGUEZ-DANIEL-AP1.PDF)
- [Diagramas](TP1/diagramas/)

## TP2. Análisis, diseño, implementación, pruebas y base de datos

- [Informe TP2 en PDF](TP2/RODRIGUEZ-DANIEL-AP2.PDF) (incluye el TP1 corregido)
- [Scripts SQL](TP2/sql/) y [salida de cada ejecución](TP2/salidas/)
- [Diagramas](TP2/diagramas/) (fuentes PlantUML y PNG)
- [Prototipos de interfaz en Swing](TP2/prototipos/)
- [Pruebas del modelo](TP2/pruebas/)
- [Capturas de phpMyAdmin](TP2/capturas/)

## TP3. Prototipo de consola en Java

- [Informe TP3 en PDF](TP3/RODRIGUEZ-DANIEL-AP3.PDF) (incluye el TP1 y el TP2)
- [Código fuente](TP3/src/) con 13 clases en dos paquetes (`modelo` y `app`)
- [Entradas guionadas](TP3/entradas/) y [salidas reales](TP3/salidas/) de tres sesiones (administrador, cliente y errores de carga)
- [Capturas de ejecución](TP3/capturas/) del administrador y el cliente

El prototipo trabaja con los datos en memoria (los mismos del script `02_insercion.sql`) y cubre el inicio de sesión, la consulta según el rol, el registro con cálculo CVSS, la asignación, el cambio de estado y el historial. Claves de prueba: Admin.2026 (dsrodriguez), Web.2026 (ref.web) y Expedientes.2026 (ref.expedientes).

### Cómo compilar y ejecutar (JDK 21, sin librerías externas)

Desde la carpeta TP3

    javac -encoding UTF-8 -Xlint:all -d bin src/modelo/*.java src/app/*.java
    java -cp bin app.MenuConsola

En NetBeans alcanza con crear un proyecto Java con la carpeta `src` y ejecutar `app.MenuConsola`.

### Cómo repetir las sesiones guardadas

La opción `-eco` hace que el programa repita cada línea que lee, así la salida guardada se entiende sin abrir el archivo de entrada.

    java -Dstdout.encoding=UTF-8 -cp bin app.MenuConsola -eco < entradas/entrada_01_administrador.txt > salidas/salida_01_administrador.txt
    java -Dstdout.encoding=UTF-8 -cp bin app.MenuConsola -eco < entradas/entrada_02_cliente.txt > salidas/salida_02_cliente.txt
    java -Dstdout.encoding=UTF-8 -cp bin app.MenuConsola -eco < entradas/entrada_03_errores.txt > salidas/salida_03_errores.txt

La única diferencia al repetirlas es la fecha y hora del cambio de estado que se registra en la primera sesión.

Las capturas se tomaron con `herramientas/ver_ejecucion.py`, un visor que ejecuta `app.MenuConsola` con esas mismas entradas y muestra su salida sin modificarla. Se puede abrir con Python y Tkinter después de compilar Java. Es una herramienta de documentación y no forma parte de la interfaz del sistema.

Los datos de prueba son ficticios y no corresponden a hallazgos reales de ninguna organización.
