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

### Cómo reproducir

Base de datos (MySQL de XAMPP), desde la carpeta TP2

    mysql -u root < sql/01_creacion.sql
    mysql -u root < sql/02_insercion.sql
    mysql -u root -t --force < sql/03_consultas.sql
    mysql -u root -t --force < sql/04_borrado.sql

Los scripts 03 y 04 terminan con operaciones que la base tiene que rechazar (una fecha inválida y un borrado que impide la clave foránea), por eso se usa --force.

Pruebas del modelo (JDK 21), desde TP2/pruebas

    javac -encoding UTF-8 -d bin src/modelo/*.java src/pruebas/*.java
    java -cp bin pruebas.PruebasTP2

Los datos de prueba son ficticios y no corresponden a hallazgos reales de ninguna organización.
