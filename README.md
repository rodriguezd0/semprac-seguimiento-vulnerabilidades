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

## TP4. Versión final con Swing, MySQL y patrón MVC

- [Informe TP4 en PDF](TP4/RODRIGUEZ-DANIEL-AP4.PDF), el documento integrado con el TP1, el TP2 y el TP3 corregidos
- [Código fuente](TP4/src/) con 23 clases en seis paquetes (`modelo`, `vista`, `controlador`, `dao`, `util` y `app`)
- [Scripts SQL](TP4/sql/) de creación, datos de prueba y verificación
- [Planilla CSV de ejemplo](TP4/entradas/planilla_hallazgos.csv) para la importación
- [Salidas reales](TP4/salidas/) y [capturas](TP4/capturas/) de la ejecución contra la base
- [Diagramas actualizados](TP4/diagramas/) (clases del modelo, capas del MVC y secuencia del cambio de estado)
- Video de presentación (3 minutos) [https://drive.google.com/file/d/1WOmHzJpT8UlJvwH-wRaepPd_MIHo2izk/view?usp=sharing](https://drive.google.com/file/d/1WOmHzJpT8UlJvwH-wRaepPd_MIHo2izk/view?usp=sharing)

La interfaz es Swing y el acceso a la base es JDBC puro con MySQL Connector/J (sin frameworks). El administrador registra hallazgos con su cálculo CVSS, cambia estados (el UPDATE y el seguimiento van en una misma transacción), consulta el historial, exporta el listado a TXT y carga hallazgos desde la planilla del área en CSV. El cliente solo consulta los hallazgos de sus proyectos.

### Cómo ejecutarlo (JDK 21 y el MySQL de XAMPP)

1. Iniciar MySQL desde el panel de XAMPP.
2. Crear la base con los scripts de `TP4/sql` en orden (desde phpMyAdmin con la opción Importar, o desde una consola cmd o Git Bash). El script 01 borra y vuelve a crear `vulnerabilidades_db`, así que si ya hay una base con ese nombre que se quiera conservar conviene respaldarla antes con `mysqldump`.

        mysql -u root < sql/01_creacion.sql
        mysql -u root < sql/02_insercion.sql

3. Desde la carpeta TP4, ejecutar el .jar (busca el driver en `lib`)

        java -jar seguimiento-vulnerabilidades.jar

    o compilar y ejecutar las fuentes (en Linux o macOS el separador del classpath es `:` en lugar de `;`)

        javac -encoding UTF-8 -d bin -cp lib/mysql-connector-j-8.4.0.jar src/app/*.java src/controlador/*.java src/dao/*.java src/modelo/*.java src/util/*.java src/vista/*.java
        java -cp "bin;lib/mysql-connector-j-8.4.0.jar" app.Aplicacion

4. Ingresar con `dsrodriguez` y la clave `Admin.2026` (administrador) o con `ref.expedientes` y `Expedientes.2026` (cliente). La otra cuenta cliente es `ref.web` con `Web.2026`.

La conexión usa por defecto `jdbc:mysql://localhost:3306/vulnerabilidades_db` con el usuario `root` sin clave, como viene XAMPP. Para otro servidor no hace falta recompilar, se agregan `-Dvulnerabilidades.url=...`, `-Dvulnerabilidades.usuario=...` y `-Dvulnerabilidades.clave=...` antes de `-jar` o de `-cp` (en PowerShell, cada uno entre comillas, porque sin comillas PowerShell los corta en el punto). En NetBeans alcanza con crear un proyecto Java con la carpeta `src`, sumar `lib/mysql-connector-j-8.4.0.jar` en Libraries y ejecutar `app.Aplicacion`.

### Cómo repetir las pruebas guardadas

`demo.sh` (Git Bash) compila, recrea la base con los scripts 01 y 02, recorre la interfaz con `herramientas/PruebasTP4.java` (un programa auxiliar que escribe en las ventanas, pulsa los botones, saca las capturas y verifica en la base lo que quedó guardado), prueba el inicio de sesión sin servidor, guarda el estado final de la base y arma el .jar. Ojo, el script 01 borra y vuelve a crear `vulnerabilidades_db`.

    ./demo.sh

Las salidas de la carpeta `salidas` se generaron el 30/10/2026 con el MariaDB 10.4 de XAMPP iniciado aparte en el puerto 3307 (para no tocar la base de trabajo), con `MYSQL_ARGS="-u root -h 127.0.0.1 -P 3307"` y `JDBC_URL="jdbc:mysql://127.0.0.1:3307/vulnerabilidades_db?connectTimeout=3000"`.

Los datos de prueba son ficticios y no corresponden a hallazgos reales de ninguna organización.
