#!/usr/bin/env bash
# ============================================================
# Sistema de seguimiento de vulnerabilidades por proyecto - TP4
# demo.sh: compila, recarga la base, ejecuta las pruebas sobre la interfaz y guarda las salidas.
# Autor: Rodríguez, Daniel Sebastián (legajo VINF016869)
# Uso (Git Bash, desde la carpeta TP4, con el MySQL de XAMPP iniciado):   ./demo.sh
# Para otro servidor se pueden cambiar estas variables, por ejemplo
#   MYSQL="C:/xampp/mysql/bin/mysql.exe" MYSQL_ARGS="-u root -h 127.0.0.1 -P 3306" \
#   JDBC_URL="jdbc:mysql://127.0.0.1:3306/vulnerabilidades_db?connectTimeout=3000" ./demo.sh
# ATENCIÓN: el script 01 borra y vuelve a crear vulnerabilidades_db.
# Mientras corre se abren y cierran ventanas solas, no hay que tocar el mouse.
# ============================================================
set -e
cd "$(dirname "$0")"
SEP=";"
[ "$(uname -s)" = "Linux" ] && SEP=":"                      # separador del classpath en Linux
CP="bin${SEP}lib/mysql-connector-j-8.4.0.jar"
MYSQL="${MYSQL:-mysql}"
MYSQL_ARGS="${MYSQL_ARGS:--u root}"
JDBC_URL="${JDBC_URL:-jdbc:mysql://localhost:3306/vulnerabilidades_db?connectTimeout=3000}"
mkdir -p salidas capturas

echo "1. Compilación"
rm -rf bin
{
    echo "\$ javac -version"; javac -version 2>&1
    echo "\$ javac -encoding UTF-8 -Xlint:all -d bin -cp lib/mysql-connector-j-8.4.0.jar (los $(find src -name '*.java' | wc -l) archivos de src)"
    javac -encoding UTF-8 -Xlint:all -d bin -cp lib/mysql-connector-j-8.4.0.jar $(find src -name "*.java") 2>&1
    echo "Código de salida de javac $? (sin errores ni advertencias)"
    echo "Clases del sistema $(find bin -name '*.class' | wc -l)"
} > salidas/salida_00_compilacion.txt
javac -encoding UTF-8 -Xlint:all -d bin -cp "$CP" herramientas/PruebasTP4.java    # programa auxiliar

echo "2. Carga de la base con los scripts 01 y 02"
{
    echo "\$ $MYSQL $MYSQL_ARGS < sql/01_creacion.sql"
    $MYSQL $MYSQL_ARGS --default-character-set=utf8mb4 < sql/01_creacion.sql
    echo "\$ $MYSQL $MYSQL_ARGS -t < sql/02_insercion.sql"
    $MYSQL $MYSQL_ARGS -t --default-character-set=utf8mb4 < sql/02_insercion.sql
} > salidas/salida_01_carga_base.txt 2>&1

echo "3. Pruebas sobre la interfaz, verificaciones en la base y rollback"
rm -rf exportaciones
java -Dstdout.encoding=UTF-8 -Dvulnerabilidades.url="$JDBC_URL" -cp "$CP" herramientas.PruebasTP4 \
     > salidas/salida_02_pruebas.txt 2>&1
tail -1 salidas/salida_02_pruebas.txt

echo "4. Inicio de sesión con la conexión apuntando a un puerto sin servidor"
java -Dstdout.encoding=UTF-8 -Dvulnerabilidades.url="jdbc:mysql://localhost:3399/vulnerabilidades_db?connectTimeout=2000" \
     -cp "$CP" herramientas.PruebasTP4 sin-servidor > salidas/salida_03_sin_servidor.txt 2>&1
tail -1 salidas/salida_03_sin_servidor.txt

echo "5. Estado final de la base"
{
    echo "\$ $MYSQL $MYSQL_ARGS -t < sql/03_verificacion.sql"
    $MYSQL $MYSQL_ARGS -t --default-character-set=utf8mb4 < sql/03_verificacion.sql
} > salidas/salida_04_verificacion_bd.txt 2>&1

echo "6. Archivo .jar del sistema (sin el programa de pruebas)"
printf "Main-Class: app.Aplicacion\nClass-Path: lib/mysql-connector-j-8.4.0.jar\n" > bin/MANIFEST.MF
rm -f seguimiento-vulnerabilidades.jar
jar --create --file seguimiento-vulnerabilidades.jar --manifest bin/MANIFEST.MF \
    -C bin app -C bin controlador -C bin dao -C bin modelo -C bin util -C bin vista
echo "Listo. Para usar el sistema: java -jar seguimiento-vulnerabilidades.jar"
