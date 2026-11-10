/*
 * Universidad Siglo 21 - Seminario de Práctica de Informática
 * Proyecto: Sistema de seguimiento de vulnerabilidades por proyecto
 * Alumno: Rodríguez, Daniel Sebastián
 * Legajo: VINF016869
 * DNI: 43.731.653
 * Trabajo Práctico 4 [TP4] - Versión final
 */
package util;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;

/*--------------------------------------------------
 * Archivos de texto del sistema (exportación del listado, CU08, y
 * carga de hallazgos desde la planilla del área en CSV).
 * File solo representa la ruta y trabaja sobre el sistema de
 * archivos (crear la carpeta, ver si un archivo existe). Leer y
 * escribir se hace con flujos encadenados, cada uno con su tarea:
 *
 *   FileOutputStream --> OutputStreamWriter --> BufferedWriter
 *   (bytes al disco)     (texto a UTF-8)       (junta escrituras chicas)
 *
 *   FileInputStream  --> InputStreamReader  --> BufferedReader
 *   (bytes del disco)    (UTF-8 a texto)       (readLine, una línea por vez)
 *
 * Cualquier problema de entrada/salida llega como IOException y lo
 * trata la ventana que pidió la operación.
 *--------------------------------------------------*/
public final class ArchivoTexto {

    private static final DateTimeFormatter SELLO = DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss");

    private ArchivoTexto() { }                                   // clase utilitaria, no se instancia

    /*--------------------------------------------------
     * Crea siempre un archivo nuevo con la fecha y hora en el nombre,
     * así un listado nunca pisa a otro. Devuelve el File creado.
     *--------------------------------------------------*/
    public static File guardar(File carpeta, String prefijo, ArrayList<String> lineas) throws IOException {
        if (!carpeta.exists() && !carpeta.mkdirs()) {           // File: operación sobre el sistema de archivos
            throw new IOException("No se pudo crear la carpeta " + carpeta.getAbsolutePath());
        }
        File archivo = new File(carpeta, prefijo + "_" + LocalDateTime.now().format(SELLO) + ".txt");
        if (archivo.exists()) {
            throw new IOException("Ya existe " + archivo.getName() + ", espere un segundo y repita.");
        }
        try (BufferedWriter salida = new BufferedWriter(
                new OutputStreamWriter(new FileOutputStream(archivo), StandardCharsets.UTF_8))) {
            for (String linea : lineas) {
                salida.write(linea);
                salida.newLine();                                // fin de línea del sistema operativo
            }
        }                                                        // el try cierra los flujos y vacía el buffer
        return archivo;
    }

    /*--------------------------------------------------
     * Lee el archivo completo. Las líneas van a un ArrayList porque
     * la cantidad recién se conoce al llegar al final del archivo.
     * El decodificador es estricto: un archivo que no está en UTF-8
     * (por ejemplo, el "CSV delimitado por comas" de Excel, que usa
     * Windows-1252) se rechaza en vez de leer las tildes cambiadas.
     *--------------------------------------------------*/
    public static ArrayList<String> leerLineas(File archivo) throws IOException {
        ArrayList<String> lineas = new ArrayList<>();
        CharsetDecoder utf8Estricto = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        try (BufferedReader entrada = new BufferedReader(
                new InputStreamReader(new FileInputStream(archivo), utf8Estricto))) {
            String linea;
            while ((linea = entrada.readLine()) != null) {      // null = fin del archivo
                lineas.add(linea);
            }
        } catch (CharacterCodingException e) {
            throw new IOException("el archivo no está en UTF-8, guárdelo como «CSV UTF-8» y repita", e);
        }
        return lineas;
    }
}
