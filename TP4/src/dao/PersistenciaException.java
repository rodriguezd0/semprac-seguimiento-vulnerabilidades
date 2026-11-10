/*
 * Universidad Siglo 21 - Seminario de Práctica de Informática
 * Proyecto: Sistema de seguimiento de vulnerabilidades por proyecto
 * Alumno: Rodríguez, Daniel Sebastián
 * Legajo: VINF016869
 * DNI: 43.731.653
 * Trabajo Práctico 4 [TP4] - Versión final
 */
package dao;

/*--------------------------------------------------
 * Error al trabajar con la base de datos. Es verificada (extiende
 * Exception), así el compilador obliga a tratarla en quien llama.
 * Guarda la SQLException original como causa y trae un mensaje que
 * se le puede mostrar al usuario sin detalles técnicos.
 *--------------------------------------------------*/
public class PersistenciaException extends Exception {

    private static final long serialVersionUID = 1L;

    public PersistenciaException(String mensaje, Throwable causa) {
        super(mensaje, causa);
    }
}
