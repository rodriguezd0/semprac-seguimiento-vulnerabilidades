/*
 * Universidad Siglo 21 - Seminario de Práctica de Informática
 * Proyecto: Sistema de seguimiento de vulnerabilidades por proyecto
 * Alumno: Rodríguez, Daniel Sebastián
 * Legajo: VINF016869
 * DNI: 43.731.653
 */
package modelo;

/*--------------------------------------------------
 * Excepción que usa el modelo cuando una operación viola una
 * regla del negocio (transición inválida, falta de asignación,
 * comentario vacío, etc.). La ventana que inició la operación la
 * captura y le muestra el mensaje al usuario.
 *--------------------------------------------------*/
public class ReglaNegocioException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public ReglaNegocioException(String mensaje) {
        super(mensaje);
    }
}
