/*
 * Universidad Siglo 21 - Seminario de Práctica de Informática
 * Proyecto: Sistema de seguimiento de vulnerabilidades por proyecto
 * Alumno: Rodríguez, Daniel Sebastián
 * Legajo: VINF016869
 * DNI: 43.731.653
 */
package modelo;

/*--------------------------------------------------
 * Estados posibles de una vulnerabilidad (mismo ENUM que la
 * columna vulnerabilidad.estado de la base de datos).
 * Transiciones admitidas:
 *   PENDIENTE      -> EN_TRATAMIENTO  (inicio del tratamiento)
 *   EN_TRATAMIENTO -> CERRADA         (cierre con verificación)
 *   CERRADA        -> PENDIENTE       (reapertura justificada)
 *--------------------------------------------------*/
public enum EstadoVulnerabilidad {
    PENDIENTE, EN_TRATAMIENTO, CERRADA;

    /*--------------------------------------------------
     * Devuelve true si desde este estado se puede pasar al destino.
     *--------------------------------------------------*/
    public boolean puedePasarA(EstadoVulnerabilidad destino) {
        switch (this) {
            case PENDIENTE:      return destino == EN_TRATAMIENTO;
            case EN_TRATAMIENTO: return destino == CERRADA;
            case CERRADA:        return destino == PENDIENTE;
            default:             return false;   // no debería ocurrir
        }
    }
}
