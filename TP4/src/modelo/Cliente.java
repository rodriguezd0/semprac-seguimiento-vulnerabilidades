/*
 * Universidad Siglo 21 - Seminario de Práctica de Informática
 * Proyecto: Sistema de seguimiento de vulnerabilidades por proyecto
 * Alumno: Rodríguez, Daniel Sebastián
 * Legajo: VINF016869
 * DNI: 43.731.653
 */
package modelo;

/*--------------------------------------------------
 * Referente de un proyecto. Solo consulta, y solamente los
 * hallazgos de los proyectos que tiene asignados (CU13).
 *--------------------------------------------------*/
public class Cliente extends Usuario {

    public Cliente(int idUsuario, String nombreAcceso, String nombreCompleto,
                   String claveHash, String sal, boolean activo) {
        super(idUsuario, nombreAcceso, nombreCompleto, claveHash, sal, activo);
    }

    @Override
    public boolean puedeGestionar() {
        return false;
    }

    /* El cliente solo consulta, así que su único botón es el historial */
    @Override
    public String[] opcionesMenu() {
        return new String[] {"Historial"};
    }

    @Override
    public String getRol() {
        return "CLIENTE";
    }
}
