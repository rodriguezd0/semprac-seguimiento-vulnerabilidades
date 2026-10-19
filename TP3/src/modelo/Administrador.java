/*
 * Universidad Siglo 21 - Seminario de Práctica de Informática
 * Proyecto: Sistema de seguimiento de vulnerabilidades por proyecto
 * Alumno: Rodríguez, Daniel Sebastián
 * Legajo: VINF016869
 * DNI: 43.731.653
 */
package modelo;

/*--------------------------------------------------
 * Personal del área tecnológica. Registra, asigna y cambia el
 * estado de los hallazgos y ve todos los proyectos.
 *--------------------------------------------------*/
public class Administrador extends Usuario {

    public Administrador(int idUsuario, String nombreAcceso, String nombreCompleto,
                         String claveHash, String sal, boolean activo) {
        super(idUsuario, nombreAcceso, nombreCompleto, claveHash, sal, activo);   // constructor de Usuario
    }

    @Override
    public boolean puedeGestionar() {
        return true;
    }

    /* Las tres primeras opciones son las mismas del cliente, después vienen las de gestión */
    @Override
    public String[] opcionesMenu() {
        return new String[] {"Listar vulnerabilidades", "Buscar por número", "Ordenar por puntaje CVSS",
                             "Registrar vulnerabilidad", "Asignar responsable", "Cambiar estado"};
    }

    @Override
    public String getRol() {
        return "ADMINISTRADOR";
    }
}
