/*
 * Universidad Siglo 21 - Seminario de Práctica de Informática
 * Proyecto: Sistema de seguimiento de vulnerabilidades por proyecto
 * Alumno: Rodríguez, Daniel Sebastián
 * Legajo: VINF016869
 * DNI: 43.731.653
 */
package modelo;

/* Persona o equipo que corrige los hallazgos (no usa el sistema) */
public class Responsable {

    private final int idResponsable;
    private final String nombre;
    private final String contacto;

    public Responsable(int idResponsable, String nombre, String contacto) {
        this.idResponsable = idResponsable;
        this.nombre = nombre;
        this.contacto = contacto;
    }

    public int getIdResponsable()   { return idResponsable; }
    public String getNombre()       { return nombre; }
    public String getContacto()     { return contacto; }

    @Override
    public String toString() {
        return nombre;
    }
}
