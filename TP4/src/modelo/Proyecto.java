/*
 * Universidad Siglo 21 - Seminario de Práctica de Informática
 * Proyecto: Sistema de seguimiento de vulnerabilidades por proyecto
 * Alumno: Rodríguez, Daniel Sebastián
 * Legajo: VINF016869
 * DNI: 43.731.653
 */
package modelo;

/* Proyecto con su único cliente (tabla proyecto) */
public class Proyecto {

    private final int idProyecto;
    private final String nombre;
    private final String descripcion;
    private final int idCliente;         // cuenta con rol CLIENTE dueña del proyecto

    public Proyecto(int idProyecto, String nombre, String descripcion, int idCliente) {
        this.idProyecto = idProyecto;
        this.nombre = nombre;
        this.descripcion = descripcion;
        this.idCliente = idCliente;
    }

    public int getIdProyecto()      { return idProyecto; }
    public String getNombre()       { return nombre; }
    public String getDescripcion()  { return descripcion; }
    public int getIdCliente()       { return idCliente; }

    @Override
    public String toString() {
        return nombre;                   // así se muestra en listas y combos
    }
}
