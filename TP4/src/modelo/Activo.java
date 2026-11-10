/*
 * Universidad Siglo 21 - Seminario de Práctica de Informática
 * Proyecto: Sistema de seguimiento de vulnerabilidades por proyecto
 * Alumno: Rodríguez, Daniel Sebastián
 * Legajo: VINF016869
 * DNI: 43.731.653
 */
package modelo;

/* Recurso informático de un proyecto (servidor, aplicación, equipo, etc.) */
public class Activo {

    private final int idActivo;
    private final int idProyecto;
    private final String nombre;
    private final String tipo;
    private final String descripcion;

    public Activo(int idActivo, int idProyecto, String nombre, String tipo, String descripcion) {
        this.idActivo = idActivo;
        this.idProyecto = idProyecto;
        this.nombre = nombre;
        this.tipo = tipo;
        this.descripcion = descripcion;
    }

    public int getIdActivo()        { return idActivo; }
    public int getIdProyecto()      { return idProyecto; }
    public String getNombre()       { return nombre; }
    public String getTipo()         { return tipo; }
    public String getDescripcion()  { return descripcion; }

    @Override
    public String toString() {
        return nombre;
    }
}
