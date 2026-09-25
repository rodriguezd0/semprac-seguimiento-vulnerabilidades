/*
 * Universidad Siglo 21 - Seminario de Práctica de Informática
 * Proyecto: Sistema de seguimiento de vulnerabilidades por proyecto
 * Alumno: Rodríguez, Daniel Sebastián
 * Legajo: VINF016869
 * DNI: 43.731.653
 */
package modelo;

import java.time.LocalDate;

/*--------------------------------------------------
 * Hallazgo de seguridad. En esta etapa solo tiene los atributos
 * que usa la regla de cambio de estado (CU06), que es la que se
 * prueba con caja blanca. Los nombres coinciden con las columnas
 * de la tabla vulnerabilidad.
 *--------------------------------------------------*/
public class Vulnerabilidad {

    private int idVulnerabilidad;
    private String titulo;
    private LocalDate fechaDeteccion;
    private Integer idResponsable;          // null = todavía sin responsable
    private LocalDate fechaObjetivo;        // null = todavía sin fecha objetivo
    private EstadoVulnerabilidad estado = EstadoVulnerabilidad.PENDIENTE;

    public Vulnerabilidad(int idVulnerabilidad, String titulo, LocalDate fechaDeteccion) {
        this.idVulnerabilidad = idVulnerabilidad;
        this.titulo = titulo;
        this.fechaDeteccion = fechaDeteccion;
    }

    /*--------------------------------------------------
     * CU04: asigna responsable y fecha objetivo. La fecha objetivo
     * no puede ser anterior a la detección (igual que el CHECK de la base).
     *--------------------------------------------------*/
    public void asignar(Integer idResponsable, LocalDate fechaObjetivo) {
        if (fechaObjetivo != null && fechaObjetivo.isBefore(fechaDeteccion)) {
            throw new ReglaNegocioException("La fecha objetivo no puede ser anterior a la detección.");
        }
        this.idResponsable = idResponsable;
        this.fechaObjetivo = fechaObjetivo;
    }

    /*--------------------------------------------------
     * CU06: valida el cambio de estado. Tres decisiones, así que
     * la complejidad ciclomática es V(G) = 4 (prueba CP03).
     *--------------------------------------------------*/
    public void validarCambioEstado(EstadoVulnerabilidad nuevo, String comentario) {
        if (nuevo == null || !estado.puedePasarA(nuevo)) {                        // D1
            throw new ReglaNegocioException("Transición no permitida: " + estado + " a " + nuevo);
        }
        if (nuevo == EstadoVulnerabilidad.EN_TRATAMIENTO && !tieneAsignacion()) { // D2
            throw new ReglaNegocioException("Falta responsable o fecha objetivo.");
        }
        if (comentario == null || comentario.isBlank()) {                         // D3
            throw new ReglaNegocioException("El comentario es obligatorio.");
        }
    }

    /*--------------------------------------------------
     * Aplica el cambio ya validado y devuelve el estado anterior
     * (lo necesita el seguimiento que se guarda en el historial).
     *--------------------------------------------------*/
    public EstadoVulnerabilidad cambiarEstado(EstadoVulnerabilidad nuevo, String comentario) {
        validarCambioEstado(nuevo, comentario);
        EstadoVulnerabilidad anterior = estado;
        estado = nuevo;
        return anterior;
    }

    public boolean tieneAsignacion() {
        return idResponsable != null && fechaObjetivo != null;
    }

    public EstadoVulnerabilidad getEstado() { return estado; }
    public int getIdVulnerabilidad()       { return idVulnerabilidad; }
    public String getTitulo()              { return titulo; }
}
