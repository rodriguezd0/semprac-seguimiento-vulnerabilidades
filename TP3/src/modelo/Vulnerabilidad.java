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
 * Hallazgo de seguridad sobre un activo. Los atributos son las
 * columnas de la tabla vulnerabilidad y son privados: el estado
 * solo cambia con cambiarEstado(), que antes valida las reglas
 * del CU06 (encapsulamiento). El puntaje y la severidad no se
 * guardan, se calculan desde el vector CVSS cada vez que se piden.
 *--------------------------------------------------*/
public class Vulnerabilidad {

    private final int idVulnerabilidad;
    private final int idActivo;
    private Integer idResponsable;           // null = todavía sin responsable
    private final String titulo;
    private final String descripcion;
    private final String tipo;
    private final String elementoAfectado;
    private final LocalDate fechaDeteccion;
    private LocalDate fechaObjetivo;         // null = todavía sin fecha objetivo
    private EstadoVulnerabilidad estado;
    private final String vectorCvss;         // null = "Sin evaluar"

    /*--------------------------------------------------
     * Constructor para un hallazgo nuevo (CU03): nace PENDIENTE,
     * sin responsable y sin fecha objetivo. Llama al constructor
     * completo con this(...) para no repetir las validaciones.
     *--------------------------------------------------*/
    public Vulnerabilidad(int idVulnerabilidad, int idActivo, String titulo, String descripcion,
                          String tipo, String elementoAfectado, LocalDate fechaDeteccion, String vectorCvss) {
        this(idVulnerabilidad, idActivo, null, titulo, descripcion, tipo, elementoAfectado,
             fechaDeteccion, null, EstadoVulnerabilidad.PENDIENTE, vectorCvss);
    }

    /* Constructor completo, para reconstruir un hallazgo ya guardado (datos de prueba o base) */
    public Vulnerabilidad(int idVulnerabilidad, int idActivo, Integer idResponsable, String titulo,
                          String descripcion, String tipo, String elementoAfectado, LocalDate fechaDeteccion,
                          LocalDate fechaObjetivo, EstadoVulnerabilidad estado, String vectorCvss) {
        if (titulo == null || titulo.isBlank() || tipo == null || tipo.isBlank()) {
            throw new ReglaNegocioException("El título y el tipo son obligatorios.");
        }
        if (fechaDeteccion == null) {
            throw new ReglaNegocioException("La fecha de detección es obligatoria.");
        }
        if (vectorCvss != null) {
            CalculadoraCvss31.calcularPuntaje(vectorCvss);   // si el vector está mal, lanza la excepción acá
        }
        this.idVulnerabilidad = idVulnerabilidad;
        this.idActivo = idActivo;
        this.idResponsable = idResponsable;
        this.titulo = titulo.trim();
        this.descripcion = descripcion;
        this.tipo = tipo.trim();
        this.elementoAfectado = elementoAfectado;
        this.fechaDeteccion = fechaDeteccion;
        this.fechaObjetivo = fechaObjetivo;
        this.estado = estado;
        this.vectorCvss = vectorCvss;
    }

    /*--------------------------------------------------
     * CU04: asigna responsable y fecha objetivo. La fecha no puede
     * ser anterior a la detección (igual que el CHECK de la base).
     *--------------------------------------------------*/
    public void asignar(Integer idResponsable, LocalDate fechaObjetivo) {
        if (estado == EstadoVulnerabilidad.CERRADA) {
            throw new ReglaNegocioException("No se puede asignar un hallazgo cerrado.");
        }
        if (idResponsable == null || fechaObjetivo == null) {
            throw new ReglaNegocioException("Indique el responsable y la fecha objetivo.");
        }
        if (fechaObjetivo.isBefore(fechaDeteccion)) {
            throw new ReglaNegocioException("La fecha objetivo no puede ser anterior a la detección.");
        }
        this.idResponsable = idResponsable;
        this.fechaObjetivo = fechaObjetivo;
    }

    /*--------------------------------------------------
     * CU06: valida el cambio de estado. Son tres decisiones, así
     * que la complejidad ciclomática es V(G) = 4 (prueba CP03).
     *--------------------------------------------------*/
    public void validarCambioEstado(EstadoVulnerabilidad nuevo, String comentario) {
        if (nuevo == null || !estado.puedePasarA(nuevo)) {                        // D1
            throw new ReglaNegocioException("Transición no permitida de " + estado + " a " + nuevo + ".");
        }
        if (nuevo == EstadoVulnerabilidad.EN_TRATAMIENTO && !tieneAsignacion()) { // D2
            throw new ReglaNegocioException("Falta responsable o fecha objetivo (primero hay que asignarlo).");
        }
        if (comentario == null || comentario.isBlank()) {                         // D3
            throw new ReglaNegocioException("El comentario es obligatorio.");
        }
    }

    /* Aplica el cambio ya validado y devuelve el estado anterior (lo usa el seguimiento) */
    public EstadoVulnerabilidad cambiarEstado(EstadoVulnerabilidad nuevo, String comentario) {
        validarCambioEstado(nuevo, comentario);
        EstadoVulnerabilidad anterior = estado;
        estado = nuevo;
        return anterior;
    }

    public boolean tieneAsignacion() {
        return idResponsable != null && fechaObjetivo != null;
    }

    /* Puntaje CVSS 3.1 base, o null si el hallazgo no fue evaluado */
    public Double getPuntaje() {
        return vectorCvss == null ? null : CalculadoraCvss31.calcularPuntaje(vectorCvss);
    }

    /* Severidad según FIRST (Ninguna, Baja, Media, Alta, Crítica) o "Sin evaluar" */
    public String getSeveridad() {
        return CalculadoraCvss31.categoria(getPuntaje());
    }

    public int getIdVulnerabilidad()        { return idVulnerabilidad; }
    public int getIdActivo()                { return idActivo; }
    public Integer getIdResponsable()       { return idResponsable; }
    public String getTitulo()               { return titulo; }
    public String getDescripcion()          { return descripcion; }
    public String getTipo()                 { return tipo; }
    public String getElementoAfectado()     { return elementoAfectado; }
    public LocalDate getFechaDeteccion()    { return fechaDeteccion; }
    public LocalDate getFechaObjetivo()     { return fechaObjetivo; }
    public EstadoVulnerabilidad getEstado() { return estado; }
    public String getVectorCvss()           { return vectorCvss; }
}
