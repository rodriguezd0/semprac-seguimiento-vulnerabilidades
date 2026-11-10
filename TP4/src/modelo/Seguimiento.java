/*
 * Universidad Siglo 21 - Seminario de Práctica de Informática
 * Proyecto: Sistema de seguimiento de vulnerabilidades por proyecto
 * Alumno: Rodríguez, Daniel Sebastián
 * Legajo: VINF016869
 * DNI: 43.731.653
 */
package modelo;

import java.time.LocalDateTime;

/*--------------------------------------------------
 * Un cambio de estado del historial (tabla seguimiento). Una vez
 * creado no se modifica, por eso todos los atributos son final y
 * no hay métodos set. Además del id del usuario guarda su nombre
 * de acceso para mostrar quién hizo el cambio.
 *--------------------------------------------------*/
public class Seguimiento {

    private final int idSeguimiento;
    private final int idVulnerabilidad;
    private final int idUsuario;
    private final String usuario;
    private final LocalDateTime fechaHora;
    private final EstadoVulnerabilidad estadoAnterior;
    private final EstadoVulnerabilidad estadoNuevo;
    private final String comentario;

    public Seguimiento(int idSeguimiento, int idVulnerabilidad, int idUsuario, String usuario,
                       LocalDateTime fechaHora, EstadoVulnerabilidad estadoAnterior,
                       EstadoVulnerabilidad estadoNuevo, String comentario) {
        this.idSeguimiento = idSeguimiento;
        this.idVulnerabilidad = idVulnerabilidad;
        this.idUsuario = idUsuario;
        this.usuario = usuario;
        this.fechaHora = fechaHora;
        this.estadoAnterior = estadoAnterior;
        this.estadoNuevo = estadoNuevo;
        this.comentario = comentario;
    }

    public int getIdSeguimiento()                   { return idSeguimiento; }
    public int getIdVulnerabilidad()                { return idVulnerabilidad; }
    public int getIdUsuario()                       { return idUsuario; }
    public String getUsuario()                      { return usuario; }
    public LocalDateTime getFechaHora()             { return fechaHora; }
    public EstadoVulnerabilidad getEstadoAnterior() { return estadoAnterior; }
    public EstadoVulnerabilidad getEstadoNuevo()    { return estadoNuevo; }
    public String getComentario()                   { return comentario; }
}
