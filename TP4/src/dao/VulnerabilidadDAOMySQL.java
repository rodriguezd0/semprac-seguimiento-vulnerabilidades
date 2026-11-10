/*
 * Universidad Siglo 21 - Seminario de Práctica de Informática
 * Proyecto: Sistema de seguimiento de vulnerabilidades por proyecto
 * Alumno: Rodríguez, Daniel Sebastián
 * Legajo: VINF016869
 * DNI: 43.731.653
 * Trabajo Práctico 4 [TP4] - Versión final
 */
package dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;

import modelo.EstadoVulnerabilidad;
import modelo.Seguimiento;
import modelo.Usuario;
import modelo.Vulnerabilidad;

/*--------------------------------------------------
 * Implementación de VulnerabilidadDAO con JDBC y MySQL. Todas las
 * sentencias son PreparedStatement con parámetros (?) para evitar
 * la inyección SQL, y toda SQLException se traduce a
 * PersistenciaException con un mensaje entendible.
 *--------------------------------------------------*/
public class VulnerabilidadDAOMySQL implements VulnerabilidadDAO {

    private static final String SQL_BASE = "SELECT v.id_vulnerabilidad, v.id_activo, v.id_responsable, v.titulo, "
            + "v.descripcion, v.tipo, v.elemento_afectado, v.fecha_deteccion, v.fecha_objetivo, v.estado, "
            + "v.vector_cvss FROM vulnerabilidad v JOIN activo a ON a.id_activo = v.id_activo "
            + "JOIN proyecto p ON p.id_proyecto = a.id_proyecto ";
    private static final String SQL_TODAS = SQL_BASE + "ORDER BY v.id_vulnerabilidad";
    private static final String SQL_CLIENTE = SQL_BASE + "WHERE p.id_cliente = ? ORDER BY v.id_vulnerabilidad";
    private static final String SQL_INSERTAR = "INSERT INTO vulnerabilidad (id_activo, titulo, descripcion, tipo, "
            + "elemento_afectado, fecha_deteccion, estado, vector_cvss) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    private static final String SQL_ESTADO = "UPDATE vulnerabilidad SET estado = ?, id_responsable = ?, "
            + "fecha_objetivo = ? WHERE id_vulnerabilidad = ?";
    private static final String SQL_SEGUIMIENTO = "INSERT INTO seguimiento (id_vulnerabilidad, id_usuario, "
            + "fecha_hora, estado_anterior, estado_nuevo, comentario) VALUES (?, ?, ?, ?, ?, ?)";
    private static final String SQL_HISTORIAL = "SELECT s.id_seguimiento, s.id_vulnerabilidad, s.id_usuario, "
            + "u.nombre_acceso, s.fecha_hora, s.estado_anterior, s.estado_nuevo, s.comentario FROM seguimiento s "
            + "JOIN usuario u ON u.id_usuario = s.id_usuario WHERE s.id_vulnerabilidad = ? "
            + "ORDER BY s.fecha_hora, s.id_seguimiento";

    /* El rol decide la consulta: el cliente solo recibe las filas de sus proyectos (CU13) */
    @Override
    public ArrayList<Vulnerabilidad> listar(Usuario usuario) throws PersistenciaException {
        boolean todas = usuario.puedeGestionar();
        try (Connection con = ConexionBD.obtener();
             PreparedStatement ps = con.prepareStatement(todas ? SQL_TODAS : SQL_CLIENTE)) {
            if (!todas) {
                ps.setInt(1, usuario.getIdUsuario());
            }
            ArrayList<Vulnerabilidad> lista = new ArrayList<>();       // la cantidad depende de la consulta
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    lista.add(crear(rs));
                }
            }
            return lista;
        } catch (SQLException e) {
            throw new PersistenciaException("No se pudo leer el listado de vulnerabilidades.", e);
        }
    }

    @Override
    public int insertar(Vulnerabilidad v) throws PersistenciaException {
        try (Connection con = ConexionBD.obtener();
             PreparedStatement ps = con.prepareStatement(SQL_INSERTAR, Statement.RETURN_GENERATED_KEYS)) {
            ps.setInt(1, v.getIdActivo());
            ps.setString(2, v.getTitulo());
            ps.setString(3, v.getDescripcion());
            ps.setString(4, v.getTipo());
            ps.setString(5, v.getElementoAfectado());
            ps.setObject(6, v.getFechaDeteccion());
            ps.setString(7, v.getEstado().name());
            ps.setString(8, v.getVectorCvss());                 // null queda NULL ("Sin evaluar")
            ps.executeUpdate();
            try (ResultSet claves = ps.getGeneratedKeys()) {
                claves.next();
                return claves.getInt(1);                         // número AUTO_INCREMENT del hallazgo
            }
        } catch (SQLException e) {
            throw new PersistenciaException("No se pudo registrar la vulnerabilidad.", e);
        }
    }

    /*--------------------------------------------------
     * UPDATE del hallazgo e INSERT del seguimiento en la misma
     * transacción (RNF03). Si falla cualquiera de los dos, rollback
     * y la base queda como estaba (nunca un estado sin su historial).
     *--------------------------------------------------*/
    @Override
    public void guardarCambioEstado(Vulnerabilidad v, Seguimiento s) throws PersistenciaException {
        try (Connection con = ConexionBD.obtener()) {
            con.setAutoCommit(false);                            // empieza la transacción
            try (PreparedStatement actualizar = con.prepareStatement(SQL_ESTADO);
                 PreparedStatement registrar = con.prepareStatement(SQL_SEGUIMIENTO)) {
                actualizar.setString(1, v.getEstado().name());
                actualizar.setObject(2, v.getIdResponsable());   // Integer, admite null
                actualizar.setObject(3, v.getFechaObjetivo());
                actualizar.setInt(4, v.getIdVulnerabilidad());
                actualizar.executeUpdate();
                registrar.setInt(1, s.getIdVulnerabilidad());
                registrar.setInt(2, s.getIdUsuario());
                registrar.setObject(3, s.getFechaHora());
                registrar.setString(4, s.getEstadoAnterior().name());
                registrar.setString(5, s.getEstadoNuevo().name());
                registrar.setString(6, s.getComentario());
                registrar.executeUpdate();
                con.commit();                                    // se confirman los dos cambios juntos
            } catch (SQLException e) {
                con.rollback();                                  // se deshace el UPDATE si falló el INSERT
                throw e;                                         // lo traduce el catch de afuera
            }
        } catch (SQLException e) {
            throw new PersistenciaException("No se pudo guardar el cambio de estado, la base quedó como estaba.", e);
        }
    }

    @Override
    public ArrayList<Seguimiento> historial(int idVulnerabilidad) throws PersistenciaException {
        try (Connection con = ConexionBD.obtener();
             PreparedStatement ps = con.prepareStatement(SQL_HISTORIAL)) {
            ps.setInt(1, idVulnerabilidad);
            ArrayList<Seguimiento> lista = new ArrayList<>();
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    lista.add(new Seguimiento(rs.getInt("id_seguimiento"), rs.getInt("id_vulnerabilidad"),
                            rs.getInt("id_usuario"), rs.getString("nombre_acceso"),
                            rs.getObject("fecha_hora", LocalDateTime.class),
                            EstadoVulnerabilidad.valueOf(rs.getString("estado_anterior")),
                            EstadoVulnerabilidad.valueOf(rs.getString("estado_nuevo")), rs.getString("comentario")));
                }
            }
            return lista;
        } catch (SQLException e) {
            throw new PersistenciaException("No se pudo leer el historial del hallazgo.", e);
        }
    }

    /* Convierte la fila actual del ResultSet en un objeto del modelo */
    private static Vulnerabilidad crear(ResultSet rs) throws SQLException {
        int idResponsable = rs.getInt("id_responsable");
        Integer responsable = rs.wasNull() ? null : idResponsable;      // NULL de la base = sin responsable
        return new Vulnerabilidad(rs.getInt("id_vulnerabilidad"), rs.getInt("id_activo"), responsable,
                rs.getString("titulo"), rs.getString("descripcion"), rs.getString("tipo"),
                rs.getString("elemento_afectado"), rs.getObject("fecha_deteccion", LocalDate.class),
                rs.getObject("fecha_objetivo", LocalDate.class), EstadoVulnerabilidad.valueOf(rs.getString("estado")),
                rs.getString("vector_cvss"));
    }
}
