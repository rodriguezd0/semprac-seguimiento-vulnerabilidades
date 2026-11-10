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
import java.util.ArrayList;

import modelo.Activo;
import modelo.Proyecto;
import modelo.Responsable;
import modelo.Usuario;

/*--------------------------------------------------
 * Lectura de proyectos, activos y responsables para los combos y
 * para mostrar nombres en la tabla. En el prototipo son solo
 * consultas (el alta de estos datos queda fuera del alcance).
 *--------------------------------------------------*/
public class CatalogoDAO {

    private static final String SQL_PROYECTOS = "SELECT id_proyecto, nombre, descripcion, id_cliente FROM proyecto "
            + "ORDER BY id_proyecto";
    private static final String SQL_PROYECTOS_CLIENTE = "SELECT id_proyecto, nombre, descripcion, id_cliente "
            + "FROM proyecto WHERE id_cliente = ? ORDER BY id_proyecto";
    private static final String SQL_ACTIVOS = "SELECT id_activo, id_proyecto, nombre, tipo, descripcion FROM activo "
            + "ORDER BY id_activo";
    private static final String SQL_RESPONSABLES = "SELECT id_responsable, nombre, contacto FROM responsable "
            + "ORDER BY id_responsable";

    /* Todos para el administrador y solo los propios para un cliente */
    public ArrayList<Proyecto> proyectos(Usuario usuario) throws PersistenciaException {
        boolean todos = usuario.puedeGestionar();
        try (Connection con = ConexionBD.obtener();
             PreparedStatement ps = con.prepareStatement(todos ? SQL_PROYECTOS : SQL_PROYECTOS_CLIENTE)) {
            if (!todos) {
                ps.setInt(1, usuario.getIdUsuario());
            }
            ArrayList<Proyecto> lista = new ArrayList<>();
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    lista.add(new Proyecto(rs.getInt(1), rs.getString(2), rs.getString(3), rs.getInt(4)));
                }
            }
            return lista;
        } catch (SQLException e) {
            throw new PersistenciaException("No se pudo leer la lista de proyectos.", e);
        }
    }

    public ArrayList<Activo> activos() throws PersistenciaException {
        try (Connection con = ConexionBD.obtener();
             PreparedStatement ps = con.prepareStatement(SQL_ACTIVOS);
             ResultSet rs = ps.executeQuery()) {
            ArrayList<Activo> lista = new ArrayList<>();
            while (rs.next()) {
                lista.add(new Activo(rs.getInt(1), rs.getInt(2), rs.getString(3), rs.getString(4), rs.getString(5)));
            }
            return lista;
        } catch (SQLException e) {
            throw new PersistenciaException("No se pudo leer la lista de activos.", e);
        }
    }

    public ArrayList<Responsable> responsables() throws PersistenciaException {
        try (Connection con = ConexionBD.obtener();
             PreparedStatement ps = con.prepareStatement(SQL_RESPONSABLES);
             ResultSet rs = ps.executeQuery()) {
            ArrayList<Responsable> lista = new ArrayList<>();
            while (rs.next()) {
                lista.add(new Responsable(rs.getInt(1), rs.getString(2), rs.getString(3)));
            }
            return lista;
        } catch (SQLException e) {
            throw new PersistenciaException("No se pudo leer la lista de responsables.", e);
        }
    }
}
