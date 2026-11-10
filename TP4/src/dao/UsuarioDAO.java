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

import modelo.Administrador;
import modelo.Cliente;
import modelo.Usuario;

/* Acceso a la tabla usuario (CU11) */
public class UsuarioDAO {

    private static final String SQL_BUSCAR = "SELECT id_usuario, nombre_acceso, nombre_completo, clave_hash, sal, "
            + "rol, activo FROM usuario WHERE nombre_acceso = ?";

    /*--------------------------------------------------
     * Busca la cuenta por su nombre de acceso y devuelve null si no
     * existe. La columna rol decide qué subclase de Usuario se crea,
     * así el resto del programa trabaja con Usuario sin preguntar.
     *--------------------------------------------------*/
    public Usuario buscarPorAcceso(String nombreAcceso) throws PersistenciaException {
        try (Connection con = ConexionBD.obtener();
             PreparedStatement ps = con.prepareStatement(SQL_BUSCAR)) {
            ps.setString(1, nombreAcceso);                  // parámetro, nunca concatenado (inyección SQL)
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return null;
                }
                int id = rs.getInt("id_usuario");
                String acceso = rs.getString("nombre_acceso");
                String nombre = rs.getString("nombre_completo");
                String hash = rs.getString("clave_hash");
                String sal = rs.getString("sal");
                boolean activo = rs.getBoolean("activo");
                if ("ADMINISTRADOR".equals(rs.getString("rol"))) {
                    return new Administrador(id, acceso, nombre, hash, sal, activo);
                }
                return new Cliente(id, acceso, nombre, hash, sal, activo);
            }
        } catch (SQLException e) {
            throw new PersistenciaException("No se pudo consultar la cuenta en la base de datos.", e);
        }
    }
}
