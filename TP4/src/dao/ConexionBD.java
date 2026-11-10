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
import java.sql.DriverManager;
import java.sql.SQLException;

/*--------------------------------------------------
 * Abre las conexiones con MySQL (el de XAMPP en el mismo equipo).
 * Cada operación pide una conexión y la cierra al terminar con
 * try-with-resources, así nunca queda una conexión abierta colgada.
 * Los datos de conexión se pueden cambiar sin recompilar con
 *   -Dvulnerabilidades.url=jdbc:mysql://servidor:3306/vulnerabilidades_db
 *   -Dvulnerabilidades.usuario=...   -Dvulnerabilidades.clave=...
 *--------------------------------------------------*/
public final class ConexionBD {

    private static final String URL = System.getProperty("vulnerabilidades.url",
            "jdbc:mysql://localhost:3306/vulnerabilidades_db?connectTimeout=3000");
    private static final String USUARIO = System.getProperty("vulnerabilidades.usuario", "root");  // el de XAMPP
    private static final String CLAVE = System.getProperty("vulnerabilidades.clave", "");          // XAMPP no trae clave

    private ConexionBD() { }                        // clase utilitaria, no se instancia

    public static Connection obtener() throws PersistenciaException {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");                     // carga el driver de MySQL
            return DriverManager.getConnection(URL, USUARIO, CLAVE);
        } catch (ClassNotFoundException e) {
            throw new PersistenciaException("No se encontró el driver de MySQL (falta el archivo "
                    + "lib/mysql-connector-j-8.4.0.jar en el classpath).", e);
        } catch (SQLException e) {
            throw new PersistenciaException("No se pudo conectar con la base de datos. Verifique que MySQL "
                    + "esté iniciado y que exista vulnerabilidades_db.", e);
        }
    }
}
