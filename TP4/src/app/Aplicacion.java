/*
 * Universidad Siglo 21 - Seminario de Práctica de Informática
 * Proyecto: Sistema de seguimiento de vulnerabilidades por proyecto
 * Alumno: Rodríguez, Daniel Sebastián
 * Legajo: VINF016869
 * DNI: 43.731.653
 * Trabajo Práctico 4 [TP4] - Versión final
 */
package app;

import java.awt.Font;
import java.util.Locale;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;

import controlador.ControladorVulnerabilidades;
import dao.CatalogoDAO;
import dao.UsuarioDAO;
import dao.VulnerabilidadDAOMySQL;
import vista.VentanaLogin;

/*--------------------------------------------------
 * Punto de entrada. Arma las piezas del MVC (los DAO, el
 * controlador y la primera ventana) y abre el inicio de sesión.
 * Uso: java -cp "bin;lib/mysql-connector-j-8.4.0.jar" app.Aplicacion
 *--------------------------------------------------*/
public class Aplicacion {

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {                  // Swing se usa desde su propio hilo (EDT)
            aplicarAspecto();
            ControladorVulnerabilidades controlador = new ControladorVulnerabilidades(
                    new UsuarioDAO(), new VulnerabilidadDAOMySQL(), new CatalogoDAO());
            new VentanaLogin(controlador).mostrar();
        });
    }

    /* Aspecto de Windows, textos de Swing en español y la misma fuente de los prototipos del TP2 */
    public static void aplicarAspecto() {
        Locale.setDefault(Locale.of("es", "AR"));          // "Aceptar" y "Cancelar" en los cuadros de diálogo
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (ReflectiveOperationException | UnsupportedLookAndFeelException e) {
            System.err.println("Se usa el aspecto por defecto de Swing (" + e.getMessage() + ")");
        }
        UIManager.put("Label.font", new Font("Segoe UI", Font.PLAIN, 13));
    }
}
