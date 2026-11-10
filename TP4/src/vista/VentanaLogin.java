/*
 * Universidad Siglo 21 - Seminario de Práctica de Informática
 * Proyecto: Sistema de seguimiento de vulnerabilidades por proyecto
 * Alumno: Rodríguez, Daniel Sebastián
 * Legajo: VINF016869
 * DNI: 43.731.653
 * Trabajo Práctico 4 [TP4] - Versión final
 */
package vista;

import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagLayout;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.WindowConstants;
import javax.swing.border.EmptyBorder;

import controlador.ControladorVulnerabilidades;
import dao.PersistenciaException;
import modelo.ReglaNegocioException;

/*--------------------------------------------------
 * Ventana de acceso (CU11), igual al prototipo del TP2. Solo toma
 * los datos y muestra el resultado. Quien verifica la clave es el
 * controlador, con el modelo y la base.
 *--------------------------------------------------*/
public final class VentanaLogin {

    private final JFrame ventana = new JFrame("Iniciar sesión - Vulnerabilidades");
    private final ControladorVulnerabilidades controlador;
    private final JTextField txtUsuario = new JTextField(18);
    private final JPasswordField txtClave = new JPasswordField(18);
    private final JLabel lblMensaje = new JLabel(texto("Las operaciones se habilitan según el rol de la cuenta."));

    public VentanaLogin(ControladorVulnerabilidades controlador) {
        this.controlador = controlador;
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(new EmptyBorder(16, 20, 12, 20));
        JLabel titulo = new JLabel("Ingrese sus credenciales");
        titulo.setFont(titulo.getFont().deriveFont(Font.BOLD, 15f));
        VentanaPrincipal.filaCompleta(panel, 0, titulo);
        VentanaPrincipal.fila(panel, 1, "Usuario:", txtUsuario);
        VentanaPrincipal.fila(panel, 2, "Contraseña:", txtClave);
        lblMensaje.setForeground(new Color(90, 90, 90));
        VentanaPrincipal.filaCompleta(panel, 3, lblMensaje);
        JButton btnIngresar = new JButton("Ingresar");
        JButton btnSalir = new JButton("Salir");
        btnIngresar.addActionListener(e -> ingresar());
        btnSalir.addActionListener(e -> ventana.dispose());
        JPanel botones = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        botones.add(btnIngresar);
        botones.add(btnSalir);
        VentanaPrincipal.filaCompleta(panel, 4, botones);
        txtUsuario.setName("txtUsuario");                 // nombres internos (los usa el programa de capturas)
        txtClave.setName("txtClave");
        btnIngresar.setName("btnIngresar");
        ventana.getRootPane().setDefaultButton(btnIngresar);  // Enter equivale a Ingresar
        ventana.setContentPane(panel);
        ventana.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        ventana.setResizable(false);
        ventana.pack();
        ventana.setLocationRelativeTo(null);
    }

    public void mostrar() {
        ventana.setVisible(true);
    }

    /* Si falla muestra el motivo en la ventana. La clave se borra siempre (finally) */
    private void ingresar() {
        try {
            controlador.iniciarSesion(txtUsuario.getText(), txtClave.getPassword());
            new VentanaPrincipal(controlador).mostrar();
            ventana.dispose();
        } catch (ReglaNegocioException | PersistenciaException e) {
            lblMensaje.setForeground(new Color(170, 30, 30));
            lblMensaje.setText(texto(e.getMessage()));
            ventana.pack();
        } finally {
            txtClave.setText("");                          // la clave no queda escrita, entre bien o mal
        }
    }

    /* HTML con ancho fijo para que los mensajes largos bajen de renglón */
    private static String texto(String mensaje) {
        return "<html><div style='width:270px'>" + mensaje + "</div></html>";
    }
}
