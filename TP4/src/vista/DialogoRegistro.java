/*
 * Universidad Siglo 21 - Seminario de Práctica de Informática
 * Proyecto: Sistema de seguimiento de vulnerabilidades por proyecto
 * Alumno: Rodríguez, Daniel Sebastián
 * Legajo: VINF016869
 * DNI: 43.731.653
 * Trabajo Práctico 4 [TP4] - Versión final
 */
package vista;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagLayout;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.format.ResolverStyle;
import java.util.ArrayList;
import java.util.Locale;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;

import controlador.ControladorVulnerabilidades;
import dao.PersistenciaException;
import modelo.Activo;
import modelo.CalculadoraCvss31;
import modelo.Proyecto;
import modelo.ReglaNegocioException;

/*--------------------------------------------------
 * Registro de una vulnerabilidad (CU03) con el panel CVSS (CU12),
 * igual al prototipo del TP2. Las métricas son siempre ocho, por
 * eso están en arreglos. Los combos se crean recorriendo esos
 * arreglos y se guardan en un ArrayList.
 *--------------------------------------------------*/
public final class DialogoRegistro {

    private static final String[] METRICAS = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"};
    private static final String[] NOMBRES = {"Vector de ataque", "Complejidad", "Privilegios", "Interacción",
                                             "Alcance", "Confidencialidad", "Integridad", "Disponibilidad"};
    private static final String[][] OPCIONES = {
        {"Red (N)", "Adyacente (A)", "Local (L)", "Física (P)"},
        {"Baja (L)", "Alta (H)"},
        {"Ninguno (N)", "Bajos (L)", "Altos (H)"},
        {"Ninguna (N)", "Requerida (R)"},
        {"Sin cambio (U)", "Cambiado (C)"},
        {"Alta (H)", "Baja (L)", "Ninguna (N)"},
        {"Alta (H)", "Baja (L)", "Ninguna (N)"},
        {"Alta (H)", "Baja (L)", "Ninguna (N)"}};
    private static final DateTimeFormatter FECHA =
            DateTimeFormatter.ofPattern("dd/MM/uuuu").withResolverStyle(ResolverStyle.STRICT);
    private static final Locale ARGENTINA = Locale.of("es", "AR");

    private final JDialog dialogo;
    private final ControladorVulnerabilidades controlador;
    private final ArrayList<Proyecto> proyectos;
    private final JComboBox<String> cmbProyecto = new JComboBox<>();
    private final JComboBox<Activo> cmbActivo = new JComboBox<>();
    private final JTextField txtTitulo = new JTextField(28);
    private final JTextField txtTipo = new JTextField(28);
    private final JTextField txtElemento = new JTextField(28);
    private final JTextField txtFecha = new JTextField(10);
    private final JTextArea txtDescripcion = new JTextArea(3, 28);
    private final JCheckBox chkEvaluar = new JCheckBox("Evaluar ahora", true);
    private final ArrayList<JComboBox<String>> combos = new ArrayList<>();
    private final JLabel lblPuntaje = new JLabel();
    private final JLabel lblVector = new JLabel(" ");
    private boolean guardado = false;

    public DialogoRegistro(JFrame duenio, ControladorVulnerabilidades controlador) {
        this.controlador = controlador;
        this.proyectos = controlador.getProyectos();
        dialogo = new JDialog(duenio, "Registrar vulnerabilidad", true);    // modal
        JPanel raiz = new JPanel(new BorderLayout(10, 8));
        raiz.setBorder(new EmptyBorder(12, 12, 10, 12));
        raiz.add(armarDatos(), BorderLayout.WEST);
        raiz.add(armarCvss(), BorderLayout.CENTER);
        JButton btnGuardar = new JButton("Guardar");
        JButton btnCancelar = new JButton("Cancelar");
        btnGuardar.setName("btnGuardar");
        btnGuardar.addActionListener(e -> guardar());
        btnCancelar.addActionListener(e -> dialogo.dispose());
        JPanel botones = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        botones.add(btnGuardar);
        botones.add(btnCancelar);
        raiz.add(botones, BorderLayout.SOUTH);
        dialogo.setContentPane(raiz);
        actualizarPuntaje();
        dialogo.pack();
        dialogo.setLocationRelativeTo(duenio);
    }

    /* Muestra el diálogo (modal, espera a que se cierre) y devuelve true si se guardó */
    public boolean mostrar() {
        dialogo.setVisible(true);
        return guardado;
    }

    private JPanel armarDatos() {
        for (Proyecto p : proyectos) {
            cmbProyecto.addItem(p.getNombre());
        }
        cmbProyecto.addActionListener(e -> cargarActivos());
        cargarActivos();
        txtFecha.setText(ControladorVulnerabilidades.fecha(LocalDate.now()));
        txtDescripcion.setLineWrap(true);
        txtDescripcion.setWrapStyleWord(true);
        txtDescripcion.setFont(txtTitulo.getFont());          // JTextArea trae letra de ancho fijo por defecto
        JPanel datos = new JPanel(new GridBagLayout());
        datos.setBorder(new TitledBorder("Datos del hallazgo"));
        VentanaPrincipal.fila(datos, 0, "Proyecto:", cmbProyecto);
        VentanaPrincipal.fila(datos, 1, "Activo:", cmbActivo);
        VentanaPrincipal.fila(datos, 2, "Título:", txtTitulo);
        VentanaPrincipal.fila(datos, 3, "Tipo:", txtTipo);
        VentanaPrincipal.fila(datos, 4, "Elemento afectado:", txtElemento);
        VentanaPrincipal.fila(datos, 5, "Fecha de detección:", txtFecha);
        VentanaPrincipal.fila(datos, 6, "Descripción:", new JScrollPane(txtDescripcion));
        cmbProyecto.setName("cmbProyecto");
        cmbActivo.setName("cmbActivo");
        txtTitulo.setName("txtTitulo");
        txtTipo.setName("txtTipo");
        txtElemento.setName("txtElemento");
        txtFecha.setName("txtFecha");
        txtDescripcion.setName("txtDescripcion");
        return datos;
    }

    /* Cada proyecto tiene sus activos: al cambiar el proyecto se recarga el segundo combo */
    private void cargarActivos() {
        cmbActivo.removeAllItems();
        int i = cmbProyecto.getSelectedIndex();
        if (i >= 0) {
            for (Activo a : controlador.activosDe(proyectos.get(i))) {
                cmbActivo.addItem(a);
            }
        }
    }

    private JPanel armarCvss() {
        JPanel cvss = new JPanel(new GridBagLayout());
        cvss.setBorder(new TitledBorder("Evaluación CVSS 3.1 (opcional, CU12)"));
        VentanaPrincipal.filaCompleta(cvss, 0, chkEvaluar);
        for (int i = 0; i < METRICAS.length; i++) {
            JComboBox<String> combo = new JComboBox<>(OPCIONES[i]);
            combo.setName("cvss" + METRICAS[i]);
            combo.addActionListener(e -> actualizarPuntaje());
            combos.add(combo);
            VentanaPrincipal.fila(cvss, i + 1, NOMBRES[i] + " (" + METRICAS[i] + "):", combo);
        }
        chkEvaluar.setName("chkEvaluar");
        chkEvaluar.addActionListener(e -> actualizarPuntaje());
        lblPuntaje.setFont(lblPuntaje.getFont().deriveFont(Font.BOLD, 14f));
        VentanaPrincipal.filaCompleta(cvss, 9, lblPuntaje);
        VentanaPrincipal.filaCompleta(cvss, 10, lblVector);
        return cvss;
    }

    /* Vector CVSS con la letra entre paréntesis de cada opción ("Red (N)" da N), o null si no se evalúa */
    private String vector() {
        if (!chkEvaluar.isSelected()) {
            return null;
        }
        StringBuilder vector = new StringBuilder("CVSS:3.1");
        for (int i = 0; i < METRICAS.length; i++) {
            String opcion = (String) combos.get(i).getSelectedItem();
            vector.append('/').append(METRICAS[i]).append(':').append(opcion.charAt(opcion.length() - 2));
        }
        return vector.toString();
    }

    /* El puntaje se recalcula con la clase del modelo cada vez que cambia una métrica */
    private void actualizarPuntaje() {
        for (JComboBox<String> combo : combos) {
            combo.setEnabled(chkEvaluar.isSelected());
        }
        String vector = vector();
        if (vector == null) {
            lblPuntaje.setText("Sin evaluar");
            lblVector.setText(" ");
            return;
        }
        double puntaje = CalculadoraCvss31.calcularPuntaje(vector);
        lblPuntaje.setText(String.format(ARGENTINA, "Puntaje: %.1f   Severidad: %s", puntaje,
                                         CalculadoraCvss31.categoria(puntaje)));
        lblVector.setText(vector);
    }

    private void guardar() {
        try {
            LocalDate fecha = LocalDate.parse(txtFecha.getText().trim(), FECHA);
            int numero = controlador.registrar((Activo) cmbActivo.getSelectedItem(), txtTitulo.getText(),
                    txtDescripcion.getText(), txtTipo.getText(), txtElemento.getText(), fecha, vector());
            guardado = true;
            JOptionPane.showMessageDialog(dialogo, "Vulnerabilidad " + numero + " registrada en estado PENDIENTE.",
                                          "Registro guardado", JOptionPane.INFORMATION_MESSAGE);
            dialogo.dispose();
        } catch (ReglaNegocioException e) {
            JOptionPane.showMessageDialog(dialogo, e.getMessage(), "Datos incompletos", JOptionPane.WARNING_MESSAGE);
        } catch (DateTimeParseException e) {
            JOptionPane.showMessageDialog(dialogo, "La fecha de detección va como dd/mm/aaaa y tiene que existir.",
                                          "Fecha inválida", JOptionPane.WARNING_MESSAGE);
        } catch (PersistenciaException e) {
            JOptionPane.showMessageDialog(dialogo, e.getMessage(), "Error de la base de datos",
                                          JOptionPane.ERROR_MESSAGE);
        }
    }
}
