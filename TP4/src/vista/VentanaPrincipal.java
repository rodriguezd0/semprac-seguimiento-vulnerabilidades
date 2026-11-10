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
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;
import java.io.IOException;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.format.ResolverStyle;
import java.util.ArrayList;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;

import controlador.ControladorVulnerabilidades;
import dao.PersistenciaException;
import modelo.*;

/*--------------------------------------------------
 * Ventana principal (CU05 con acceso a CU03, CU06, CU07, CU08 y a
 * la carga desde la planilla). Los botones salen de
 * usuario.opcionesMenu(), así el cliente ve solo "Historial" sin
 * que la ventana pregunte el rol. Es parte de la vista del MVC: no
 * tiene SQL ni reglas, todo lo que muestra se lo pide al controlador.
 *--------------------------------------------------*/
public final class VentanaPrincipal {

    private static final String[] COLUMNAS = {"ID", "Proyecto", "Activo", "Título", "Estado", "CVSS", "Severidad",
                                              "Responsable", "Fecha objetivo"};
    private static final int[] ANCHOS = {35, 170, 180, 290, 115, 45, 80, 170, 100};
    private static final DateTimeFormatter FECHA =
            DateTimeFormatter.ofPattern("dd/MM/uuuu").withResolverStyle(ResolverStyle.STRICT);
    private static final DateTimeFormatter FECHA_HORA = DateTimeFormatter.ofPattern("dd/MM/uuuu HH:mm");

    private final JFrame ventana;
    private final ControladorVulnerabilidades controlador;
    private final JComboBox<String> cmbProyecto = new JComboBox<>();
    private final JComboBox<String> cmbEstado = new JComboBox<>();
    private final JComboBox<String> cmbSeveridad = new JComboBox<>();
    private final DefaultTableModel modelo = new DefaultTableModel(COLUMNAS, 0);
    private final JTable tabla = new JTable(modelo);
    private final JLabel lblResumen = new JLabel();
    private final ArrayList<Proyecto> proyectos;
    private ArrayList<Vulnerabilidad> listado = new ArrayList<>();    // filas que se ven en la tabla
    private String filtrosDelListado = "";                            // filtros con los que se armó listado

    public VentanaPrincipal(ControladorVulnerabilidades controlador) {
        this.controlador = controlador;
        this.proyectos = controlador.getProyectos();
        Usuario usuario = controlador.getUsuario();
        ventana = new JFrame("Seguimiento de vulnerabilidades - " + usuario.getNombreAcceso() + " ("
                             + usuario.getRol() + ")");
        JPanel raiz = new JPanel(new BorderLayout(0, 8));
        raiz.setBorder(new EmptyBorder(10, 10, 8, 10));
        raiz.add(armarFiltros(), BorderLayout.NORTH);
        raiz.add(armarTabla(), BorderLayout.CENTER);
        raiz.add(armarBotones(usuario), BorderLayout.SOUTH);
        ventana.setContentPane(raiz);
        ventana.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        ventana.pack();
        ventana.setLocationRelativeTo(null);
        actualizarTabla();
    }

    public void mostrar() {
        ventana.setVisible(true);
    }

    private JPanel armarFiltros() {
        cmbProyecto.addItem(ControladorVulnerabilidades.TODOS);
        for (Proyecto p : proyectos) {
            cmbProyecto.addItem(p.getNombre());
        }
        cmbEstado.addItem(ControladorVulnerabilidades.TODOS);
        cmbEstado.addItem(ControladorVulnerabilidades.ABIERTOS);
        for (EstadoVulnerabilidad e : EstadoVulnerabilidad.values()) {
            cmbEstado.addItem(e.name());
        }
        cmbSeveridad.addItem(ControladorVulnerabilidades.TODAS);
        for (String severidad : ControladorVulnerabilidades.SEVERIDADES) {
            cmbSeveridad.addItem(severidad);
        }
        JButton btnBuscar = new JButton("Buscar");
        btnBuscar.addActionListener(e -> actualizarTabla());
        JPanel filtros = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        filtros.setBorder(new TitledBorder("Filtros"));
        filtros.add(new JLabel("Proyecto:"));
        filtros.add(cmbProyecto);
        filtros.add(new JLabel("Estado:"));
        filtros.add(cmbEstado);
        filtros.add(new JLabel("Severidad:"));
        filtros.add(cmbSeveridad);
        filtros.add(btnBuscar);
        return filtros;
    }

    private JScrollPane armarTabla() {
        tabla.setDefaultEditor(Object.class, null);                 // la tabla es solo de consulta
        tabla.setRowHeight(22);
        tabla.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        tabla.setName("tabla");
        for (int i = 0; i < ANCHOS.length; i++) {
            tabla.getColumnModel().getColumn(i).setPreferredWidth(ANCHOS[i]);
        }
        JScrollPane scroll = new JScrollPane(tabla);
        scroll.setPreferredSize(new Dimension(1185, 250));
        return scroll;
    }

    /* Un botón por cada opción del rol (polimorfismo) y el de cerrar sesión */
    private JPanel armarBotones(Usuario usuario) {
        JPanel botones = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        for (String opcion : usuario.opcionesMenu()) {
            JButton boton = new JButton(opcion);
            boton.setName(opcion);
            boton.addActionListener(e -> ejecutar(opcion));
            botones.add(boton);
        }
        JButton btnCerrar = new JButton("Cerrar sesión");
        btnCerrar.setName("Cerrar sesión");
        btnCerrar.addActionListener(e -> cerrarSesion());
        botones.add(btnCerrar);
        JPanel sur = new JPanel(new BorderLayout());
        sur.add(botones, BorderLayout.WEST);
        sur.add(lblResumen, BorderLayout.EAST);
        return sur;
    }

    private void ejecutar(String opcion) {
        switch (opcion) {
            case "Nuevo hallazgo" -> nuevo();
            case "Cambiar estado" -> cambiarEstado();
            case "Historial" -> historial();
            case "Exportar TXT" -> exportar();
            case "Importar CSV" -> importar();
            default -> { }
        }
    }

    /*--------------------------------------------------
     * Vuelve a leer la base y llena la tabla con un arreglo Object[]
     * por fila. Si la base no responde se vacía la tabla, así nunca
     * queda a la vista (ni seleccionable) un objeto que no coincide
     * con lo guardado. También anota los filtros usados, que son los
     * que después declara el archivo exportado.
     *--------------------------------------------------*/
    private void actualizarTabla() {
        modelo.setRowCount(0);
        try {
            int i = cmbProyecto.getSelectedIndex();
            Proyecto proyecto = i <= 0 ? null : proyectos.get(i - 1);   // la posición 0 es "Todos"
            listado = controlador.listar(proyecto, (String) cmbEstado.getSelectedItem(),
                                         (String) cmbSeveridad.getSelectedItem());
            filtrosDelListado = "Proyecto " + cmbProyecto.getSelectedItem() + " | Estado "
                                + cmbEstado.getSelectedItem() + " | Severidad " + cmbSeveridad.getSelectedItem();
        } catch (PersistenciaException e) {
            listado = new ArrayList<>();
            lblResumen.setText("Sin datos (no se pudo leer la base)  ");
            error("Error de la base de datos", e.getMessage());
            return;
        }
        for (Vulnerabilidad v : listado) {
            Object[] fila = {v.getIdVulnerabilidad(), controlador.nombreProyecto(v), controlador.nombreActivo(v),
                    v.getTitulo(), v.getEstado(), ControladorVulnerabilidades.puntaje(v), v.getSeveridad(),
                    controlador.nombreResponsable(v), ControladorVulnerabilidades.fecha(v.getFechaObjetivo())};
            modelo.addRow(fila);
        }
        lblResumen.setText(controlador.resumen(listado) + "  ");
    }

    private Vulnerabilidad seleccionada() {
        int fila = tabla.getSelectedRow();
        if (fila < 0) {
            aviso("Seleccione un hallazgo de la tabla.");
            return null;
        }
        return listado.get(fila);
    }

    /* CU03 con CU12 */
    private void nuevo() {
        if (new DialogoRegistro(ventana, controlador).mostrar()) {
            actualizarTabla();
        }
    }

    /*--------------------------------------------------
     * CU06 en un cuadro de JOptionPane. Si el hallazgo pasa a
     * tratamiento sin responsable, el mismo cuadro pide responsable y
     * fecha objetivo (CU04) y todo se guarda en la misma transacción.
     *--------------------------------------------------*/
    private void cambiarEstado() {
        Vulnerabilidad v = seleccionada();
        if (v == null) {
            return;
        }
        EstadoVulnerabilidad actual = v.getEstado();
        JComboBox<EstadoVulnerabilidad> cmbNuevo = new JComboBox<>();
        for (EstadoVulnerabilidad e : EstadoVulnerabilidad.values()) {
            if (e != actual) {
                cmbNuevo.addItem(e);
            }
            if (actual.puedePasarA(e)) {
                cmbNuevo.setSelectedItem(e);                        // queda elegida la transición permitida
            }
        }
        JComboBox<Responsable> cmbResponsable = new JComboBox<>();
        for (Responsable r : controlador.getResponsables()) {
            cmbResponsable.addItem(r);
            if (v.getIdResponsable() != null && r.getIdResponsable() == v.getIdResponsable()) {
                cmbResponsable.setSelectedItem(r);
            }
        }
        JTextField txtFecha = new JTextField(ControladorVulnerabilidades.fecha(v.tieneAsignacion()
                ? v.getFechaObjetivo() : LocalDate.now().plusDays(7)), 10);
        cmbResponsable.setEnabled(!v.tieneAsignacion());            // si ya está asignado, solo se muestra
        txtFecha.setEnabled(!v.tieneAsignacion());
        JTextArea txtComentario = new JTextArea(3, 36);
        txtComentario.setLineWrap(true);
        txtComentario.setWrapStyleWord(true);
        txtComentario.setFont(txtFecha.getFont());                  // misma letra que los demás campos
        cmbNuevo.setName("cmbNuevo");
        cmbResponsable.setName("cmbResponsable");
        txtFecha.setName("txtFechaObjetivo");
        txtComentario.setName("txtComentario");
        JPanel panel = new JPanel(new GridBagLayout());
        fila(panel, 0, "Hallazgo:", new JLabel(v.getIdVulnerabilidad() + " | " + v.getTitulo()));
        fila(panel, 1, "Estado actual:", new JLabel(actual.name()));
        fila(panel, 2, "Nuevo estado:", cmbNuevo);
        fila(panel, 3, "Responsable:", cmbResponsable);
        fila(panel, 4, "Fecha objetivo:", txtFecha);
        fila(panel, 5, "Comentario:", new JScrollPane(txtComentario));
        JLabel ayuda = new JLabel("Para iniciar el tratamiento hacen falta responsable y fecha objetivo. "
                                  + "El comentario es obligatorio.");
        ayuda.setForeground(new Color(90, 90, 90));
        filaCompleta(panel, 6, ayuda);
        int respuesta = JOptionPane.showConfirmDialog(ventana, panel, "Cambiar estado - hallazgo "
                + v.getIdVulnerabilidad(), JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (respuesta != JOptionPane.OK_OPTION) {
            return;
        }
        EstadoVulnerabilidad nuevo = (EstadoVulnerabilidad) cmbNuevo.getSelectedItem();
        try {
            LocalDate fechaObjetivo = v.tieneAsignacion() ? v.getFechaObjetivo()
                    : LocalDate.parse(txtFecha.getText().trim(), FECHA);
            controlador.cambiarEstado(v, nuevo, txtComentario.getText(),
                                      (Responsable) cmbResponsable.getSelectedItem(), fechaObjetivo);
            JOptionPane.showMessageDialog(ventana, "Estado actualizado, " + actual + " pasa a " + nuevo
                    + ". El cambio quedó en el historial.", "Cambio de estado guardado",
                    JOptionPane.INFORMATION_MESSAGE);
        } catch (ReglaNegocioException e) {
            aviso(e.getMessage());
        } catch (DateTimeParseException e) {
            aviso("La fecha objetivo va como dd/mm/aaaa y tiene que existir.");
        } catch (PersistenciaException e) {
            error("Error de la base de datos", e.getMessage());
        }
        actualizarTabla();                     // se relee la base, haya salido bien o mal
    }

    /* CU07: el historial va en una matriz Object[][] (una fila por cambio) */
    private void historial() {
        Vulnerabilidad v = seleccionada();
        if (v == null) {
            return;
        }
        try {
            ArrayList<Seguimiento> cambios = controlador.historial(v);
            Object[][] datos = new Object[cambios.size()][];
            for (int i = 0; i < cambios.size(); i++) {
                Seguimiento s = cambios.get(i);
                datos[i] = new Object[] {s.getFechaHora().format(FECHA_HORA), s.getEstadoAnterior(),
                                         s.getEstadoNuevo(), s.getUsuario(), s.getComentario()};
            }
            String[] columnas = {"Fecha y hora", "Estado anterior", "Estado nuevo", "Usuario", "Comentario"};
            JTable tablaHistorial = new JTable(datos, columnas);
            tablaHistorial.setDefaultEditor(Object.class, null);
            tablaHistorial.setRowHeight(22);
            int[] anchos = {110, 115, 115, 95, 380};
            for (int i = 0; i < anchos.length; i++) {
                tablaHistorial.getColumnModel().getColumn(i).setPreferredWidth(anchos[i]);
            }
            JScrollPane scroll = new JScrollPane(tablaHistorial);
            scroll.setPreferredSize(new Dimension(815, 130));
            JOptionPane.showMessageDialog(ventana, new Object[] {v.getTitulo(), scroll},
                    "Historial - hallazgo " + v.getIdVulnerabilidad(), JOptionPane.PLAIN_MESSAGE);
        } catch (PersistenciaException e) {
            error("Error de la base de datos", e.getMessage());
        }
    }

    /*--------------------------------------------------
     * CU08: guarda el listado que se ve en pantalla y muestra el
     * archivo leído del disco. Los filtros que se anotan son los de la
     * última búsqueda (los de las filas), no los que los combos tengan
     * ahora si el usuario los cambió sin pulsar Buscar.
     *--------------------------------------------------*/
    private void exportar() {
        try {
            File archivo = controlador.exportar(listado, filtrosDelListado);
            mostrarTexto("Listado exportado", "Se guardó el archivo " + archivo.getPath()
                         + ". Este es su contenido, leído del disco.", controlador.leerArchivo(archivo), 900);
        } catch (IOException e) {
            error("Error al guardar el archivo", "No se pudo guardar el listado (" + e.getMessage() + ").");
        }
    }

    /*--------------------------------------------------
     * Carga desde la planilla en CSV. El JFileChooser solo deja elegir
     * el archivo, la lectura y las validaciones las hace el controlador.
     * Al final se muestra el informe fila por fila y se relee la base.
     *--------------------------------------------------*/
    private void importar() {
        JFileChooser selector = new JFileChooser(new File("entradas"));
        selector.setDialogTitle("Importar hallazgos desde la planilla (CSV)");
        selector.setFileFilter(new FileNameExtensionFilter("Planilla CSV separada por punto y coma", "csv"));
        if (selector.showOpenDialog(ventana) != JFileChooser.APPROVE_OPTION) {
            return;                                                  // el usuario canceló
        }
        try {
            ArrayList<String> informe = controlador.importar(selector.getSelectedFile());
            mostrarTexto("Importación terminada", informe.remove(0), informe, 760);   // la línea 0 es el resumen
        } catch (IOException e) {
            error("Error al leer el archivo", "No se pudo leer " + selector.getSelectedFile().getName()
                  + " (" + e.getMessage() + ").");
        }
        actualizarTabla();
    }

    /* Cuadro con un título y las líneas de un archivo o de un informe, en letra de ancho fijo */
    private void mostrarTexto(String titulo, String encabezado, ArrayList<String> lineas, int ancho) {
        JTextArea contenido = new JTextArea(String.join("\n", lineas));
        contenido.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        contenido.setEditable(false);
        contenido.setName("txtContenido");
        int renglones = Math.min(lineas.size(), 18);                 // más de 18 líneas, con barra de desplazamiento
        int alto = renglones * contenido.getFontMetrics(contenido.getFont()).getHeight() + 12;
        JScrollPane scroll = new JScrollPane(contenido);
        scroll.setPreferredSize(new Dimension(ancho, alto));
        JOptionPane.showMessageDialog(ventana, new Object[] {encabezado, scroll}, titulo,
                                      JOptionPane.INFORMATION_MESSAGE);
    }

    private void cerrarSesion() {
        controlador.cerrarSesion();
        ventana.dispose();
        new VentanaLogin(controlador).mostrar();
    }

    private void aviso(String mensaje) {
        JOptionPane.showMessageDialog(ventana, mensaje, "Operación rechazada", JOptionPane.WARNING_MESSAGE);
    }

    private void error(String titulo, String mensaje) {
        JOptionPane.showMessageDialog(ventana, mensaje, titulo, JOptionPane.ERROR_MESSAGE);
    }

    /* Utilidades de armado que también usan VentanaLogin y DialogoRegistro (etiqueta a la izquierda) */
    static void fila(JPanel panel, int y, String etiqueta, JComponent componente) {
        GridBagConstraints c = restricciones(y);
        panel.add(new JLabel(etiqueta), c);
        c.gridx = 1;
        c.weightx = 1;
        panel.add(componente, c);
    }

    static void filaCompleta(JPanel panel, int y, JComponent componente) {
        GridBagConstraints c = restricciones(y);
        c.gridwidth = 2;
        panel.add(componente, c);
    }

    private static GridBagConstraints restricciones(int y) {
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 4);
        c.anchor = GridBagConstraints.WEST;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.gridx = 0;
        c.gridy = y;
        return c;
    }
}
