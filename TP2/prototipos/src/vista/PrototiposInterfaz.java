/*
 * Universidad Siglo 21 - Seminario de Práctica de Informática
 * Proyecto: Sistema de seguimiento de vulnerabilidades por proyecto
 * Alumno: Rodríguez, Daniel Sebastián
 * Legajo: VINF016869
 * DNI: 43.731.653
 */
package vista;

import java.awt.*;
import java.awt.image.BufferedImage;
import java.awt.image.MultiResolutionImage;
import java.io.File;
import java.util.List;
import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;
import modelo.CalculadoraCvss31;

/*--------------------------------------------------
 * Prototipos de interfaz (Swing) de cuatro pantallas del sistema.
 * No tienen lógica de negocio conectada: arman las ventanas con
 * datos de prueba y las guardan como PNG en la carpeta indicada.
 * El panel CVSS sí usa la clase CalculadoraCvss31 del modelo.
 * Uso: java -cp bin;../pruebas/bin vista.PrototiposInterfaz <carpetaSalida>
 *--------------------------------------------------*/
public class PrototiposInterfaz {

    private static final Font FUENTE = new Font("Segoe UI", Font.PLAIN, 13);

    public static void main(String[] args) throws Exception {
        String salida = args.length > 0 ? args[0] : ".";
        UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        UIManager.put("Label.font", FUENTE);
        capturar(ventanaLogin(), salida + "/prototipo_1_login.png");
        capturar(ventanaConsulta(), salida + "/prototipo_2_consulta.png");
        capturar(ventanaRegistro(), salida + "/prototipo_3_registro_cvss.png");
        capturar(ventanaCambioEstado(), salida + "/prototipo_4_cambio_estado.png");
        System.exit(0);
    }

    /*--------------------------------------------------
     * CU11: inicio de sesión.
     *--------------------------------------------------*/
    private static Window ventanaLogin() {
        JFrame f = new JFrame("Iniciar sesión - Vulnerabilidades");
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(new EmptyBorder(16, 20, 12, 20));
        GridBagConstraints c = base();
        JLabel titulo = new JLabel("Ingrese sus credenciales");
        titulo.setFont(FUENTE.deriveFont(Font.BOLD, 15f));
        c.gridwidth = 2;
        p.add(titulo, c);
        c.gridwidth = 1;
        fila(p, c, 1, "Usuario:", campo("ref.expedientes", 18));
        JPasswordField clave = new JPasswordField("clave-de-prueba", 18);
        fila(p, c, 2, "Contraseña:", clave);
        JLabel aviso = new JLabel("Las operaciones se habilitan según el rol de la cuenta.");
        aviso.setForeground(new Color(90, 90, 90));
        c.gridx = 0; c.gridy = 3; c.gridwidth = 2;
        p.add(aviso, c);
        JPanel botones = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        botones.add(new JButton("Ingresar"));
        botones.add(new JButton("Salir"));
        c.gridy = 4;
        p.add(botones, c);
        f.setContentPane(p);
        return f;
    }

    /*--------------------------------------------------
     * CU05 con acceso a CU07, CU08, CU03 y CU06 (vista del administrador).
     *--------------------------------------------------*/
    private static Window ventanaConsulta() {
        JFrame f = new JFrame("Consulta de vulnerabilidades - dsrodriguez (ADMINISTRADOR)");
        JPanel raiz = new JPanel(new BorderLayout(0, 8));
        raiz.setBorder(new EmptyBorder(10, 10, 8, 10));

        JPanel filtros = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        filtros.setBorder(new TitledBorder("Filtros"));
        filtros.add(new JLabel("Proyecto:"));
        filtros.add(combo("Todos", "Portal web institucional", "Gestión de expedientes", "Infraestructura de oficina"));
        filtros.add(new JLabel("Estado:"));
        filtros.add(combo("Abiertos (sin CERRADA)", "PENDIENTE", "EN_TRATAMIENTO", "CERRADA", "Todos"));
        filtros.add(new JLabel("Severidad:"));
        filtros.add(combo("Todas", "Crítica", "Alta", "Media", "Baja", "Ninguna", "Sin evaluar"));
        filtros.add(new JButton("Buscar"));
        raiz.add(filtros, BorderLayout.NORTH);

        String[] columnas = {"ID", "Proyecto", "Activo", "Título", "Estado", "CVSS", "Severidad", "Responsable", "Fecha objetivo"};
        Object[][] filas = {
            {4, "Infraestructura de oficina", "NAS de respaldos", "Panel del NAS con credenciales por defecto", "EN_TRATAMIENTO", "8,8", "Alta", "Soporte de infraestructura", "02/10/2026"},
            {2, "Gestión de expedientes", "Aplicación de expedientes", "Inyección SQL en la búsqueda de expedientes", "EN_TRATAMIENTO", "8,1", "Alta", "Desarrollo interno", "30/09/2026"},
            {3, "Portal web institucional", "Formulario de contacto", "XSS reflejado en el formulario de contacto", "PENDIENTE", "6,1", "Media", "Desarrollo interno", "05/10/2026"},
            {5, "Portal web institucional", "Servidor web", "Divulgación de versión en encabezados HTTP", "PENDIENTE", "5,3", "Media", "", ""},
            {6, "Gestión de expedientes", "Base de datos de expedientes", "Conexión a la base sin cifrado en la red interna", "PENDIENTE", "", "Sin evaluar", "", ""},
        };
        JTable tabla = new JTable(new DefaultTableModel(filas, columnas));
        tabla.setRowHeight(22);
        tabla.setRowSelectionInterval(0, 0);
        int[] anchos = {35, 170, 170, 290, 115, 45, 80, 170, 100};
        for (int i = 0; i < anchos.length; i++) {
            tabla.getColumnModel().getColumn(i).setPreferredWidth(anchos[i]);
        }
        JScrollPane scroll = new JScrollPane(tabla);
        scroll.setPreferredSize(new Dimension(1175, 150));
        raiz.add(scroll, BorderLayout.CENTER);

        JPanel sur = new JPanel(new BorderLayout());
        JPanel botones = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
        for (String b : List.of("Nuevo hallazgo", "Ver detalle", "Ver historial", "Cambiar estado", "Exportar TXT", "Cerrar sesión")) {
            botones.add(new JButton(b));
        }
        sur.add(botones, BorderLayout.WEST);
        sur.add(new JLabel("5 hallazgos abiertos  "), BorderLayout.EAST);
        raiz.add(sur, BorderLayout.SOUTH);
        f.setContentPane(raiz);
        return f;
    }

    /*--------------------------------------------------
     * CU03 con la extensión CU12 (panel de evaluación CVSS).
     *--------------------------------------------------*/
    private static Window ventanaRegistro() {
        JDialog d = new JDialog((Frame) null, "Registrar vulnerabilidad");
        JPanel raiz = new JPanel(new BorderLayout(10, 8));
        raiz.setBorder(new EmptyBorder(12, 12, 10, 12));

        JPanel datos = new JPanel(new GridBagLayout());
        datos.setBorder(new TitledBorder("Datos del hallazgo"));
        GridBagConstraints c = base();
        fila(datos, c, 0, "Proyecto:", combo("Gestión de expedientes"));
        fila(datos, c, 1, "Activo:", combo("Aplicación de expedientes", "Base de datos de expedientes"));
        fila(datos, c, 2, "Título:", campo("Inyección SQL en la búsqueda de expedientes", 28));
        fila(datos, c, 3, "Tipo:", campo("Inyección", 28));
        fila(datos, c, 4, "Elemento afectado:", campo("Parámetro q de /expedientes/buscar", 28));
        fila(datos, c, 5, "Fecha de detección:", campo("02/09/2026", 10));
        JTextArea desc = new JTextArea("El parámetro de búsqueda se concatena en la consulta.", 3, 28);
        desc.setLineWrap(true);
        fila(datos, c, 6, "Descripción:", new JScrollPane(desc));
        raiz.add(datos, BorderLayout.WEST);

        // Panel CVSS: los valores elegidos arman el vector y la calculadora da el puntaje
        String vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N";
        double puntaje = CalculadoraCvss31.calcularPuntaje(vector);
        JPanel cvss = new JPanel(new GridBagLayout());
        cvss.setBorder(new TitledBorder("Evaluación CVSS 3.1 (opcional, CU12)"));
        GridBagConstraints k = base();
        fila(cvss, k, 0, "Vector de ataque (AV):", combo("Red (N)", "Adyacente (A)", "Local (L)", "Física (P)"));
        fila(cvss, k, 1, "Complejidad (AC):", combo("Baja (L)", "Alta (H)"));
        fila(cvss, k, 2, "Privilegios (PR):", combo("Bajos (L)", "Ninguno (N)", "Altos (H)"));
        fila(cvss, k, 3, "Interacción (UI):", combo("Ninguna (N)", "Requerida (R)"));
        fila(cvss, k, 4, "Alcance (S):", combo("Sin cambio (U)", "Cambiado (C)"));
        fila(cvss, k, 5, "Confidencialidad (C):", combo("Alta (H)", "Baja (L)", "Ninguna (N)"));
        fila(cvss, k, 6, "Integridad (I):", combo("Alta (H)", "Baja (L)", "Ninguna (N)"));
        fila(cvss, k, 7, "Disponibilidad (A):", combo("Ninguna (N)", "Baja (L)", "Alta (H)"));
        JLabel resultado = new JLabel(String.format("Puntaje: %.1f   Severidad: %s", puntaje,
                CalculadoraCvss31.categoria(puntaje)).replace('.', ','));
        resultado.setFont(FUENTE.deriveFont(Font.BOLD, 14f));
        k.gridx = 0; k.gridy = 8; k.gridwidth = 2;
        cvss.add(resultado, k);
        k.gridy = 9;
        cvss.add(new JLabel(vector), k);
        raiz.add(cvss, BorderLayout.CENTER);

        JPanel botones = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        botones.add(new JButton("Calcular CVSS"));
        botones.add(new JButton("Guardar"));
        botones.add(new JButton("Cancelar"));
        raiz.add(botones, BorderLayout.SOUTH);
        d.setContentPane(raiz);
        return d;
    }

    /*--------------------------------------------------
     * CU06: cambio de estado con comentario obligatorio.
     *--------------------------------------------------*/
    private static Window ventanaCambioEstado() {
        JDialog d = new JDialog((Frame) null, "Cambiar estado - hallazgo 4");
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(new EmptyBorder(12, 14, 10, 14));
        GridBagConstraints c = base();
        fila(p, c, 0, "Hallazgo:", new JLabel("Panel del NAS con credenciales por defecto"));
        fila(p, c, 1, "Estado actual:", new JLabel("PENDIENTE"));
        fila(p, c, 2, "Responsable:", new JLabel("Soporte de infraestructura (fecha objetivo 02/10/2026)"));
        fila(p, c, 3, "Nuevo estado:", combo("EN_TRATAMIENTO"));
        JTextArea comentario = new JTextArea("Se cambia la clave de fábrica y se limita el acceso al panel.", 3, 34);
        comentario.setLineWrap(true);
        comentario.setWrapStyleWord(true);
        fila(p, c, 4, "Comentario:", new JScrollPane(comentario));
        JLabel ayuda = new JLabel("Desde PENDIENTE solo se puede iniciar el tratamiento. El comentario es obligatorio.");
        ayuda.setForeground(new Color(90, 90, 90));
        c.gridx = 0; c.gridy = 5; c.gridwidth = 2;
        p.add(ayuda, c);
        JPanel botones = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        botones.add(new JButton("Confirmar"));
        botones.add(new JButton("Cancelar"));
        c.gridy = 6;
        p.add(botones, c);
        d.setContentPane(p);
        return d;
    }

    // ----------------- utilidades de armado -----------------

    private static GridBagConstraints base() {
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 4);
        c.anchor = GridBagConstraints.WEST;
        c.fill = GridBagConstraints.HORIZONTAL;
        return c;
    }

    private static void fila(JPanel p, GridBagConstraints c, int y, String etiqueta, JComponent comp) {
        c.gridwidth = 1;
        c.gridx = 0; c.gridy = y; c.weightx = 0;
        p.add(new JLabel(etiqueta), c);
        c.gridx = 1; c.weightx = 1;
        p.add(comp, c);
    }

    private static JTextField campo(String texto, int columnas) {
        return new JTextField(texto, columnas);
    }

    private static JComboBox<String> combo(String... opciones) {
        return new JComboBox<>(opciones);
    }

    /*--------------------------------------------------
     * Muestra la ventana, la captura con Robot (incluye la barra de
     * título de Windows) y la guarda como PNG. Si Robot no puede
     * capturar (sesión bloqueada), pinta el contenido en memoria.
     *--------------------------------------------------*/
    private static void capturar(Window w, String archivo) throws Exception {
        // Fondo blanco detrás de la ventana: así las esquinas redondeadas y la
        // sombra de Windows 11 no muestran lo que haya abierto en el escritorio.
        JWindow fondo = new JWindow();
        SwingUtilities.invokeAndWait(() -> {
            w.pack();
            w.setLocation(60, 60);
            fondo.getContentPane().setBackground(Color.WHITE);
            fondo.setBounds(20, 20, w.getWidth() + 80, w.getHeight() + 80);
            fondo.setAlwaysOnTop(false);
            fondo.setVisible(true);
            fondo.toFront();
        });
        Thread.sleep(400);
        SwingUtilities.invokeAndWait(() -> {
            w.setAlwaysOnTop(true);
            w.setVisible(true);
            w.toFront();
        });
        Thread.sleep(1500);
        SwingUtilities.invokeAndWait(w::toFront);
        Thread.sleep(300);
        BufferedImage img;
        try {
            Robot robot = new Robot();
            Rectangle r = w.getBounds();
            MultiResolutionImage mri = robot.createMultiResolutionScreenCapture(r);
            List<Image> variantes = mri.getResolutionVariants();
            Image mayor = variantes.get(variantes.size() - 1);
            img = new BufferedImage(mayor.getWidth(null), mayor.getHeight(null), BufferedImage.TYPE_INT_RGB);
            img.getGraphics().drawImage(mayor, 0, 0, null);
        } catch (Exception e) {
            img = new BufferedImage(w.getWidth(), w.getHeight(), BufferedImage.TYPE_INT_RGB);
            w.paint(img.getGraphics());
        }
        ImageIO.write(img, "png", new File(archivo));
        System.out.println("Guardado " + archivo + " (" + img.getWidth() + "x" + img.getHeight() + ")");
        SwingUtilities.invokeAndWait(() -> {
            w.dispose();
            fondo.dispose();
        });
    }
}
