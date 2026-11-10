/*
 * Universidad Siglo 21 - Seminario de Práctica de Informática
 * Proyecto: Sistema de seguimiento de vulnerabilidades por proyecto
 * Alumno: Rodríguez, Daniel Sebastián
 * Legajo: VINF016869
 * DNI: 43.731.653
 * Trabajo Práctico 4 [TP4] - Programa auxiliar de pruebas (no forma parte del sistema)
 */
package herramientas;

import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Image;
import java.awt.Point;
import java.awt.Robot;
import java.awt.Window;
import java.awt.image.BufferedImage;
import java.awt.image.MultiResolutionImage;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.text.JTextComponent;

import app.Aplicacion;
import controlador.ControladorVulnerabilidades;
import dao.CatalogoDAO;
import dao.ConexionBD;
import dao.PersistenciaException;
import dao.UsuarioDAO;
import dao.VulnerabilidadDAO;
import dao.VulnerabilidadDAOMySQL;
import modelo.CalculadoraCvss31;
import modelo.EstadoVulnerabilidad;
import modelo.Seguimiento;
import modelo.Usuario;
import modelo.Vulnerabilidad;
import vista.VentanaLogin;

/*--------------------------------------------------
 * Recorre las ventanas reales del sistema como lo haría un usuario
 * (escribe en los campos y pulsa los botones por su nombre interno),
 * guarda una captura de cada pantalla con java.awt.Robot y verifica
 * en la base lo que quedó guardado. Al final fuerza un error en el
 * INSERT del seguimiento para comprobar el rollback (RNF03).
 * Necesita la base recién cargada con los scripts 01 y 02.
 * Uso: java -cp "bin;lib/mysql-connector-j-8.4.0.jar" herramientas.PruebasTP4 [sin-servidor]
 *--------------------------------------------------*/
public final class PruebasTP4 {

    private static final File CAPTURAS = new File("capturas");
    private static final File SALIDAS = new File("salidas");
    private static final File PLANILLA = new File("entradas", "planilla_hallazgos.csv");
    private static final DateTimeFormatter FECHA = DateTimeFormatter.ofPattern("dd/MM/uuuu");
    private static final int PAUSA_MS = 700;
    private static final int LIMITE_MS = 15000;
    private static int verificaciones = 0;
    private static int aprobadas = 0;

    private PruebasTP4() { }

    public static void main(String[] args) {
        int codigo;
        try {
            CAPTURAS.mkdirs();
            SALIDAS.mkdirs();
            SwingUtilities.invokeAndWait(Aplicacion::aplicarAspecto);
            ControladorVulnerabilidades controlador = new ControladorVulnerabilidades(new UsuarioDAO(),
                    new VulnerabilidadDAOMySQL(), new CatalogoDAO());
            System.out.println("Pruebas de la versión final | " + LocalDateTime.now().withNano(0).format(
                    DateTimeFormatter.ofPattern("dd/MM/uuuu HH:mm:ss")));
            if (args.length > 0 && args[0].equals("sin-servidor")) {
                sinServidor(controlador);
            } else {
                sesionAdministrador(controlador);
                sesionCliente();
                pruebaRollback();
            }
            System.out.println("RESUMEN " + verificaciones + " verificaciones, " + aprobadas + " aprobadas, "
                               + (verificaciones - aprobadas) + " fallidas");
            codigo = verificaciones == aprobadas ? 0 : 1;
        } catch (Exception e) {
            System.out.println("La prueba se interrumpió por un error inesperado");
            e.printStackTrace(System.out);
            codigo = 2;
        }
        System.exit(codigo);                          // cierra también las ventanas que hayan quedado abiertas
    }

    /* CU11, CU05, CU03 con CU12, CU06 con CU04, CU07, CU08 y la carga desde la planilla */
    private static void sesionAdministrador(ControladorVulnerabilidades controlador) throws Exception {
        System.out.println("Sesión del administrador");
        enEdt(() -> new VentanaLogin(controlador).mostrar());
        JFrame login = esperarVentana("Iniciar sesión - Vulnerabilidades");
        escribir(login, "txtUsuario", "dsrodriguez");
        escribir(login, "txtClave", "Admin.2026");
        capturar(login, "cap_01_login.png");
        clic(login, "btnIngresar");
        JFrame principal = esperarVentana("Seguimiento de vulnerabilidades - dsrodriguez (ADMINISTRADOR)");
        verificar("CP05 | filas que ve el administrador al ingresar", "6", String.valueOf(filas(principal)));

        // CU03 con CU12: alta desde la ventana con las ocho métricas (mismo vector que Shellshock, 9,8)
        clicDiferido(principal, "Nuevo hallazgo");
        JDialog registro = esperarDialogo("Registrar vulnerabilidad");
        elegir(registro, "cmbProyecto", "Infraestructura de oficina");
        elegir(registro, "cmbActivo", "Firewall perimetral");
        escribir(registro, "txtTitulo", "Administración del firewall expuesta a Internet");
        escribir(registro, "txtTipo", "Configuración insegura");
        escribir(registro, "txtElemento", "Puerto 8443/TCP");
        escribir(registro, "txtFecha", LocalDate.now().format(FECHA));
        escribir(registro, "txtDescripcion", "La interfaz de administración responde desde fuera de la red interna.");
        String[] metricas = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"};
        String[] valores = {"Red (N)", "Baja (L)", "Ninguno (N)", "Ninguna (N)", "Sin cambio (U)", "Alta (H)",
                            "Alta (H)", "Alta (H)"};
        for (int i = 0; i < metricas.length; i++) {
            elegir(registro, "cvss" + metricas[i], valores[i]);
        }
        capturar(registro, "cap_03_registro_cvss.png");
        clicDiferido(registro, "btnGuardar");
        aceptar(esperarDialogo("Registro guardado"));
        esperarCierre(registro);
        verificar("CP07 | hallazgo 7 guardado en la base (estado y puntaje)", "PENDIENTE 9.8",
                  consulta("SELECT estado FROM vulnerabilidad WHERE id_vulnerabilidad = 7") + " " + puntajeEnBase(7));
        verificar("CP07 | el hallazgo nuevo aparece en la tabla", "7", String.valueOf(filas(principal)));

        // CU06 con CU04: inicio del tratamiento con responsable y fecha objetivo en el mismo cuadro
        String fechaObjetivo = LocalDate.now().plusDays(14).format(FECHA);
        seleccionar(principal, 4);
        clicDiferido(principal, "Cambiar estado");
        JDialog cambio = esperarDialogo("Cambiar estado - hallazgo 4");
        elegir(cambio, "cmbResponsable", "Soporte de infraestructura");
        escribir(cambio, "txtFechaObjetivo", fechaObjetivo);
        escribir(cambio, "txtComentario", "Soporte cambia la clave de fábrica y limita el acceso al panel.");
        capturar(cambio, "cap_04_cambio_estado.png");
        String seguimientosAntes = consulta("SELECT COUNT(*) FROM seguimiento");
        aceptar(cambio);
        aceptar(esperarDialogo("Cambio de estado guardado"));
        verificar("CP08 | hallazgo 4 en la base (estado, responsable y fecha objetivo)",
                  "EN_TRATAMIENTO 1 " + LocalDate.now().plusDays(14),
                  consulta("SELECT CONCAT(estado, ' ', id_responsable, ' ', fecha_objetivo) FROM vulnerabilidad "
                           + "WHERE id_vulnerabilidad = 4"));
        verificar("CP08 | un seguimiento más, guardado en la misma transacción",
                  String.valueOf(Integer.parseInt(seguimientosAntes) + 1), consulta("SELECT COUNT(*) FROM seguimiento"));

        // CU07: historial leído de la base
        seleccionar(principal, 4);
        clicDiferido(principal, "Historial");
        JDialog historial = esperarDialogo("Historial - hallazgo 4");
        capturar(historial, "cap_05_historial.png");
        aceptar(historial);

        // CU08: exportación a TXT y lectura del archivo desde el disco
        File[] antes = archivosExportados();
        clicDiferido(principal, "Exportar TXT");
        JDialog exportado = esperarDialogo("Listado exportado");
        capturar(exportado, "cap_06_exportacion.png");
        aceptar(exportado);
        File[] despues = archivosExportados();
        verificar("CP09 | archivo nuevo en la carpeta exportaciones", String.valueOf(antes.length + 1),
                  String.valueOf(despues.length));
        File nuevo = masReciente(despues);
        List<String> lineas = Files.readAllLines(nuevo.toPath(), StandardCharsets.UTF_8);
        verificar("CP09 | el archivo tiene las 7 filas del listado más 7 líneas de encabezado y pie", "14",
                  String.valueOf(lineas.size()));
        Files.copy(nuevo.toPath(), new File(SALIDAS, "salida_05_listado_exportado.txt").toPath(),
                   java.nio.file.StandardCopyOption.REPLACE_EXISTING);

        // Carga desde la planilla CSV: tres filas válidas y tres con errores (fecha, activo y vector)
        String hallazgosAntes = consulta("SELECT COUNT(*) FROM vulnerabilidad");
        clicDiferido(principal, "Importar CSV");
        JDialog selector = esperarDialogo("Importar hallazgos desde la planilla (CSV)");
        enEdt(() -> {
            JFileChooser chooser = (JFileChooser) buscarTipo(selector, JFileChooser.class);
            chooser.setSelectedFile(PLANILLA.getAbsoluteFile());
            chooser.approveSelection();                       // equivale a elegir el archivo y pulsar Abrir
        });
        JDialog informe = esperarDialogo("Importación terminada");
        String textoInforme = textoDe(informe, "txtContenido");
        capturar(informe, "cap_07_importacion.png");
        aceptar(informe);
        verificar("CP09 | hallazgos agregados desde la planilla", String.valueOf(Integer.parseInt(hallazgosAntes) + 3),
                  consulta("SELECT COUNT(*) FROM vulnerabilidad"));
        verificar("CP09 | filas rechazadas en el informe", "3",
                  String.valueOf(textoInforme.split("Rechazada", -1).length - 1));
        Files.writeString(new File(SALIDAS, "salida_06_informe_importacion.txt").toPath(), textoInforme + "\n",
                          StandardCharsets.UTF_8);

        // Pantalla principal con todo lo anterior, ordenada por puntaje
        capturar(principal, "cap_02_principal_administrador.png");
        verificar("CP05 | primera fila, la de mayor puntaje", "7", String.valueOf(celda(principal, 0)));
        clicDiferido(principal, "Cerrar sesión");
        esperarCierre(principal);
    }

    /* CP05: el cliente 3 solo ve los hallazgos de sus dos proyectos y no tiene botones de gestión */
    private static void sesionCliente() throws Exception {
        System.out.println("Sesión del cliente ref.expedientes");
        JFrame login = esperarVentana("Iniciar sesión - Vulnerabilidades");
        escribir(login, "txtUsuario", "ref.expedientes");
        escribir(login, "txtClave", "Expedientes.2026");
        clic(login, "btnIngresar");
        JFrame principal = esperarVentana("Seguimiento de vulnerabilidades - ref.expedientes (CLIENTE)");
        StringBuilder ids = new StringBuilder();
        for (int i = 0; i < filas(principal); i++) {
            ids.append(i == 0 ? "" : " ").append(celda(principal, i));
        }
        verificar("CP05 | hallazgos que ve el cliente (sus dos proyectos)", "7 4 2 6 9", ids.toString());
        verificar("CP05 | botón Nuevo hallazgo para el cliente", "no existe",
                  buscar(principal, "Nuevo hallazgo") == null ? "no existe" : "existe");
        capturar(principal, "cap_08_principal_cliente.png");
        enEdt(principal::dispose);
    }

    /*--------------------------------------------------
     * CP08, rollback real. El hallazgo 5 pasa a tratamiento en el
     * modelo, pero el seguimiento lleva un usuario que no existe (99),
     * así el INSERT falla por la clave foránea después del UPDATE.
     * La base tiene que quedar igual que antes.
     *--------------------------------------------------*/
    private static void pruebaRollback() throws Exception {
        System.out.println("Prueba de rollback con un error forzado en el INSERT del seguimiento");
        Usuario admin = new UsuarioDAO().buscarPorAcceso("dsrodriguez");
        VulnerabilidadDAO dao = new VulnerabilidadDAOMySQL();
        Vulnerabilidad v5 = null;
        for (Vulnerabilidad v : dao.listar(admin)) {
            if (v.getIdVulnerabilidad() == 5) {
                v5 = v;
            }
        }
        v5.asignar(1, LocalDate.now().plusDays(7));
        EstadoVulnerabilidad anterior = v5.cambiarEstado(EstadoVulnerabilidad.EN_TRATAMIENTO, "Prueba de rollback");
        Seguimiento conUsuarioInexistente = new Seguimiento(0, 5, 99, "inexistente",
                LocalDateTime.now().withNano(0), anterior, EstadoVulnerabilidad.EN_TRATAMIENTO, "Prueba de rollback");
        String seguimientosAntes = consulta("SELECT COUNT(*) FROM seguimiento");
        try {
            dao.guardarCambioEstado(v5, conUsuarioInexistente);
            verificar("CP08 | el DAO informa el error", "PersistenciaException", "sin excepción");
        } catch (PersistenciaException e) {
            SQLException causa = (SQLException) e.getCause();
            System.out.println("  mensaje para el usuario | " + e.getMessage());
            System.out.println("  causa | " + causa.getClass().getSimpleName() + ", código de error "
                               + causa.getErrorCode());
            verificar("CP08 | el DAO informa el error", "PersistenciaException", e.getClass().getSimpleName());
        }
        verificar("CP08 | hallazgo 5 sin cambios después del rollback", "PENDIENTE sin responsable",
                  consulta("SELECT CONCAT(estado, IF(id_responsable IS NULL, ' sin responsable', ' con responsable'))"
                           + " FROM vulnerabilidad WHERE id_vulnerabilidad = 5"));
        verificar("CP08 | seguimientos sin cambios después del rollback", seguimientosAntes,
                  consulta("SELECT COUNT(*) FROM seguimiento"));
    }

    /* CP10: con -Dvulnerabilidades.url apuntando a un puerto sin servidor (CU11, flujo alternativo 2a) */
    private static void sinServidor(ControladorVulnerabilidades controlador) throws Exception {
        System.out.println("Inicio de sesión sin servidor de base de datos");
        enEdt(() -> new VentanaLogin(controlador).mostrar());
        JFrame login = esperarVentana("Iniciar sesión - Vulnerabilidades");
        escribir(login, "txtUsuario", "dsrodriguez");
        escribir(login, "txtClave", "Admin.2026");
        clic(login, "btnIngresar");
        pausa();
        String mensaje = textoEtiqueta(login);
        System.out.println("  mensaje de la ventana | " + mensaje);
        verificar("CP10 | la ventana de acceso informa el error", "No se pudo conectar",
                  mensaje.contains("No se pudo conectar") ? "No se pudo conectar" : mensaje);
        AtomicReference<Integer> largoClave = new AtomicReference<>();
        enEdt(() -> largoClave.set(((JPasswordField) buscar(login, "txtClave")).getPassword().length));
        verificar("CP10 | la contraseña se borra aunque falle (finally)", "0", String.valueOf(largoClave.get()));
        capturar(login, "cap_09_login_sin_servidor.png");
        enEdt(login::dispose);
    }

    /* ------------------------------ acciones sobre las ventanas ------------------------------ */

    private static void escribir(Container ventana, String nombre, String valor) throws Exception {
        enEdt(() -> ((JTextComponent) buscar(ventana, nombre)).setText(valor));
    }

    private static void elegir(Container ventana, String nombre, String opcion) throws Exception {
        enEdt(() -> {
            JComboBox<?> combo = (JComboBox<?>) buscar(ventana, nombre);
            for (int i = 0; i < combo.getItemCount(); i++) {
                if (String.valueOf(combo.getItemAt(i)).equals(opcion)) {
                    combo.setSelectedIndex(i);
                    return;
                }
            }
            throw new IllegalStateException("No está la opción " + opcion + " en " + nombre);
        });
    }

    private static void clic(Container ventana, String nombre) throws Exception {
        enEdt(() -> ((AbstractButton) buscar(ventana, nombre)).doClick());
    }

    /* Para botones que abren un cuadro modal: se encola el clic y no se espera a que termine */
    private static void clicDiferido(Container ventana, String nombre) {
        SwingUtilities.invokeLater(() -> ((AbstractButton) buscar(ventana, nombre)).doClick());
    }

    /* Pulsa el botón Aceptar (u OK) de un cuadro de JOptionPane */
    private static void aceptar(JDialog dialogo) throws Exception {
        pausa();
        SwingUtilities.invokeLater(() -> botonConTexto(dialogo, "Aceptar", "OK").doClick());
        esperarCierre(dialogo);
    }

    private static void seleccionar(JFrame principal, int id) throws Exception {
        enEdt(() -> {
            JTable tabla = (JTable) buscar(principal, "tabla");
            for (int i = 0; i < tabla.getRowCount(); i++) {
                if (Integer.valueOf(id).equals(tabla.getValueAt(i, 0))) {
                    tabla.setRowSelectionInterval(i, i);
                    return;
                }
            }
            throw new IllegalStateException("No está el hallazgo " + id + " en la tabla");
        });
    }

    /* ------------------------------ lectura de las ventanas ------------------------------ */

    private static Component buscar(Container contenedor, String nombre) {
        for (Component c : contenedor.getComponents()) {
            if (nombre.equals(c.getName())) {
                return c;
            }
            if (c instanceof Container hijo) {
                Component encontrado = buscar(hijo, nombre);
                if (encontrado != null) {
                    return encontrado;
                }
            }
        }
        return null;
    }

    private static Component buscarTipo(Container contenedor, Class<?> tipo) {
        for (Component c : contenedor.getComponents()) {
            if (tipo.isInstance(c)) {
                return c;
            }
            if (c instanceof Container hijo) {
                Component encontrado = buscarTipo(hijo, tipo);
                if (encontrado != null) {
                    return encontrado;
                }
            }
        }
        return null;
    }

    private static JButton botonConTexto(Container contenedor, String... textos) {
        for (Component c : contenedor.getComponents()) {
            if (c instanceof JButton b && List.of(textos).contains(b.getText())) {
                return b;
            }
            if (c instanceof Container hijo) {
                JButton encontrado = botonConTexto(hijo, textos);
                if (encontrado != null) {
                    return encontrado;
                }
            }
        }
        return null;
    }

    private static int filas(JFrame principal) throws Exception {
        AtomicReference<Integer> valor = new AtomicReference<>();
        enEdt(() -> valor.set(((JTable) buscar(principal, "tabla")).getRowCount()));
        return valor.get();
    }

    private static Object celda(JFrame principal, int fila) throws Exception {
        AtomicReference<Object> valor = new AtomicReference<>();
        enEdt(() -> valor.set(((JTable) buscar(principal, "tabla")).getValueAt(fila, 0)));
        return valor.get();
    }

    private static String textoDe(Container ventana, String nombre) throws Exception {
        AtomicReference<String> valor = new AtomicReference<>("");
        enEdt(() -> valor.set(((JTextComponent) buscar(ventana, nombre)).getText()));
        return valor.get();
    }

    /* Texto de la etiqueta de mensajes de la ventana de acceso (la que tiene HTML) */
    private static String textoEtiqueta(Container ventana) throws Exception {
        AtomicReference<String> valor = new AtomicReference<>("");
        enEdt(() -> {
            for (Component c : ((JFrame) ventana).getContentPane().getComponents()) {
                if (c instanceof JLabel l && l.getText().startsWith("<html>")) {
                    valor.set(l.getText().replaceAll("<[^>]+>", ""));
                }
            }
        });
        return valor.get();
    }

    private static File[] archivosExportados() {
        File[] archivos = new File("exportaciones").listFiles((carpeta, nombre) -> nombre.endsWith(".txt"));
        return archivos == null ? new File[0] : archivos;
    }

    private static File masReciente(File[] archivos) {
        File elegido = archivos[0];
        for (File f : archivos) {
            if (f.lastModified() > elegido.lastModified()) {
                elegido = f;
            }
        }
        return elegido;
    }

    /* ------------------------------ espera de ventanas ------------------------------ */

    private static JFrame esperarVentana(String titulo) throws Exception {
        return (JFrame) esperar(titulo, JFrame.class);
    }

    private static JDialog esperarDialogo(String titulo) throws Exception {
        return (JDialog) esperar(titulo, JDialog.class);
    }

    private static Window esperar(String titulo, Class<? extends Window> tipo) throws Exception {
        long limite = System.currentTimeMillis() + LIMITE_MS;
        while (System.currentTimeMillis() < limite) {
            AtomicReference<Window> encontrada = new AtomicReference<>();
            enEdt(() -> {
                for (Window w : Window.getWindows()) {
                    String t = w instanceof JFrame f ? f.getTitle() : w instanceof JDialog d ? d.getTitle() : "";
                    if (tipo.isInstance(w) && w.isShowing() && titulo.equals(t)) {
                        encontrada.set(w);
                    }
                }
            });
            if (encontrada.get() != null) {
                pausa();
                return encontrada.get();
            }
            Thread.sleep(150);
        }
        throw new IllegalStateException("No apareció la ventana " + titulo);
    }

    private static void esperarCierre(Window ventana) throws Exception {
        long limite = System.currentTimeMillis() + LIMITE_MS;
        while (ventana.isShowing() && System.currentTimeMillis() < limite) {
            Thread.sleep(100);
        }
        pausa();
    }

    /*--------------------------------------------------
     * Igual que en los prototipos del TP2: fondo blanco detrás de la
     * ventana (para que la sombra de Windows no muestre el escritorio),
     * la ventana al frente y captura de su rectángulo con la barra de
     * título. Si otra ventana quedó encima, se repite.
     *--------------------------------------------------*/
    private static void capturar(Window ventana, String archivo) throws Exception {
        JWindow fondo = new JWindow();
        boolean esDialogo = ventana instanceof JDialog;    // el diálogo tapa además a su ventana dueña
        enEdt(() -> {
            ventana.setLocation(60, 60);
            fondo.getContentPane().setBackground(Color.WHITE);
            fondo.setBounds(20, 20, ventana.getWidth() + 80, ventana.getHeight() + 80);
            fondo.setAlwaysOnTop(esDialogo);
            fondo.setVisible(true);
            fondo.toFront();
            ventana.setAlwaysOnTop(true);
            ventana.toFront();
        });
        Thread.sleep(1200);
        BufferedImage imagen = null;
        for (int intento = 1; intento <= 5 && imagen == null; intento++) {
            enEdt(ventana::toFront);
            Thread.sleep(300);
            BufferedImage candidata = pantalla(ventana);
            if (tapada(ventana, candidata)) {
                System.out.println("  " + archivo + " quedó tapada por otra ventana, se repite (intento " + intento + ")");
                Thread.sleep(1000);
            } else {
                imagen = candidata;
            }
        }
        enEdt(() -> {
            ventana.setAlwaysOnTop(false);
            fondo.dispose();
        });
        if (imagen == null) {
            throw new IllegalStateException("No se pudo capturar " + archivo + " sin otras ventanas encima");
        }
        ImageIO.write(imagen, "png", new File(CAPTURAS, archivo));
        System.out.println("  captura " + archivo + " (" + imagen.getWidth() + " x " + imagen.getHeight() + ")");
    }

    private static BufferedImage pantalla(Window ventana) throws Exception {
        MultiResolutionImage capturas = new Robot().createMultiResolutionScreenCapture(ventana.getBounds());
        List<Image> variantes = capturas.getResolutionVariants();
        Image mayor = variantes.get(variantes.size() - 1);                 // la de más resolución
        BufferedImage imagen = new BufferedImage(mayor.getWidth(null), mayor.getHeight(null),
                                                 BufferedImage.TYPE_INT_RGB);
        imagen.getGraphics().drawImage(mayor, 0, 0, null);
        return imagen;
    }

    /*--------------------------------------------------
     * Compara el contenido de la captura (sin la barra de título) con
     * lo que Swing dibuja en memoria. Si más del 5 % de los puntos no
     * coincide, otra ventana del escritorio quedó encima.
     *--------------------------------------------------*/
    private static boolean tapada(Window ventana, BufferedImage captura) throws Exception {
        AtomicReference<BufferedImage> memoria = new AtomicReference<>();
        AtomicReference<Point> corrimiento = new AtomicReference<>();
        enEdt(() -> {
            JRootPane raiz = ((RootPaneContainer) ventana).getRootPane();
            BufferedImage img = new BufferedImage(raiz.getWidth(), raiz.getHeight(), BufferedImage.TYPE_INT_RGB);
            java.awt.Graphics2D g = img.createGraphics();
            raiz.printAll(g);
            g.dispose();
            memoria.set(img);
            Point r = raiz.getLocationOnScreen();
            Point v = ventana.getLocationOnScreen();
            corrimiento.set(new Point(r.x - v.x, r.y - v.y));
        });
        double escala = (double) captura.getWidth() / ventana.getWidth();
        int distintos = 0;
        int total = 0;
        for (int y = 0; y < memoria.get().getHeight(); y += 3) {
            for (int x = 0; x < memoria.get().getWidth(); x += 3) {
                int cx = (int) ((x + corrimiento.get().x) * escala);
                int cy = (int) ((y + corrimiento.get().y) * escala);
                if (cx < captura.getWidth() && cy < captura.getHeight()) {
                    total++;
                    if (diferencia(memoria.get().getRGB(x, y), captura.getRGB(cx, cy)) > 90) {
                        distintos++;
                    }
                }
            }
        }
        return distintos > total * 0.05;
    }

    private static int diferencia(int a, int b) {
        return Math.abs((a >> 16 & 255) - (b >> 16 & 255)) + Math.abs((a >> 8 & 255) - (b >> 8 & 255))
               + Math.abs((a & 255) - (b & 255));
    }

    /* ------------------------------ utilidades ------------------------------ */

    @FunctionalInterface
    private interface Tarea {
        void ejecutar() throws Exception;
    }

    /* Ejecuta la tarea en el hilo de Swing (EDT) y espera a que termine */
    private static void enEdt(Tarea tarea) throws Exception {
        AtomicReference<Exception> error = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            try {
                tarea.ejecutar();
            } catch (Exception e) {
                error.set(e);
            }
        });
        if (error.get() != null) {
            throw error.get();
        }
    }

    private static void pausa() throws InterruptedException {
        Thread.sleep(PAUSA_MS);
    }

    private static String consulta(String sql) throws Exception {
        try (Connection con = ConexionBD.obtener();
             PreparedStatement ps = con.prepareStatement(sql);
             ResultSet rs = ps.executeQuery()) {
            return rs.next() ? rs.getString(1) : "sin filas";
        }
    }

    private static String puntajeEnBase(int id) throws Exception {
        String vector = consulta("SELECT vector_cvss FROM vulnerabilidad WHERE id_vulnerabilidad = " + id);
        return String.valueOf(CalculadoraCvss31.calcularPuntaje(vector));
    }

    private static void verificar(String caso, String esperado, String obtenido) {
        verificaciones++;
        boolean pasa = esperado.equals(obtenido);
        if (pasa) {
            aprobadas++;
        }
        System.out.println("  " + (pasa ? "PASA " : "FALLA") + " | " + caso + " | esperado " + esperado
                           + " | obtenido " + obtenido);
    }
}
