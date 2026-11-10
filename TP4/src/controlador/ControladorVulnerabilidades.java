/*
 * Universidad Siglo 21 - Seminario de Práctica de Informática
 * Proyecto: Sistema de seguimiento de vulnerabilidades por proyecto
 * Alumno: Rodríguez, Daniel Sebastián
 * Legajo: VINF016869
 * DNI: 43.731.653
 * Trabajo Práctico 4 [TP4] - Versión final
 */
package controlador;

import java.io.File;
import java.io.IOException;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.format.ResolverStyle;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Locale;

import dao.CatalogoDAO;
import dao.PersistenciaException;
import dao.UsuarioDAO;
import dao.VulnerabilidadDAO;
import modelo.*;
import util.ArchivoTexto;

/*--------------------------------------------------
 * Controlador del patrón MVC. Recibe los pedidos de las ventanas,
 * le pide al modelo que valide las reglas y a los DAO que lean o
 * guarden. Las ventanas no conocen SQL y los DAO no conocen Swing.
 *
 *   vista (Swing) --> controlador --> modelo (reglas del negocio)
 *                          |
 *                          +--------> dao (JDBC) --> MySQL
 *--------------------------------------------------*/
public class ControladorVulnerabilidades {

    /* Las categorías de severidad son siempre seis, por eso un arreglo de tamaño fijo */
    public static final String[] SEVERIDADES = {"Crítica", "Alta", "Media", "Baja", "Ninguna", "Sin evaluar"};
    public static final String TODOS = "Todos";                    // opciones "sin filtro" de los combos
    public static final String TODAS = "Todas";
    public static final String ABIERTOS = "Abiertos (sin CERRADA)";
    public static final int MAX_COMENTARIO = 500;                  // largo de seguimiento.comentario
    private static final int COLUMNAS_CSV = 8;                     // proyecto;activo;titulo;tipo;elemento;fecha;vector;descripcion
    private static final File CARPETA_EXPORTACIONES = new File("exportaciones");
    private static final DateTimeFormatter FECHA = DateTimeFormatter.ofPattern("dd/MM/uuuu");
    private static final DateTimeFormatter FECHA_ESTRICTA = FECHA.withResolverStyle(ResolverStyle.STRICT);
    private static final DateTimeFormatter FECHA_HORA = DateTimeFormatter.ofPattern("dd/MM/uuuu HH:mm");
    private static final Locale ARGENTINA = Locale.of("es", "AR");

    private final UsuarioDAO usuarioDAO;
    private final VulnerabilidadDAO vulnerabilidadDAO;   // tipo de la interfaz, no de la clase MySQL
    private final CatalogoDAO catalogoDAO;
    private Usuario usuario;                             // null = no hay sesión
    private ArrayList<Proyecto> proyectos = new ArrayList<>();
    private ArrayList<Activo> activos = new ArrayList<>();
    private ArrayList<Responsable> responsables = new ArrayList<>();

    public ControladorVulnerabilidades(UsuarioDAO usuarioDAO, VulnerabilidadDAO vulnerabilidadDAO,
                                       CatalogoDAO catalogoDAO) {
        this.usuarioDAO = usuarioDAO;
        this.vulnerabilidadDAO = vulnerabilidadDAO;
        this.catalogoDAO = catalogoDAO;
    }

    /* CU11: mismo mensaje si la cuenta no existe o si la clave no coincide */
    public Usuario iniciarSesion(String nombreAcceso, char[] clave) throws PersistenciaException {
        Usuario encontrado = usuarioDAO.buscarPorAcceso(nombreAcceso.trim());
        if (encontrado == null || !encontrado.verificarClave(new String(clave))) {
            throw new ReglaNegocioException("Usuario o contraseña incorrectos.");
        }
        usuario = encontrado;
        proyectos = catalogoDAO.proyectos(usuario);        // catálogos para combos y nombres de la tabla
        activos = catalogoDAO.activos();
        responsables = catalogoDAO.responsables();
        return usuario;
    }

    public void cerrarSesion() {
        usuario = null;
        proyectos = new ArrayList<>();
        activos = new ArrayList<>();
        responsables = new ArrayList<>();
    }

    /*--------------------------------------------------
     * CU05 con CU13. La base ya devuelve solo lo que el rol puede ver
     * y acá se quitan las filas que no pasan los filtros de la pantalla.
     * Se recorre con un Iterator porque es la forma segura de borrar
     * de un ArrayList mientras se lo recorre (con un for-each, el
     * remove() de la lista lanza ConcurrentModificationException).
     *--------------------------------------------------*/
    public ArrayList<Vulnerabilidad> listar(Proyecto proyecto, String estado, String severidad)
            throws PersistenciaException {
        ArrayList<Vulnerabilidad> lista = vulnerabilidadDAO.listar(usuario);
        Iterator<Vulnerabilidad> it = lista.iterator();
        while (it.hasNext()) {
            Vulnerabilidad v = it.next();
            boolean pasaProyecto = proyecto == null || idProyectoDe(v) == proyecto.getIdProyecto();
            boolean pasaEstado = estado.equals(TODOS)
                    || (estado.equals(ABIERTOS) && v.getEstado() != EstadoVulnerabilidad.CERRADA)
                    || estado.equals(v.getEstado().name());
            boolean pasaSeveridad = severidad.equals(TODAS) || severidad.equals(v.getSeveridad());
            if (!(pasaProyecto && pasaEstado && pasaSeveridad)) {
                it.remove();                                 // se quita del ArrayList sin cortar el recorrido
            }
        }
        return ordenarPorPuntaje(lista);
    }

    /*--------------------------------------------------
     * Ordenamiento por inserción del TP3, de mayor a menor puntaje
     * ("Sin evaluar" al final). El puntaje se calcula en Java y no
     * está en la base, por eso el orden no se le pide al ORDER BY.
     * Complejidad O(n²) en el peor caso, alcanza para pocos hallazgos.
     *--------------------------------------------------*/
    private static ArrayList<Vulnerabilidad> ordenarPorPuntaje(ArrayList<Vulnerabilidad> lista) {
        for (int i = 1; i < lista.size(); i++) {
            Vulnerabilidad actual = lista.get(i);
            int j = i - 1;
            while (j >= 0 && puntajeParaOrden(lista.get(j)) < puntajeParaOrden(actual)) {
                lista.set(j + 1, lista.get(j));              // corre el de menor puntaje a la derecha
                j--;
            }
            lista.set(j + 1, actual);
        }
        return lista;
    }

    private static double puntajeParaOrden(Vulnerabilidad v) {
        return v.getPuntaje() == null ? -1.0 : v.getPuntaje();
    }

    /* Cuenta cuántos hallazgos hay de cada severidad (una posición del arreglo por categoría) */
    public int[] contarPorSeveridad(ArrayList<Vulnerabilidad> lista) {
        int[] conteo = new int[SEVERIDADES.length];        // Java lo inicializa en ceros
        for (Vulnerabilidad v : lista) {
            for (int i = 0; i < SEVERIDADES.length; i++) {
                if (SEVERIDADES[i].equals(v.getSeveridad())) {
                    conteo[i]++;
                }
            }
        }
        return conteo;
    }

    /* CU03 con CU12: el constructor del modelo valida los datos y la base asigna el número */
    public int registrar(Activo activo, String titulo, String descripcion, String tipo, String elemento,
                         LocalDate fechaDeteccion, String vector) throws PersistenciaException {
        exigirGestion();
        if (activo == null) {
            throw new ReglaNegocioException("Elija el activo afectado.");
        }
        if (fechaDeteccion.isAfter(LocalDate.now())) {
            throw new ReglaNegocioException("La fecha de detección no puede ser futura.");
        }
        Vulnerabilidad nueva = new Vulnerabilidad(0, activo.getIdActivo(), titulo, descripcion, tipo, elemento,
                                                  fechaDeteccion, vector);
        return vulnerabilidadDAO.insertar(nueva);
    }

    /*--------------------------------------------------
     * CU06, y CU04 cuando empieza el tratamiento (la asignación se pide
     * en el mismo cuadro). El modelo valida todo antes de tocar la base
     * y después el DAO guarda estado y seguimiento en una transacción.
     *--------------------------------------------------*/
    public void cambiarEstado(Vulnerabilidad v, EstadoVulnerabilidad nuevo, String comentario,
                              Responsable responsable, LocalDate fechaObjetivo) throws PersistenciaException {
        exigirGestion();
        if (comentario != null && comentario.trim().length() > MAX_COMENTARIO) {
            throw new ReglaNegocioException("El comentario admite hasta " + MAX_COMENTARIO + " caracteres.");
        }
        if (nuevo == EstadoVulnerabilidad.EN_TRATAMIENTO && !v.tieneAsignacion()) {
            v.asignar(responsable == null ? null : responsable.getIdResponsable(), fechaObjetivo);
        }
        EstadoVulnerabilidad anterior = v.cambiarEstado(nuevo, comentario);
        Seguimiento s = new Seguimiento(0, v.getIdVulnerabilidad(), usuario.getIdUsuario(),
                usuario.getNombreAcceso(), LocalDateTime.now().withNano(0), anterior, nuevo, comentario.trim());
        vulnerabilidadDAO.guardarCambioEstado(v, s);
    }

    /* CU07 */
    public ArrayList<Seguimiento> historial(Vulnerabilidad v) throws PersistenciaException {
        return vulnerabilidadDAO.historial(v.getIdVulnerabilidad());
    }

    /* CU08: arma el listado como texto y lo guarda en un archivo nuevo de la carpeta exportaciones */
    public File exportar(ArrayList<Vulnerabilidad> lista, String filtros) throws IOException {
        exigirGestion();
        ArrayList<String> lineas = new ArrayList<>();
        lineas.add("Listado de vulnerabilidades | Seguimiento de vulnerabilidades por proyecto");
        lineas.add("Generado el " + LocalDateTime.now().format(FECHA_HORA) + " por " + usuario.getNombreAcceso());
        lineas.add("Filtros " + filtros);
        lineas.add("=".repeat(116));
        lineas.add(String.format("%-4s %-48s %-15s %5s  %-12s %s", "ID", "Título", "Estado", "CVSS", "Severidad",
                                 "Proyecto"));
        for (Vulnerabilidad v : lista) {
            lineas.add(String.format("%-4d %-48s %-15s %5s  %-12s %s", v.getIdVulnerabilidad(), v.getTitulo(),
                                     v.getEstado(), puntaje(v), v.getSeveridad(), nombreProyecto(v)));
        }
        lineas.add("=".repeat(116));
        lineas.add(resumen(lista));
        return ArchivoTexto.guardar(CARPETA_EXPORTACIONES, "listado", lineas);
    }

    public ArrayList<String> leerArchivo(File archivo) throws IOException {
        return ArchivoTexto.leerLineas(archivo);
    }

    /*--------------------------------------------------
     * Carga de hallazgos desde la planilla del área guardada como CSV
     * (UTF-8, separador ";" y la primera fila con los títulos). Cada
     * fila se parte en un arreglo de 8 campos y pasa por registrar(),
     * así tiene las mismas validaciones que el alta manual. Una fila
     * con errores se informa y no frena a las demás. Si se cae la base
     * la carga se corta ahí, pero el informe dice qué filas quedaron
     * guardadas (así no se duplican al repetir la importación).
     *--------------------------------------------------*/
    public ArrayList<String> importar(File archivo) throws IOException {
        exigirGestion();
        ArrayList<String> lineas = ArchivoTexto.leerLineas(archivo);
        ArrayList<String> informe = new ArrayList<>();
        int filas = 0;
        int registradas = 0;
        for (int n = 1; n < lineas.size(); n++) {                  // la posición 0 son los títulos
            if (lineas.get(n).replace(";", "").isBlank()) {
                continue;                                           // fila vacía (o solo separadores) de la planilla
            }
            filas++;
            String[] campos = lineas.get(n).split(";", -1);         // -1 conserva los campos vacíos del final
            String fila = "Fila " + (n + 1) + ". ";                 // número de fila como lo muestra la planilla
            try {
                if (campos.length != COLUMNAS_CSV) {
                    throw new ReglaNegocioException("Tiene " + campos.length + " columnas y se esperan "
                                                    + COLUMNAS_CSV + ".");
                }
                Activo activo = buscarActivo(campo(campos[0]), campo(campos[1]));
                LocalDate fecha = LocalDate.parse(campo(campos[5]), FECHA_ESTRICTA);
                String vector = campo(campos[6]).isEmpty() ? null : campo(campos[6]);   // vacío = "Sin evaluar"
                int numero = registrar(activo, campo(campos[2]), campo(campos[7]), campo(campos[3]),
                                       campo(campos[4]), fecha, vector);
                informe.add(fila + "Registrada como hallazgo " + numero + ".");
                registradas++;
            } catch (ReglaNegocioException e) {
                informe.add(fila + "Rechazada. " + e.getMessage());
            } catch (DateTimeParseException e) {
                informe.add(fila + "Rechazada. La fecha va como dd/mm/aaaa y tiene que existir.");
            } catch (IllegalArgumentException e) {                  // vector CVSS mal escrito
                informe.add(fila + "Rechazada. Vector CVSS inválido (" + e.getMessage() + ").");
            } catch (PersistenciaException e) {                     // se cayó la base, no tiene sentido seguir
                informe.add(fila + "No se guardó. " + e.getMessage() + " La carga se detuvo en esta fila.");
                break;
            }
        }
        informe.add(0, registradas + " de " + filas + " filas registradas desde " + archivo.getName() + ".");
        return informe;
    }

    /* Saca los espacios y las comillas que agrega la planilla cuando un texto tiene comillas ("" es una) */
    private static String campo(String valor) {
        String limpio = valor.trim();
        if (limpio.length() >= 2 && limpio.startsWith("\"") && limpio.endsWith("\"")) {
            limpio = limpio.substring(1, limpio.length() - 1).replace("\"\"", "\"").trim();
        }
        return limpio;
    }

    /* Activo de la planilla, buscado por nombre dentro de su proyecto (sin distinguir mayúsculas) */
    private Activo buscarActivo(String nombreProyecto, String nombreActivo) {
        for (Proyecto p : proyectos) {
            if (p.getNombre().equalsIgnoreCase(nombreProyecto)) {
                for (Activo a : activosDe(p)) {
                    if (a.getNombre().equalsIgnoreCase(nombreActivo)) {
                        return a;
                    }
                }
            }
        }
        throw new ReglaNegocioException("No existe el activo " + nombreActivo + " en el proyecto "
                                        + nombreProyecto + ".");
    }

    /* Texto del pie de la ventana y del archivo, a partir del arreglo de conteos */
    public String resumen(ArrayList<Vulnerabilidad> lista) {
        int[] conteo = contarPorSeveridad(lista);
        StringBuilder texto = new StringBuilder(lista.size() + " hallazgos");
        for (int i = 0; i < SEVERIDADES.length; i++) {
            texto.append(" | ").append(SEVERIDADES[i]).append(' ').append(conteo[i]);
        }
        return texto.toString();
    }

    public static String puntaje(Vulnerabilidad v) {
        return v.getPuntaje() == null ? "-" : String.format(ARGENTINA, "%.1f", v.getPuntaje());
    }

    public static String fecha(LocalDate fecha) {
        return fecha == null ? "" : fecha.format(FECHA);
    }

    private void exigirGestion() {
        if (usuario == null || !usuario.puedeGestionar()) {
            throw new ReglaNegocioException("Operación reservada al administrador.");
        }
    }

    /* Nombres para la tabla (búsqueda lineal en los catálogos, que son listas chicas) */
    public String nombreActivo(Vulnerabilidad v) {
        Activo a = activoDe(v);
        return a == null ? "" : a.getNombre();
    }

    public String nombreProyecto(Vulnerabilidad v) {
        int id = idProyectoDe(v);
        for (Proyecto p : proyectos) {
            if (p.getIdProyecto() == id) {
                return p.getNombre();
            }
        }
        return "";
    }

    public String nombreResponsable(Vulnerabilidad v) {
        for (Responsable r : responsables) {
            if (v.getIdResponsable() != null && r.getIdResponsable() == v.getIdResponsable()) {
                return r.getNombre();
            }
        }
        return "Sin asignar";
    }

    private Activo activoDe(Vulnerabilidad v) {
        for (Activo a : activos) {
            if (a.getIdActivo() == v.getIdActivo()) {
                return a;
            }
        }
        return null;
    }

    private int idProyectoDe(Vulnerabilidad v) {
        Activo a = activoDe(v);
        return a == null ? -1 : a.getIdProyecto();
    }

    public ArrayList<Activo> activosDe(Proyecto proyecto) {
        ArrayList<Activo> lista = new ArrayList<>();
        for (Activo a : activos) {
            if (proyecto != null && a.getIdProyecto() == proyecto.getIdProyecto()) {
                lista.add(a);
            }
        }
        return lista;
    }

    /* Se devuelven copias para que la vista no modifique las listas del controlador */
    public Usuario getUsuario()                     { return usuario; }
    public ArrayList<Proyecto> getProyectos()       { return new ArrayList<>(proyectos); }
    public ArrayList<Responsable> getResponsables() { return new ArrayList<>(responsables); }
}
