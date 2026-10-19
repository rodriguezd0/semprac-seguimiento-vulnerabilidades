/*
 * Universidad Siglo 21 - Seminario de Práctica de Informática
 * Proyecto: Sistema de seguimiento de vulnerabilidades por proyecto
 * Alumno: Rodríguez, Daniel Sebastián
 * Legajo: VINF016869
 * DNI: 43.731.653
 * Trabajo Práctico 3 [TP3] - Prototipo de consola
 */
package app;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.format.ResolverStyle;
import java.util.ArrayList;
import java.util.Locale;
import java.util.NoSuchElementException;
import java.util.Scanner;

import modelo.*;

/*--------------------------------------------------
 * Menú de consola del prototipo (clase con el main). Muestra las
 * opciones del rol que inició sesión, lee con Scanner y atrapa
 * los errores de entrada para que el programa no se corte.
 * Uso: java -cp bin app.MenuConsola [-eco]
 * Con -eco repite cada línea leída (sirve cuando la entrada viene
 * de un archivo, así la salida guardada se entiende).
 *--------------------------------------------------*/
public class MenuConsola {

    private static final DateTimeFormatter FECHA =
            DateTimeFormatter.ofPattern("dd/MM/uuuu").withResolverStyle(ResolverStyle.STRICT);  // 31/02 no pasa
    private static final DateTimeFormatter FECHA_HORA = DateTimeFormatter.ofPattern("dd/MM/uuuu HH:mm");
    private static final Locale ARGENTINA = Locale.of("es", "AR");                  // coma decimal
    private static final String LINEA = "=".repeat(88);

    /* Métricas base de CVSS 3.1: un arreglo con los códigos y una matriz con los valores de cada una */
    private static final String[] METRICAS = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"};
    private static final String[] NOMBRES = {"Vector de ataque", "Complejidad del ataque",
            "Privilegios requeridos", "Interacción del usuario", "Alcance", "Confidencialidad",
            "Integridad", "Disponibilidad"};
    private static final String[][] VALORES = {{"N", "A", "L", "P"}, {"L", "H"}, {"N", "L", "H"},
            {"N", "R"}, {"U", "C"}, {"H", "L", "N"}, {"H", "L", "N"}, {"H", "L", "N"}};

    private final Scanner teclado = new Scanner(System.in);
    private final SistemaVulnerabilidades sistema = new SistemaVulnerabilidades();
    private final boolean eco;

    public MenuConsola(boolean eco) {
        this.eco = eco;
    }

    public static void main(String[] args) {
        boolean eco = args.length > 0 && args[0].equals("-eco");
        try {
            new MenuConsola(eco).iniciar();
        } catch (NoSuchElementException e) {
            System.out.println("Se terminó la entrada de datos.");   // el archivo no tenía más líneas
        }
    }

    /* Bucle de inicio de sesión (CU11). SALIR termina el programa */
    private void iniciar() {
        System.out.println(LINEA);
        System.out.println("Seguimiento de vulnerabilidades por proyecto | Prototipo de consola TP3");
        System.out.println(LINEA);
        String acceso = leer("Usuario (SALIR para terminar) > ");
        while (!acceso.trim().equalsIgnoreCase("SALIR")) {
            String clave = leerClave("Contraseña > ");
            try {
                Usuario usuario = sistema.iniciarSesion(acceso, clave);
                System.out.println("Sesión iniciada. " + usuario.getNombreCompleto() + " (" + usuario.getRol() + ")");
                menu(usuario);
            } catch (ReglaNegocioException e) {
                System.out.println("ACCESO DENEGADO. " + e.getMessage());
            }
            System.out.println();
            acceso = leer("Usuario (SALIR para terminar) > ");
        }
        System.out.println("Programa terminado.");
    }

    /*--------------------------------------------------
     * Menú de selección. Las opciones las da el propio usuario con
     * opcionesMenu() (polimorfismo), así que el menú no pregunta
     * de qué clase es la cuenta. El cliente recibe tres opciones y
     * no puede elegir las de gestión (4 a 6).
     *--------------------------------------------------*/
    private void menu(Usuario usuario) {
        String[] opciones = usuario.opcionesMenu();
        int opcion;
        do {
            System.out.println();
            System.out.println("Menú " + usuario.getRol().toLowerCase());
            for (int i = 0; i < opciones.length; i++) {
                System.out.println("  " + (i + 1) + ". " + opciones[i]);
            }
            System.out.println("  0. Cerrar sesión");
            opcion = leerOpcion(opciones.length);
            try {
                ejecutar(usuario, opcion);
            } catch (ReglaNegocioException e) {                // regla del negocio violada
                System.out.println("OPERACIÓN RECHAZADA. " + e.getMessage());
            } catch (NumberFormatException e) {                // es subclase de IllegalArgumentException, va antes
                System.out.println("DATO INVÁLIDO. Se esperaba un número.");
            } catch (DateTimeParseException e) {
                System.out.println("DATO INVÁLIDO. La fecha va como dd/mm/aaaa y tiene que existir.");
            } catch (IllegalArgumentException e) {             // por ejemplo, un estado que no existe
                System.out.println("DATO INVÁLIDO. " + e.getMessage());
            }
        } while (opcion != 0);
        System.out.println("Sesión cerrada.");
    }

    private void ejecutar(Usuario usuario, int opcion) {
        switch (opcion) {
            case 1 -> listar(usuario, sistema.listarPara(usuario), "Listado por número");
            case 2 -> buscar(usuario);
            case 3 -> listar(usuario, SistemaVulnerabilidades.ordenarPorPuntaje(sistema.listarPara(usuario)),
                             "Listado ordenado por puntaje CVSS, de mayor a menor");
            case 4 -> registrar(usuario);
            case 5 -> asignar(usuario);
            case 6 -> cambiarEstado(usuario);
            default -> { }                                     // 0 vuelve al inicio de sesión
        }
    }

    /* Lee la opción hasta que sea un número válido (no corta el programa) */
    private int leerOpcion(int maximo) {
        while (true) {
            String texto = leer("Opción > ");
            try {
                int opcion = Integer.parseInt(texto.trim());
                if (opcion >= 0 && opcion <= maximo) {
                    return opcion;
                }
                System.out.println("Opción inexistente, elija un número entre 0 y " + maximo + ".");
            } catch (NumberFormatException e) {
                System.out.println("DATO INVÁLIDO. Escriba el número de la opción.");
            }
        }
    }

    /* CU05: una fila por hallazgo */
    private void listar(Usuario usuario, ArrayList<Vulnerabilidad> lista, String titulo) {
        ArrayList<String> nombres = new ArrayList<>();
        for (Proyecto p : sistema.proyectosDe(usuario)) {
            nombres.add(p.getNombre());
        }
        System.out.println(titulo);
        System.out.println("Proyectos visibles " + String.join(", ", nombres));
        System.out.printf("%-4s %-48s %-15s %5s  %s%n", "Nro", "Título", "Estado", "CVSS", "Severidad");
        for (Vulnerabilidad v : lista) {
            System.out.printf("%-4d %-48s %-15s %5s  %s%n", v.getIdVulnerabilidad(), recortar(v.getTitulo(), 48),
                              v.getEstado(), puntaje(v), v.getSeveridad());
        }
        System.out.println(lista.size() + " vulnerabilidades en el listado.");
    }

    /* CU05 y CU07: detalle e historial de un número (búsqueda binaria en el sistema) */
    private void buscar(Usuario usuario) {
        int numero = Integer.parseInt(leer("Número de vulnerabilidad > ").trim());
        Vulnerabilidad v = sistema.buscarVisible(usuario, numero);
        Responsable r = sistema.buscarResponsable(v.getIdResponsable());
        System.out.println("Vulnerabilidad " + numero + " | " + v.getTitulo());
        System.out.println("  Proyecto " + sistema.proyectoDe(v) + " | Activo " + sistema.buscarActivo(v.getIdActivo()));
        System.out.println("  Tipo " + v.getTipo() + " | Elemento afectado " + v.getElementoAfectado());
        System.out.println("  Descripción " + v.getDescripcion());
        System.out.println("  Detectada el " + v.getFechaDeteccion().format(FECHA) + " | Estado " + v.getEstado()
                           + " | CVSS " + puntajeYSeveridad(v));
        System.out.println("  Responsable " + (r == null ? "sin asignar" : r.getNombre()) + " | Fecha objetivo "
                           + (v.getFechaObjetivo() == null ? "sin definir" : v.getFechaObjetivo().format(FECHA)));
        ArrayList<Seguimiento> historial = sistema.historial(usuario, numero);
        System.out.println("  Historial con " + historial.size() + (historial.size() == 1 ? " cambio" : " cambios"));
        for (Seguimiento s : historial) {
            System.out.println("    " + s.getFechaHora().format(FECHA_HORA) + " | " + s.getEstadoAnterior() + " a "
                               + s.getEstadoNuevo() + " | " + s.getUsuario());
            System.out.println("      " + s.getComentario());
        }
    }

    /* CU03 con la extensión CU12 */
    private void registrar(Usuario usuario) {
        System.out.println("Activos");
        for (Activo a : sistema.getActivos()) {
            System.out.println("  " + a.getIdActivo() + " " + a.getNombre() + " ("
                               + sistema.buscarProyecto(a.getIdProyecto()) + ")");
        }
        int idActivo = Integer.parseInt(leer("Número de activo > ").trim());
        if (sistema.buscarActivo(idActivo) == null) {
            throw new ReglaNegocioException("No existe el activo " + idActivo + ".");   // antes de pedir el resto
        }
        String titulo = leer("Título > ");
        String descripcion = leer("Descripción > ");
        String tipo = leer("Tipo > ");
        String elemento = leer("Elemento afectado > ");
        LocalDate fecha = LocalDate.parse(leer("Fecha de detección (dd/mm/aaaa) > ").trim(), FECHA);
        String vector = null;                                    // null = queda "Sin evaluar"
        if (leer("¿Evaluar con CVSS 3.1 ahora? (S/N) > ").trim().equalsIgnoreCase("S")) {
            vector = leerVectorCvss();
        }
        Vulnerabilidad v = sistema.registrar(usuario, idActivo, titulo, descripcion, tipo, elemento, fecha, vector);
        System.out.println("Vulnerabilidad " + v.getIdVulnerabilidad() + " registrada en estado " + v.getEstado()
                           + " con CVSS " + puntajeYSeveridad(v) + ".");
    }

    /*--------------------------------------------------
     * CU12: pide las ocho métricas recorriendo los arreglos. Si el
     * valor no está entre los permitidos lo vuelve a pedir (do-while).
     *--------------------------------------------------*/
    private String leerVectorCvss() {
        StringBuilder vector = new StringBuilder("CVSS:3.1");
        for (int i = 0; i < METRICAS.length; i++) {
            String opciones = String.join(" ", VALORES[i]);
            String valor;
            boolean valido;
            do {
                valor = leer("  " + METRICAS[i] + " " + NOMBRES[i] + " (" + opciones + ") > ").trim().toUpperCase();
                valido = contiene(VALORES[i], valor);
                if (!valido) {
                    System.out.println("  Valor no válido, las opciones son " + opciones + ".");
                }
            } while (!valido);
            vector.append('/').append(METRICAS[i]).append(':').append(valor);
        }
        return vector.toString();
    }

    /* Búsqueda lineal en un arreglo chico */
    private static boolean contiene(String[] valores, String buscado) {
        for (String valor : valores) {
            if (valor.equals(buscado)) {
                return true;
            }
        }
        return false;
    }

    /* CU04 */
    private void asignar(Usuario usuario) {
        int numero = Integer.parseInt(leer("Número de vulnerabilidad > ").trim());
        sistema.buscarVisible(usuario, numero);                 // si no existe corta acá
        System.out.println("Responsables");
        for (Responsable r : sistema.getResponsables()) {
            System.out.println("  " + r.getIdResponsable() + " " + r.getNombre());
        }
        int idResponsable = Integer.parseInt(leer("Número de responsable > ").trim());
        LocalDate fecha = LocalDate.parse(leer("Fecha objetivo (dd/mm/aaaa) > ").trim(), FECHA);
        sistema.asignar(usuario, numero, idResponsable, fecha);
        System.out.println("Vulnerabilidad " + numero + " asignada a " + sistema.buscarResponsable(idResponsable)
                           + " con fecha objetivo " + fecha.format(FECHA) + ".");
    }

    /* CU06: el cambio queda en el historial */
    private void cambiarEstado(Usuario usuario) {
        int numero = Integer.parseInt(leer("Número de vulnerabilidad > ").trim());
        Vulnerabilidad v = sistema.buscarVisible(usuario, numero);
        System.out.println("Estado actual " + v.getEstado());
        String texto = leer("Estado nuevo (PENDIENTE, EN_TRATAMIENTO o CERRADA) > ").trim().toUpperCase();
        EstadoVulnerabilidad nuevo;
        try {
            nuevo = EstadoVulnerabilidad.valueOf(texto);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("No existe el estado " + texto + ".");   // mensaje más claro
        }
        String comentario = leer("Comentario > ");
        Seguimiento s = sistema.cambiarEstado(usuario, numero, nuevo, comentario);
        System.out.println("Estado actualizado, " + s.getEstadoAnterior() + " pasa a " + s.getEstadoNuevo()
                           + " y el cambio queda en el historial.");
    }

    /* Lectura de una línea. NoSuchElementException si se terminó la entrada */
    private String leer(String mensaje) {
        System.out.print(mensaje);
        String linea = teclado.nextLine();
        if (eco) {
            System.out.println(linea);
        }
        return linea;
    }

    /* La clave no se muestra al escribir (si hay consola) ni en la salida guardada */
    private String leerClave(String mensaje) {
        if (System.console() != null && !eco) {
            return new String(System.console().readPassword(mensaje));
        }
        System.out.print(mensaje);
        String clave = teclado.nextLine();
        if (eco) {
            System.out.println("*".repeat(clave.length()));
        }
        return clave;
    }

    private static String puntaje(Vulnerabilidad v) {
        return v.getPuntaje() == null ? "-" : String.format(ARGENTINA, "%.1f", v.getPuntaje());
    }

    private static String puntajeYSeveridad(Vulnerabilidad v) {
        return v.getPuntaje() == null ? "sin evaluar" : puntaje(v) + " (" + v.getSeveridad() + ")";
    }

    private static String recortar(String texto, int largo) {
        return texto.length() <= largo ? texto : texto.substring(0, largo - 3) + "...";
    }
}
