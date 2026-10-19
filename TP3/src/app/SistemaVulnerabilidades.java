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
import java.time.LocalDateTime;
import java.util.ArrayList;

import modelo.*;

/*--------------------------------------------------
 * Lógica del prototipo con los datos en memoria. Cada entidad
 * vive en un ArrayList (en la versión final esas listas se
 * reemplazan por consultas a MySQL). Los datos iniciales son los
 * mismos del script 02_insercion.sql del TP2.
 *--------------------------------------------------*/
public class SistemaVulnerabilidades {

    private final ArrayList<Usuario> usuarios = new ArrayList<>();
    private final ArrayList<Proyecto> proyectos = new ArrayList<>();
    private final ArrayList<Activo> activos = new ArrayList<>();
    private final ArrayList<Responsable> responsables = new ArrayList<>();
    private final ArrayList<Vulnerabilidad> vulnerabilidades = new ArrayList<>();  // siempre ordenada por número
    private final ArrayList<Seguimiento> seguimientos = new ArrayList<>();

    public SistemaVulnerabilidades() {
        cargarDatosPrueba();
    }

    /*--------------------------------------------------
     * CU11: busca la cuenta y verifica la clave. Si falla da el
     * mismo mensaje exista o no la cuenta (no revela usuarios).
     *--------------------------------------------------*/
    public Usuario iniciarSesion(String nombreAcceso, String clave) throws ReglaNegocioException {
        for (Usuario u : usuarios) {
            if (u.getNombreAcceso().equalsIgnoreCase(nombreAcceso.trim()) && u.verificarClave(clave)) {
                return u;
            }
        }
        throw new ReglaNegocioException("Usuario o contraseña incorrectos.");
    }

    /* CU05 con CU13: el administrador ve todo y el cliente solo sus proyectos */
    public ArrayList<Vulnerabilidad> listarPara(Usuario usuario) {
        ArrayList<Vulnerabilidad> visibles = new ArrayList<>();
        for (Vulnerabilidad v : vulnerabilidades) {
            if (puedeVer(usuario, v)) {
                visibles.add(v);
            }
        }
        return visibles;
    }

    private boolean puedeVer(Usuario usuario, Vulnerabilidad v) {
        if (usuario.puedeGestionar()) {
            return true;                                   // administrador
        }
        Proyecto p = proyectoDe(v);
        return p != null && p.getIdCliente() == usuario.getIdUsuario();
    }

    /*--------------------------------------------------
     * Búsqueda binaria por número. Funciona porque la lista está
     * ordenada por número (cada hallazgo nuevo recibe el número
     * siguiente y se agrega al final). En cada vuelta descarta la
     * mitad de la lista, así que hace O(log n) comparaciones.
     *--------------------------------------------------*/
    public Vulnerabilidad buscarPorNumero(int numero) {
        int izquierda = 0;
        int derecha = vulnerabilidades.size() - 1;
        while (izquierda <= derecha) {
            int medio = (izquierda + derecha) / 2;
            int actual = vulnerabilidades.get(medio).getIdVulnerabilidad();
            if (actual == numero) {
                return vulnerabilidades.get(medio);            // encontrado
            } else if (actual < numero) {
                izquierda = medio + 1;                         // sigue en la mitad derecha
            } else {
                derecha = medio - 1;                           // sigue en la mitad izquierda
            }
        }
        return null;                                           // no existe
    }

    /* Un número ajeno se informa igual que uno inexistente (CU13) */
    public Vulnerabilidad buscarVisible(Usuario usuario, int numero) throws ReglaNegocioException {
        Vulnerabilidad v = buscarPorNumero(numero);
        if (v == null || !puedeVer(usuario, v)) {
            throw new ReglaNegocioException("No hay una vulnerabilidad " + numero + " entre sus proyectos.");
        }
        return v;
    }

    /* CU03 con CU12: el vector puede ser null (queda "Sin evaluar") */
    public Vulnerabilidad registrar(Usuario usuario, int idActivo, String titulo, String descripcion,
                                    String tipo, String elemento, LocalDate fechaDeteccion, String vector)
            throws ReglaNegocioException {
        exigirGestion(usuario);
        if (buscarActivo(idActivo) == null) {
            throw new ReglaNegocioException("No existe el activo " + idActivo + ".");
        }
        if (fechaDeteccion.isAfter(LocalDate.now())) {
            throw new ReglaNegocioException("La fecha de detección no puede ser futura.");
        }
        int numero = vulnerabilidades.isEmpty() ? 1
                : vulnerabilidades.get(vulnerabilidades.size() - 1).getIdVulnerabilidad() + 1;
        Vulnerabilidad nueva = new Vulnerabilidad(numero, idActivo, titulo, descripcion, tipo, elemento,
                                                  fechaDeteccion, vector);
        vulnerabilidades.add(nueva);                           // al final, la lista sigue ordenada
        return nueva;
    }

    /* CU04 */
    public void asignar(Usuario usuario, int numero, int idResponsable, LocalDate fechaObjetivo)
            throws ReglaNegocioException {
        exigirGestion(usuario);
        Vulnerabilidad v = buscarVisible(usuario, numero);
        if (buscarResponsable(idResponsable) == null) {
            throw new ReglaNegocioException("No existe el responsable " + idResponsable + ".");
        }
        v.asignar(idResponsable, fechaObjetivo);               // las reglas las controla el modelo
    }

    /* CU06: el modelo valida y el sistema guarda el seguimiento en el historial */
    public Seguimiento cambiarEstado(Usuario usuario, int numero, EstadoVulnerabilidad nuevo, String comentario)
            throws ReglaNegocioException {
        exigirGestion(usuario);
        Vulnerabilidad v = buscarVisible(usuario, numero);
        EstadoVulnerabilidad anterior = v.cambiarEstado(nuevo, comentario);
        Seguimiento s = new Seguimiento(seguimientos.size() + 1, numero, usuario.getIdUsuario(),
                usuario.getNombreAcceso(), LocalDateTime.now(), anterior, nuevo, comentario.trim());
        seguimientos.add(s);
        return s;
    }

    /* CU07: historial con los mismos permisos que la consulta */
    public ArrayList<Seguimiento> historial(Usuario usuario, int numero) throws ReglaNegocioException {
        buscarVisible(usuario, numero);                        // controla el acceso
        ArrayList<Seguimiento> lista = new ArrayList<>();
        for (Seguimiento s : seguimientos) {
            if (s.getIdVulnerabilidad() == numero) {
                lista.add(s);
            }
        }
        return lista;
    }

    /*--------------------------------------------------
     * Ordenamiento por inserción, de mayor a menor puntaje. Toma
     * cada elemento y lo corre hacia la izquierda mientras el de
     * adelante tenga menos puntaje. Es O(n²) en el peor caso, pero
     * con pocos hallazgos alcanza y es estable (los empates quedan
     * por número). Trabaja sobre una copia y no toca la original.
     *--------------------------------------------------*/
    public static ArrayList<Vulnerabilidad> ordenarPorPuntaje(ArrayList<Vulnerabilidad> origen) {
        ArrayList<Vulnerabilidad> lista = new ArrayList<>(origen);
        for (int i = 1; i < lista.size(); i++) {
            Vulnerabilidad actual = lista.get(i);
            int j = i - 1;
            while (j >= 0 && puntajeParaOrden(lista.get(j)) < puntajeParaOrden(actual)) {
                lista.set(j + 1, lista.get(j));                // corre el mayor un lugar a la derecha
                j--;
            }
            lista.set(j + 1, actual);                          // inserta en su lugar
        }
        return lista;
    }

    private static double puntajeParaOrden(Vulnerabilidad v) {
        Double puntaje = v.getPuntaje();
        return puntaje == null ? -1.0 : puntaje;               // "Sin evaluar" queda al final
    }

    private void exigirGestion(Usuario usuario) throws ReglaNegocioException {
        if (!usuario.puedeGestionar()) {
            throw new ReglaNegocioException("Operación reservada al administrador.");
        }
    }

    /* Búsquedas lineales en los catálogos (son listas chicas) */
    public Activo buscarActivo(int idActivo) {
        for (Activo a : activos) {
            if (a.getIdActivo() == idActivo) {
                return a;
            }
        }
        return null;
    }

    public Responsable buscarResponsable(Integer idResponsable) {
        for (Responsable r : responsables) {
            if (idResponsable != null && r.getIdResponsable() == idResponsable) {
                return r;
            }
        }
        return null;
    }

    public Proyecto buscarProyecto(int idProyecto) {
        for (Proyecto p : proyectos) {
            if (p.getIdProyecto() == idProyecto) {
                return p;
            }
        }
        return null;
    }

    /* El proyecto de un hallazgo se obtiene a través de su activo */
    public Proyecto proyectoDe(Vulnerabilidad v) {
        Activo a = buscarActivo(v.getIdActivo());
        return a == null ? null : buscarProyecto(a.getIdProyecto());
    }

    /* Proyectos que puede ver la cuenta (para el encabezado del listado) */
    public ArrayList<Proyecto> proyectosDe(Usuario usuario) {
        ArrayList<Proyecto> lista = new ArrayList<>();
        for (Proyecto p : proyectos) {
            if (usuario.puedeGestionar() || p.getIdCliente() == usuario.getIdUsuario()) {
                lista.add(p);
            }
        }
        return lista;
    }

    /* Se devuelven copias para que nadie modifique las listas desde afuera */
    public ArrayList<Activo> getActivos()           { return new ArrayList<>(activos); }
    public ArrayList<Responsable> getResponsables() { return new ArrayList<>(responsables); }

    /*--------------------------------------------------
     * Datos de prueba FICTICIOS, los mismos del script 02 del TP2
     * (claves Admin.2026, Web.2026 y Expedientes.2026).
     *--------------------------------------------------*/
    private void cargarDatosPrueba() {
        usuarios.add(new Administrador(1, "dsrodriguez", "Daniel Sebastián Rodríguez",
                "ccf068aaeee4b504339ce3006e5e374986c3e2632dd11a4a27b9084073cb2d54",
                "4de738ee2fd78daabfcc4cc5fb5084f1", true));
        usuarios.add(new Cliente(2, "ref.web", "Referente del portal web",
                "ded88dca84b2ce0fff941cfc62f6da70b9a2571a767460b09d00db8f6bfaa86c",
                "5041f9ce24d6ec8d4388bb75641fba53", true));
        usuarios.add(new Cliente(3, "ref.expedientes", "Referente de gestión de expedientes",
                "bf38850a3b43347d28960739b447e9277114e98c15838c830ce43cfc1074ee24",
                "77a37b66957a42e77efcaa2c7790d4ec", true));

        proyectos.add(new Proyecto(1, "Portal web institucional", "Sitio público y formularios de contacto", 2));
        proyectos.add(new Proyecto(2, "Gestión de expedientes", "Aplicación interna de seguimiento de expedientes", 3));
        proyectos.add(new Proyecto(3, "Infraestructura de oficina", "Red interna, respaldos y equipos compartidos", 3));

        activos.add(new Activo(1, 1, "Servidor web", "Servidor", "Apache que publica el sitio institucional"));
        activos.add(new Activo(2, 1, "Formulario de contacto", "Aplicación", "Formulario público del sitio"));
        activos.add(new Activo(3, 2, "Aplicación de expedientes", "Aplicación", "Módulo web de búsqueda y carga"));
        activos.add(new Activo(4, 2, "Base de datos de expedientes", "Base de datos", "Servidor MySQL de la aplicación"));
        activos.add(new Activo(5, 3, "NAS de respaldos", "Equipo", "Almacenamiento de copias de seguridad"));
        activos.add(new Activo(6, 3, "Firewall perimetral", "Red", "Equipo de borde de la red de oficina"));

        responsables.add(new Responsable(1, "Soporte de infraestructura", "soporte@ejemplo.local"));
        responsables.add(new Responsable(2, "Desarrollo interno", "desarrollo@ejemplo.local"));
        responsables.add(new Responsable(3, "Proveedor de hosting", "mesa@proveedor.ejemplo"));
        responsables.add(new Responsable(4, "Mesa de ayuda", "ayuda@ejemplo.local"));

        vulnerabilidades.add(new Vulnerabilidad(1, 1, 3, "TLS 1.0 y 1.1 habilitados",
                "El servidor acepta versiones de TLS obsoletas.", "Configuración insegura", "Puerto 443/TCP",
                LocalDate.of(2026, 8, 18), LocalDate.of(2026, 9, 15), EstadoVulnerabilidad.CERRADA,
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"));
        vulnerabilidades.add(new Vulnerabilidad(2, 3, 2, "Inyección SQL en la búsqueda de expedientes",
                "El parámetro de búsqueda se concatena en la consulta.", "Inyección",
                "Parámetro q de /expedientes/buscar", LocalDate.of(2026, 9, 2), LocalDate.of(2026, 9, 30),
                EstadoVulnerabilidad.EN_TRATAMIENTO, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"));
        vulnerabilidades.add(new Vulnerabilidad(3, 2, 2, "XSS reflejado en el formulario de contacto",
                "El campo nombre se devuelve sin codificar.", "Cross-site scripting", "Campos nombre y asunto",
                LocalDate.of(2026, 9, 5), LocalDate.of(2026, 10, 5), EstadoVulnerabilidad.PENDIENTE,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"));
        vulnerabilidades.add(new Vulnerabilidad(4, 5, null, "Panel del NAS con credenciales por defecto",
                "La administración acepta la clave de fábrica.", "Autenticación débil",
                "Interfaz web de administración", LocalDate.of(2026, 9, 10), null, EstadoVulnerabilidad.PENDIENTE,
                "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"));
        vulnerabilidades.add(new Vulnerabilidad(5, 1, null, "Divulgación de versión en encabezados HTTP",
                "El encabezado Server informa la versión de Apache.", "Divulgación de información",
                "Encabezado Server", LocalDate.of(2026, 9, 15), null, EstadoVulnerabilidad.PENDIENTE,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"));
        vulnerabilidades.add(new Vulnerabilidad(6, 4, null, "Conexión a la base sin cifrado en la red interna",
                "El servidor MySQL acepta conexiones sin TLS.", "Configuración insegura", "Puerto 3306/TCP",
                LocalDate.of(2026, 9, 21), null, EstadoVulnerabilidad.PENDIENTE, null));

        EstadoVulnerabilidad pen = EstadoVulnerabilidad.PENDIENTE;
        EstadoVulnerabilidad tra = EstadoVulnerabilidad.EN_TRATAMIENTO;
        EstadoVulnerabilidad cer = EstadoVulnerabilidad.CERRADA;
        seguimientos.add(new Seguimiento(1, 1, 1, "dsrodriguez", LocalDateTime.of(2026, 8, 20, 10, 15), pen, tra,
                "Se pide al proveedor deshabilitar TLS 1.0 y 1.1."));
        seguimientos.add(new Seguimiento(2, 1, 1, "dsrodriguez", LocalDateTime.of(2026, 9, 10, 16, 40), tra, cer,
                "Verificado con escaneo, solo responde TLS 1.2 y 1.3."));
        seguimientos.add(new Seguimiento(3, 2, 1, "dsrodriguez", LocalDateTime.of(2026, 9, 3, 9, 30), pen, tra,
                "Desarrollo pasa la búsqueda a consultas parametrizadas."));
        seguimientos.add(new Seguimiento(4, 3, 1, "dsrodriguez", LocalDateTime.of(2026, 9, 7, 11, 0), pen, tra,
                "Se agrega codificación de salida en el formulario."));
        seguimientos.add(new Seguimiento(5, 3, 1, "dsrodriguez", LocalDateTime.of(2026, 9, 12, 15, 20), tra, cer,
                "Probado con carga de prueba en el campo nombre."));
        seguimientos.add(new Seguimiento(6, 3, 1, "dsrodriguez", LocalDateTime.of(2026, 9, 19, 12, 5), cer, pen,
                "Reapertura, el campo asunto sigue sin codificar."));
    }
}
