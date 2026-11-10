/*
 * Universidad Siglo 21 - Seminario de Práctica de Informática
 * Proyecto: Sistema de seguimiento de vulnerabilidades por proyecto
 * Alumno: Rodríguez, Daniel Sebastián
 * Legajo: VINF016869
 * DNI: 43.731.653
 */
package modelo;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/*--------------------------------------------------
 * Cuenta del sistema. Es abstracta porque no existe un usuario
 * "genérico": toda cuenta es Administrador o Cliente (igual que la
 * columna rol de la tabla usuario). Lo común (datos y verificación
 * de la clave) está acá y lo que cambia según el rol lo resuelve
 * cada subclase con los métodos abstractos (polimorfismo).
 *--------------------------------------------------*/
public abstract class Usuario {

    private final int idUsuario;
    private final String nombreAcceso;
    private final String nombreCompleto;
    private final String claveHash;      // SHA-256 de (sal + clave), en hexadecimal
    private final String sal;            // distinta para cada cuenta
    private final boolean activo;

    protected Usuario(int idUsuario, String nombreAcceso, String nombreCompleto,
                      String claveHash, String sal, boolean activo) {
        this.idUsuario = idUsuario;
        this.nombreAcceso = nombreAcceso;
        this.nombreCompleto = nombreCompleto;
        this.claveHash = claveHash;
        this.sal = sal;
        this.activo = activo;
    }

    /*--------------------------------------------------
     * CU11: calcula el hash de (sal + clave ingresada) y lo compara
     * con el guardado. La clave en texto plano nunca se guarda.
     *--------------------------------------------------*/
    public boolean verificarClave(String clave) {
        if (!activo || clave == null) {
            return false;                          // cuenta inactiva o clave vacía
        }
        return claveHash.equals(sha256(sal + clave));
    }

    private static String sha256(String texto) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(texto.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);   // 64 caracteres hexadecimales
        } catch (NoSuchAlgorithmException e) {
            // Toda JVM trae SHA-256, así que no debería pasar nunca
            throw new IllegalStateException("SHA-256 no disponible en esta JVM", e);
        }
    }

    /* Métodos abstractos: cada subclase responde distinto al mismo mensaje */
    public abstract boolean puedeGestionar();      // true solo para el administrador
    public abstract String[] opcionesMenu();       // botones que ve cada rol
    public abstract String getRol();               // mismo texto que la columna rol

    public int getIdUsuario()         { return idUsuario; }
    public String getNombreAcceso()   { return nombreAcceso; }
    public String getNombreCompleto() { return nombreCompleto; }
    public boolean isActivo()         { return activo; }
}
