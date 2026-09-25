/*
 * Universidad Siglo 21 - Seminario de Práctica de Informática
 * Proyecto: Sistema de seguimiento de vulnerabilidades por proyecto
 * Alumno: Rodríguez, Daniel Sebastián
 * Legajo: VINF016869
 * DNI: 43.731.653
 */
package pruebas;

import java.time.LocalDate;
import modelo.CalculadoraCvss31;
import modelo.EstadoVulnerabilidad;
import modelo.ReglaNegocioException;
import modelo.Vulnerabilidad;

/*--------------------------------------------------
 * Casos de prueba del plan de la etapa de pruebas. No usa
 * librerías: cada caso compara lo obtenido con lo esperado e
 * imprime PASA o FALLA.
 *   CP01: caja negra, valores límite de categoria()
 *   CP02: caja negra, puntajes contra ejemplos publicados por FIRST
 *   CP03: caja blanca, caminos básicos de validarCambioEstado()
 *--------------------------------------------------*/
public class PruebasTP2 {

    private static int ejecutados = 0;
    private static int aprobados = 0;

    public static void main(String[] args) {
        System.out.println("Java " + System.getProperty("java.version"));
        cp01ValoresLimite();
        cp02EjemplosFirst();
        cp03CajaBlanca();
        System.out.printf("%nRESUMEN: %d casos, %d aprobados, %d fallidos%n",
                ejecutados, aprobados, ejecutados - aprobados);
    }

    /* CP01: un valor a cada lado de cada frontera de severidad. */
    private static void cp01ValoresLimite() {
        System.out.println("\n== CP01 Caja negra: CalculadoraCvss31.categoria() ==");
        Double[] entradas  = {null, -0.1, 0.0, 0.1, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0, 10.0, 10.1};
        String[] esperados = {"Sin evaluar", "Rechazo", "Ninguna", "Baja", "Baja", "Media", "Media",
                              "Alta", "Alta", "Crítica", "Crítica", "Rechazo"};
        for (int k = 0; k < entradas.length; k++) {
            String obtenido;
            try {
                obtenido = CalculadoraCvss31.categoria(entradas[k]);
            } catch (IllegalArgumentException e) {
                obtenido = "Rechazo";                  // puntaje fuera de 0,0 a 10,0
            }
            verificar("categoria(" + entradas[k] + ")", esperados[k], obtenido);
        }
    }

    /* CP02: tres vectores de los ejemplos oficiales de CVSS 3.1. */
    private static void cp02EjemplosFirst() {
        System.out.println("\n== CP02 Caja negra: calcularPuntaje() contra FIRST ==");
        String[][] casos = {
            {"CVE-2013-1937 (XSS en phpMyAdmin)", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "6.1"},
            {"CVE-2014-0160 (Heartbleed)",        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "7.5"},
            {"CVE-2014-6271 (Shellshock)",        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "9.8"},
        };
        for (String[] c : casos) {
            double puntaje = CalculadoraCvss31.calcularPuntaje(c[1]);
            verificar(c[0], c[2], String.valueOf(puntaje));
        }
    }

    /* CP03: un caso por cada camino independiente (V(G) = 4). */
    private static void cp03CajaBlanca() {
        System.out.println("\n== CP03 Caja blanca: Vulnerabilidad.validarCambioEstado() ==");
        LocalDate deteccion = LocalDate.of(2026, 9, 1);

        Vulnerabilidad v1 = new Vulnerabilidad(1, "Prueba", deteccion);        // PENDIENTE
        camino("C1 PENDIENTE a CERRADA", v1, EstadoVulnerabilidad.CERRADA, "x", "Rechazo");

        Vulnerabilidad v2 = new Vulnerabilidad(2, "Prueba", deteccion);
        camino("C2 inicio sin asignación", v2, EstadoVulnerabilidad.EN_TRATAMIENTO, "x", "Rechazo");

        Vulnerabilidad v3 = new Vulnerabilidad(3, "Prueba", deteccion);
        v3.asignar(2, LocalDate.of(2026, 9, 30));
        camino("C3 comentario vacío", v3, EstadoVulnerabilidad.EN_TRATAMIENTO, "   ", "Rechazo");

        Vulnerabilidad v4 = new Vulnerabilidad(4, "Prueba", deteccion);
        v4.asignar(2, LocalDate.of(2026, 9, 30));
        camino("C4 cambio válido", v4, EstadoVulnerabilidad.EN_TRATAMIENTO, "Se asigna a soporte",
               "EN_TRATAMIENTO");
    }

    private static void camino(String nombre, Vulnerabilidad v, EstadoVulnerabilidad nuevo,
                               String comentario, String esperado) {
        String obtenido;
        try {
            v.cambiarEstado(nuevo, comentario);
            obtenido = v.getEstado().name();
        } catch (ReglaNegocioException e) {
            obtenido = "Rechazo";
            System.out.println("   mensaje: " + e.getMessage());
        }
        verificar(nombre, esperado, obtenido);
    }

    private static void verificar(String caso, String esperado, String obtenido) {
        ejecutados++;
        boolean pasa = esperado.equals(obtenido);
        if (pasa) {
            aprobados++;
        }
        System.out.printf("%-5s %-38s esperado=%-14s obtenido=%s%n",
                pasa ? "PASA" : "FALLA", caso, esperado, obtenido);
    }
}
