/*
 * Universidad Siglo 21 - Seminario de Práctica de Informática
 * Proyecto: Sistema de seguimiento de vulnerabilidades por proyecto
 * Alumno: Rodríguez, Daniel Sebastián
 * Legajo: VINF016869
 * DNI: 43.731.653
 */
package modelo;

import java.util.HashMap;
import java.util.Map;

/*--------------------------------------------------
 * Cálculo de la puntuación base de CVSS 3.1 según la
 * especificación de FIRST (2019), sección 7.1 y apéndice A
 * (función Roundup). Recibe las ocho métricas base y devuelve
 * el puntaje con un decimal y su categoría de severidad.
 *--------------------------------------------------*/
public final class CalculadoraCvss31 {

    private CalculadoraCvss31() { }   // clase utilitaria, no se instancia

    /*--------------------------------------------------
     * Calcula el puntaje base a partir de un vector del tipo
     * CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
     *--------------------------------------------------*/
    public static double calcularPuntaje(String vector) {
        double base = puntajeSinRedondear(vector);
        return base <= 0 ? 0.0 : redondearArriba(base);
    }

    /*--------------------------------------------------
     * Valor base antes del Roundup (fórmula de la sección 7.1).
     *--------------------------------------------------*/
    private static double puntajeSinRedondear(String vector) {
        Map<String, String> m = parsearVector(vector);   // AV -> N, AC -> L, ...
        boolean alcanceCambia = m.get("S").equals("C");  // S:C = alcance cambiado

        // Pesos de explotabilidad (tabla 16 de la especificación)
        double av = peso(m.get("AV"), "N", 0.85, "A", 0.62, "L", 0.55, "P", 0.20);
        double ac = peso(m.get("AC"), "L", 0.77, "H", 0.44);
        double pr = alcanceCambia
                ? peso(m.get("PR"), "N", 0.85, "L", 0.68, "H", 0.50)   // PR cambia si S:C
                : peso(m.get("PR"), "N", 0.85, "L", 0.62, "H", 0.27);
        double ui = peso(m.get("UI"), "N", 0.85, "R", 0.62);

        // Pesos de impacto: H = 0.56, L = 0.22, N = 0
        double c = peso(m.get("C"), "H", 0.56, "L", 0.22, "N", 0.0);
        double i = peso(m.get("I"), "H", 0.56, "L", 0.22, "N", 0.0);
        double a = peso(m.get("A"), "H", 0.56, "L", 0.22, "N", 0.0);

        double iss = 1 - ((1 - c) * (1 - i) * (1 - a));        // Impact Sub Score
        double impacto = alcanceCambia
                ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
                : 6.42 * iss;
        double explotabilidad = 8.22 * av * ac * pr * ui;

        if (impacto <= 0) {
            return 0.0;                                        // sin impacto, puntaje 0
        }
        return alcanceCambia
                ? Math.min(1.08 * (impacto + explotabilidad), 10)
                : Math.min(impacto + explotabilidad, 10);
    }

    /*--------------------------------------------------
     * Roundup de CVSS 3.1 (apéndice A): redondea hacia arriba a un
     * decimal evitando errores de punto flotante.
     *--------------------------------------------------*/
    public static double redondearArriba(double valor) {
        long entero = Math.round(valor * 100000);
        if (entero % 10000 == 0) {
            return entero / 100000.0;
        }
        return (Math.floor(entero / 10000.0) + 1) / 10.0;
    }

    /*--------------------------------------------------
     * Categoría de severidad (tabla 14 de la especificación).
     * null significa que el hallazgo todavía no fue evaluado.
     *--------------------------------------------------*/
    public static String categoria(Double puntaje) {
        if (puntaje == null) {
            return "Sin evaluar";
        }
        if (puntaje < 0.0 || puntaje > 10.0) {
            throw new IllegalArgumentException("Puntaje fuera de rango: " + puntaje);
        }
        if (puntaje == 0.0) return "Ninguna";
        if (puntaje < 4.0)  return "Baja";
        if (puntaje < 7.0)  return "Media";
        if (puntaje < 9.0)  return "Alta";
        return "Crítica";
    }

    /*--------------------------------------------------
     * Separa el vector en pares métrica/valor y controla que estén
     * las ocho métricas base (si falta alguna se rechaza el cálculo).
     *--------------------------------------------------*/
    private static Map<String, String> parsearVector(String vector) {
        if (vector == null || !vector.startsWith("CVSS:3.1/")) {
            throw new IllegalArgumentException("El vector debe empezar con CVSS:3.1/");
        }
        Map<String, String> metricas = new HashMap<>();
        for (String par : vector.substring(9).split("/")) {
            String[] partes = par.split(":");
            if (partes.length != 2) {
                throw new IllegalArgumentException("Métrica mal formada: " + par);
            }
            metricas.put(partes[0], partes[1]);
        }
        for (String clave : new String[] {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}) {
            if (!metricas.containsKey(clave)) {
                throw new IllegalArgumentException("Falta la métrica " + clave);
            }
        }
        return metricas;
    }

    /*--------------------------------------------------
     * Busca el peso numérico de un valor de métrica. Recibe pares
     * (valor, peso) y lanza excepción si el valor no es válido.
     *--------------------------------------------------*/
    private static double peso(String valor, Object... pares) {
        for (int k = 0; k < pares.length; k += 2) {
            if (pares[k].equals(valor)) {
                return (Double) pares[k + 1];
            }
        }
        throw new IllegalArgumentException("Valor de métrica inválido: " + valor);
    }
}
