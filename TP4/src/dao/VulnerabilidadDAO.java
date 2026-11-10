/*
 * Universidad Siglo 21 - Seminario de Práctica de Informática
 * Proyecto: Sistema de seguimiento de vulnerabilidades por proyecto
 * Alumno: Rodríguez, Daniel Sebastián
 * Legajo: VINF016869
 * DNI: 43.731.653
 * Trabajo Práctico 4 [TP4] - Versión final
 */
package dao;

import java.util.ArrayList;

import modelo.Seguimiento;
import modelo.Usuario;
import modelo.Vulnerabilidad;

/*--------------------------------------------------
 * Contrato de la persistencia de hallazgos. El controlador conoce
 * solo esta interfaz, no la clase que habla con MySQL, así se
 * podría cambiar por otra implementación (por ejemplo, la de
 * listas en memoria del TP3) sin tocar el controlador ni la vista.
 *--------------------------------------------------*/
public interface VulnerabilidadDAO {

    /* CU05 con CU13: todas para el administrador, las de sus proyectos para un cliente */
    ArrayList<Vulnerabilidad> listar(Usuario usuario) throws PersistenciaException;

    /* CU03 con CU12: alta de un hallazgo nuevo, devuelve el número que asignó la base */
    int insertar(Vulnerabilidad vulnerabilidad) throws PersistenciaException;

    /* CU06 (y CU04 al iniciar el tratamiento): estado nuevo y seguimiento en una sola transacción */
    void guardarCambioEstado(Vulnerabilidad vulnerabilidad, Seguimiento seguimiento) throws PersistenciaException;

    /* CU07: cambios de estado de un hallazgo, del más viejo al más nuevo */
    ArrayList<Seguimiento> historial(int idVulnerabilidad) throws PersistenciaException;
}
