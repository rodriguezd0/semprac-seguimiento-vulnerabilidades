-- ============================================================
-- Sistema de seguimiento de vulnerabilidades por proyecto
-- 03_verificacion.sql: consultas para ver en la base lo que guardó la aplicación
-- Autor: Rodríguez, Daniel Sebastián (legajo VINF016869)
-- Se ejecuta después de usar la interfaz (por ejemplo, al grabar el video).
-- ============================================================
USE vulnerabilidades_db;

-- 1. Últimos hallazgos registrados, desde la ventana o desde la planilla CSV (CU03)
SELECT v.id_vulnerabilidad, p.nombre AS proyecto, a.nombre AS activo, v.titulo, v.estado, v.vector_cvss
FROM vulnerabilidad v
JOIN activo a   ON a.id_activo = v.id_activo
JOIN proyecto p ON p.id_proyecto = a.id_proyecto
ORDER BY v.id_vulnerabilidad DESC
LIMIT 5;

-- 2. Últimos cambios de estado con su autor (CU06, cada uno se guarda junto con el UPDATE)
SELECT s.id_seguimiento, s.id_vulnerabilidad, u.nombre_acceso, s.fecha_hora,
       s.estado_anterior, s.estado_nuevo, s.comentario
FROM seguimiento s
JOIN usuario u ON u.id_usuario = s.id_usuario
ORDER BY s.id_seguimiento DESC
LIMIT 5;

-- 3. Postcondición de CU06: el estado de cada hallazgo es el estado_nuevo de su último seguimiento
--    (los hallazgos que nunca cambiaron de estado no tienen seguimiento y muestran NULL)
SELECT v.id_vulnerabilidad, v.estado,
       (SELECT s.estado_nuevo FROM seguimiento s
         WHERE s.id_vulnerabilidad = v.id_vulnerabilidad
         ORDER BY s.fecha_hora DESC, s.id_seguimiento DESC LIMIT 1) AS ultimo_seguimiento
FROM vulnerabilidad v
ORDER BY v.id_vulnerabilidad;
