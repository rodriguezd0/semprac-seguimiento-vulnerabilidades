-- ============================================================
-- Sistema de seguimiento de vulnerabilidades por proyecto
-- 03_consultas.sql: consultas de los casos de uso y actualización
-- Autor: Rodríguez, Daniel Sebastián (legajo VINF016869)
-- ============================================================
USE vulnerabilidades_db;

-- C1 (CU05, administrador): hallazgos abiertos de todos los proyectos.
-- LEFT JOIN con responsable porque un hallazgo puede no tenerlo todavía.
SELECT v.id_vulnerabilidad AS id, p.nombre AS proyecto, a.nombre AS activo,
       v.titulo, v.estado, r.nombre AS responsable, v.fecha_objetivo
FROM vulnerabilidad v
JOIN activo a           ON a.id_activo = v.id_activo
JOIN proyecto p         ON p.id_proyecto = a.id_proyecto
LEFT JOIN responsable r ON r.id_responsable = v.id_responsable
WHERE v.estado <> 'CERRADA'
ORDER BY v.fecha_deteccion;

-- C2 (CU05 con CU13, cliente 3): solo ve los hallazgos de SUS proyectos.
SELECT v.id_vulnerabilidad AS id, p.nombre AS proyecto, v.titulo, v.estado
FROM vulnerabilidad v
JOIN activo a   ON a.id_activo = v.id_activo
JOIN proyecto p ON p.id_proyecto = a.id_proyecto
WHERE p.id_cliente = 3
ORDER BY v.id_vulnerabilidad;

-- C3 (CU07): historial del hallazgo 3 con el usuario que registró cada cambio.
SELECT s.fecha_hora, s.estado_anterior, s.estado_nuevo, u.nombre_acceso AS usuario, s.comentario
FROM seguimiento s
JOIN usuario u ON u.id_usuario = s.id_usuario
WHERE s.id_vulnerabilidad = 3
ORDER BY s.fecha_hora;

-- C4: cantidad de hallazgos por proyecto y estado.
SELECT p.nombre AS proyecto, v.estado, COUNT(*) AS cantidad
FROM vulnerabilidad v
JOIN activo a   ON a.id_activo = v.id_activo
JOIN proyecto p ON p.id_proyecto = a.id_proyecto
GROUP BY p.nombre, v.estado
ORDER BY p.nombre, v.estado;

-- C5 (CU04 y CU06): asignar el hallazgo 4 e iniciar su tratamiento.
-- El cambio de estado y su seguimiento van en la misma transacción.
START TRANSACTION;
UPDATE vulnerabilidad
   SET id_responsable = 1, fecha_objetivo = '2026-10-02', estado = 'EN_TRATAMIENTO'
 WHERE id_vulnerabilidad = 4;
INSERT INTO seguimiento (id_vulnerabilidad, id_usuario, estado_anterior, estado_nuevo, comentario)
VALUES (4, 1, 'PENDIENTE', 'EN_TRATAMIENTO', 'Soporte cambia la clave de fábrica del panel.');
COMMIT;
SELECT id_vulnerabilidad, estado, id_responsable, fecha_objetivo
FROM vulnerabilidad WHERE id_vulnerabilidad = 4;

-- C6 (prueba de integridad): fecha objetivo anterior a la detección.
-- La base tiene que rechazarla por la restricción CHECK.
UPDATE vulnerabilidad SET fecha_objetivo = '2026-01-01' WHERE id_vulnerabilidad = 5;
