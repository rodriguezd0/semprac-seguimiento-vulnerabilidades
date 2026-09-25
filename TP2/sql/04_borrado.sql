-- ============================================================
-- Sistema de seguimiento de vulnerabilidades por proyecto
-- 04_borrado.sql: borrado de registros
-- Autor: Rodríguez, Daniel Sebastián (legajo VINF016869)
-- ============================================================
USE vulnerabilidades_db;

-- B1: borrar un responsable que no tiene hallazgos (se permite).
DELETE FROM responsable WHERE nombre = 'Mesa de ayuda';
SELECT id_responsable, nombre FROM responsable;

-- B2: borrar un activo que tiene hallazgos. Lo rechaza la clave foránea,
-- así no se pierde el historial de esos hallazgos.
DELETE FROM activo WHERE id_activo = 1;

-- B3: el activo 6 no tiene hallazgos, se puede borrar.
DELETE FROM activo WHERE id_activo = 6;
SELECT id_activo, nombre FROM activo;
