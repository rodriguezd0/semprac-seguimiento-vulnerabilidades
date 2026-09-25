-- ============================================================
-- Sistema de seguimiento de vulnerabilidades por proyecto
-- 01_creacion.sql: creación de la base y de las tablas
-- Autor: Rodríguez, Daniel Sebastián (legajo VINF016869)
-- Motor: MySQL de XAMPP (MariaDB 10.4)
-- ============================================================
DROP DATABASE IF EXISTS vulnerabilidades_db;
CREATE DATABASE vulnerabilidades_db
  CHARACTER SET utf8mb4 COLLATE utf8mb4_spanish_ci;
USE vulnerabilidades_db;

-- Cuentas del sistema. El rol define qué puede hacer cada una.
-- La contraseña nunca se guarda: se guarda el hash SHA-256 de (sal + clave).
CREATE TABLE usuario (
  id_usuario      INT AUTO_INCREMENT PRIMARY KEY,
  nombre_acceso   VARCHAR(40)  NOT NULL UNIQUE,
  nombre_completo VARCHAR(100) NOT NULL,
  clave_hash      CHAR(64)     NOT NULL,
  sal             CHAR(32)     NOT NULL,
  rol             ENUM('ADMINISTRADOR','CLIENTE') NOT NULL,
  activo          BOOLEAN      NOT NULL DEFAULT TRUE
) ENGINE = InnoDB;

-- Cada proyecto tiene un único cliente (cuenta con rol CLIENTE).
CREATE TABLE proyecto (
  id_proyecto  INT AUTO_INCREMENT PRIMARY KEY,
  nombre       VARCHAR(80)  NOT NULL UNIQUE,
  descripcion  VARCHAR(255),
  id_cliente   INT NOT NULL,
  FOREIGN KEY (id_cliente) REFERENCES usuario (id_usuario)
) ENGINE = InnoDB;

-- Recursos informáticos de un proyecto (servidor, aplicación, equipo...).
CREATE TABLE activo (
  id_activo    INT AUTO_INCREMENT PRIMARY KEY,
  id_proyecto  INT NOT NULL,
  nombre       VARCHAR(80) NOT NULL,
  tipo         VARCHAR(40) NOT NULL,
  descripcion  VARCHAR(255),
  FOREIGN KEY (id_proyecto) REFERENCES proyecto (id_proyecto)
) ENGINE = InnoDB;

-- Personas o equipos que corrigen los hallazgos (no usan el sistema).
CREATE TABLE responsable (
  id_responsable INT AUTO_INCREMENT PRIMARY KEY,
  nombre         VARCHAR(100) NOT NULL UNIQUE,
  contacto       VARCHAR(100)
) ENGINE = InnoDB;

-- Hallazgo de seguridad sobre un activo. El vector CVSS se guarda como texto
-- (formato estándar de FIRST); el puntaje y la severidad los calcula Java.
CREATE TABLE vulnerabilidad (
  id_vulnerabilidad INT AUTO_INCREMENT PRIMARY KEY,
  id_activo         INT NOT NULL,
  id_responsable    INT NULL,
  titulo            VARCHAR(150) NOT NULL,
  descripcion       TEXT,
  tipo              VARCHAR(60)  NOT NULL,
  elemento_afectado VARCHAR(150),
  fecha_deteccion   DATE NOT NULL,
  fecha_objetivo    DATE NULL,
  estado            ENUM('PENDIENTE','EN_TRATAMIENTO','CERRADA') NOT NULL DEFAULT 'PENDIENTE',
  vector_cvss       VARCHAR(44) NULL,
  FOREIGN KEY (id_activo)      REFERENCES activo (id_activo),
  FOREIGN KEY (id_responsable) REFERENCES responsable (id_responsable),
  CONSTRAINT ck_fecha_objetivo CHECK (fecha_objetivo IS NULL OR fecha_objetivo >= fecha_deteccion)
) ENGINE = InnoDB;

-- Historial: un registro por cada cambio de estado, con su comentario.
CREATE TABLE seguimiento (
  id_seguimiento    INT AUTO_INCREMENT PRIMARY KEY,
  id_vulnerabilidad INT NOT NULL,
  id_usuario        INT NOT NULL,
  fecha_hora        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  estado_anterior   ENUM('PENDIENTE','EN_TRATAMIENTO','CERRADA') NOT NULL,
  estado_nuevo      ENUM('PENDIENTE','EN_TRATAMIENTO','CERRADA') NOT NULL,
  comentario        VARCHAR(500) NOT NULL,
  FOREIGN KEY (id_vulnerabilidad) REFERENCES vulnerabilidad (id_vulnerabilidad),
  FOREIGN KEY (id_usuario)        REFERENCES usuario (id_usuario)
) ENGINE = InnoDB;

SHOW TABLES;
