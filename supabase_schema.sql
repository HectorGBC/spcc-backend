-- ============================================================================
-- ESQUEMA COMPLETO Y ENDURECIDO (HARDENED) DE SPCC_DATABASE PARA SUPABASE
-- Incluye las 7 tablas oficiales + Bcrypt + Auditoría Blockchain SHA-256 + RLS
-- ============================================================================

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 1. Tabla de Bancos
CREATE TABLE IF NOT EXISTS public.banco (
  id_banco SERIAL PRIMARY KEY,
  nombre VARCHAR(100) NOT NULL,
  codigo_bancario VARCHAR(10) NOT NULL UNIQUE
);

-- 2. Tabla de Usuarios
CREATE TABLE IF NOT EXISTS public.usuario (
  id_usuario SERIAL PRIMARY KEY,
  nombre VARCHAR(120) NOT NULL,
  tipo_documento VARCHAR(15) CHECK (tipo_documento IN ('CC', 'CE', 'TI', 'PASAPORTE', 'NIT')),
  documento VARCHAR(30) NOT NULL UNIQUE,
  correo VARCHAR(150) NOT NULL UNIQUE,
  telefono VARCHAR(20),
  pin_hash VARCHAR(255) NOT NULL,
  intentos_fallidos SMALLINT DEFAULT 0 CHECK (intentos_fallidos >= 0),
  bloqueado_hasta TIMESTAMP WITHOUT TIME ZONE,
  creado_en TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 3. Tabla de Cuentas Bancarias
CREATE TABLE IF NOT EXISTS public.cuenta_bancaria (
  id_cuenta SERIAL PRIMARY KEY,
  id_usuario INTEGER NOT NULL REFERENCES public.usuario(id_usuario) ON DELETE CASCADE,
  id_banco INTEGER NOT NULL REFERENCES public.banco(id_banco) ON DELETE CASCADE,
  alias VARCHAR(60),
  tipo_cuenta VARCHAR(20) CHECK (tipo_cuenta IN ('ahorros', 'corriente')),
  numero_cuenta_cifrado VARCHAR(255) NOT NULL,
  ultimos4 CHAR(4) NOT NULL CHECK (ultimos4 ~ '^[0-9]{4}$'),
  activa BOOLEAN DEFAULT TRUE,
  creado_en TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 4. Tabla de Tarjetas Tokenizadas
CREATE TABLE IF NOT EXISTS public.tarjeta_token (
  id_tarjeta SERIAL PRIMARY KEY,
  id_usuario INTEGER NOT NULL REFERENCES public.usuario(id_usuario) ON DELETE CASCADE,
  id_banco_emisor INTEGER NOT NULL REFERENCES public.banco(id_banco) ON DELETE CASCADE,
  token VARCHAR(255) NOT NULL UNIQUE,
  ultimos4 CHAR(4) NOT NULL CHECK (ultimos4 ~ '^[0-9]{4}$'),
  alias VARCHAR(60),
  marca VARCHAR(20) CHECK (marca IN ('VISA', 'MASTERCARD', 'AMEX', 'OTRA')),
  exp_mes SMALLINT NOT NULL CHECK (exp_mes BETWEEN 1 AND 12),
  exp_anio SMALLINT NOT NULL CHECK (exp_anio BETWEEN 2024 AND 2099),
  activa BOOLEAN DEFAULT TRUE,
  creado_en TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 5. Tabla de Dispositivos Biométricos
CREATE TABLE IF NOT EXISTS public.dispositivo (
  id_dispositivo SERIAL PRIMARY KEY,
  id_usuario INTEGER NOT NULL REFERENCES public.usuario(id_usuario) ON DELETE CASCADE,
  nombre VARCHAR(80),
  llave_publica TEXT,
  biometria_activa BOOLEAN DEFAULT FALSE,
  activo BOOLEAN DEFAULT TRUE,
  creado_en TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 6. Tabla de Transacciones NFC
CREATE TABLE IF NOT EXISTS public.transaccion (
  id_transaccion BIGSERIAL PRIMARY KEY,
  id_usuario_emisor INTEGER REFERENCES public.usuario(id_usuario) ON DELETE SET NULL,
  id_usuario_receptor INTEGER REFERENCES public.usuario(id_usuario) ON DELETE SET NULL,
  id_cuenta_origen INTEGER REFERENCES public.cuenta_bancaria(id_cuenta) ON DELETE SET NULL,
  id_tarjeta_origen INTEGER REFERENCES public.tarjeta_token(id_tarjeta) ON DELETE SET NULL,
  monto NUMERIC NOT NULL CHECK (monto > 0),
  moneda CHAR(3) DEFAULT 'COP',
  estado VARCHAR(20) DEFAULT 'pendiente' CHECK (estado IN ('pendiente', 'aprobada', 'rechazada')),
  mensaje_cifrado TEXT,
  clave_idempotencia VARCHAR(64) UNIQUE,
  creado_en TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  actualizado_en TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT transaccion_emisor_receptor_distintos_check
    CHECK (id_usuario_emisor IS NULL OR id_usuario_receptor IS NULL OR id_usuario_emisor <> id_usuario_receptor)
);

-- 7. Tabla de Registro de Auditoría Inmutable (Blockchain)
CREATE TABLE IF NOT EXISTS public.registro_auditoria (
  id_registro BIGSERIAL PRIMARY KEY,
  id_transaccion BIGINT NOT NULL REFERENCES public.transaccion(id_transaccion) ON DELETE RESTRICT,
  evento VARCHAR(20) CHECK (evento IN ('creada', 'aprobada', 'rechazada')),
  hash CHAR(64) NOT NULL UNIQUE,
  hash_anterior CHAR(64),
  timestamp_blockchain TIMESTAMP WITHOUT TIME ZONE,
  creado_en TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- TRIGGERS DE SEGURIDAD Y AUDITORÍA
-- ============================================================================

CREATE OR REPLACE FUNCTION public.fn_proteger_usuario_credenciales()
RETURNS TRIGGER AS $$
BEGIN
  IF NEW.correo IS NOT NULL THEN
    NEW.correo := lower(trim(NEW.correo));
  END IF;
  IF NEW.tipo_documento IS NOT NULL THEN
    NEW.tipo_documento := upper(trim(NEW.tipo_documento));
  END IF;
  IF NEW.pin_hash IS NOT NULL AND NEW.pin_hash NOT LIKE '$2a$%' AND NEW.pin_hash NOT LIKE '$2b$%' THEN
    NEW.pin_hash := crypt(NEW.pin_hash, gen_salt('bf', 10));
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_proteger_usuario_credenciales ON public.usuario;
CREATE TRIGGER trg_proteger_usuario_credenciales
BEFORE INSERT OR UPDATE OF pin_hash, correo, tipo_documento ON public.usuario
FOR EACH ROW EXECUTE FUNCTION public.fn_proteger_usuario_credenciales();

CREATE OR REPLACE FUNCTION public.fn_bloquear_modificacion_auditoria()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'Violación de seguridad SPCC: La tabla registro_auditoria es inmutable (no se permite %)', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_inmutabilidad_auditoria ON public.registro_auditoria;
CREATE TRIGGER trg_inmutabilidad_auditoria
BEFORE UPDATE OR DELETE ON public.registro_auditoria
FOR EACH ROW EXECUTE FUNCTION public.fn_bloquear_modificacion_auditoria();

CREATE OR REPLACE FUNCTION public.fn_auditar_transaccion_blockchain()
RETURNS TRIGGER AS $$
DECLARE
  v_hash_anterior CHAR(64);
  v_nuevo_hash CHAR(64);
  v_evento VARCHAR(20);
BEGIN
  IF TG_OP = 'INSERT' THEN
    v_evento := 'creada';
  ELSE
    v_evento := CASE WHEN NEW.estado IN ('aprobada', 'rechazada') THEN NEW.estado ELSE 'creada' END;
  END IF;

  SELECT hash INTO v_hash_anterior FROM public.registro_auditoria ORDER BY id_registro DESC LIMIT 1;

  v_nuevo_hash := encode(
    digest(
      COALESCE(v_hash_anterior, repeat('0', 64)) || '|' ||
      NEW.id_transaccion::text || '|' ||
      COALESCE(NEW.id_usuario_emisor::text, '0') || '|' ||
      COALESCE(NEW.id_usuario_receptor::text, '0') || '|' ||
      NEW.monto::text || '|' ||
      v_evento || '|' ||
      clock_timestamp()::text,
      'sha256'
    ),
    'hex'
  );

  INSERT INTO public.registro_auditoria (id_transaccion, evento, hash, hash_anterior, timestamp_blockchain, creado_en)
  VALUES (NEW.id_transaccion, v_evento, v_nuevo_hash, v_hash_anterior, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_auditar_transaccion_blockchain ON public.transaccion;
CREATE TRIGGER trg_auditar_transaccion_blockchain
AFTER INSERT OR UPDATE OF estado ON public.transaccion
FOR EACH ROW EXECUTE FUNCTION public.fn_auditar_transaccion_blockchain();

-- ============================================================================
-- ÍNDICES Y ROW LEVEL SECURITY (RLS)
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_usuario_correo_lower ON public.usuario (lower(correo));
CREATE INDEX IF NOT EXISTS idx_cuenta_bancaria_usuario ON public.cuenta_bancaria (id_usuario);
CREATE INDEX IF NOT EXISTS idx_tarjeta_token_usuario ON public.tarjeta_token (id_usuario);
CREATE INDEX IF NOT EXISTS idx_dispositivo_usuario ON public.dispositivo (id_usuario);
CREATE INDEX IF NOT EXISTS idx_transaccion_emisor ON public.transaccion (id_usuario_emisor);
CREATE INDEX IF NOT EXISTS idx_transaccion_receptor ON public.transaccion (id_usuario_receptor);
CREATE INDEX IF NOT EXISTS idx_transaccion_fecha ON public.transaccion (creado_en DESC);
CREATE INDEX IF NOT EXISTS idx_registro_auditoria_tx ON public.registro_auditoria (id_transaccion);

ALTER TABLE public.usuario ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.banco ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.cuenta_bancaria ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tarjeta_token ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.dispositivo ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.transaccion ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.registro_auditoria ENABLE ROW LEVEL SECURITY;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;

-- Datos iniciales de bancos y usuarios actuales (migrados con Bcrypt automático)
INSERT INTO public.banco (nombre, codigo_bancario)
VALUES ('Bancolombia', '007'), ('Davivienda', '051')
ON CONFLICT (codigo_bancario) DO NOTHING;

INSERT INTO public.usuario (nombre, tipo_documento, documento, correo, telefono, pin_hash)
VALUES
  ('Héctor Giovanny', 'CC', '100200300', 'hector@gmail.com', '3124567890', '1234'),
  ('Andrés Gonzalez', 'CC', '1564237864', 'andres@gmail.com', '3214567536', '1024')
ON CONFLICT (correo) DO NOTHING;

COMMIT;
