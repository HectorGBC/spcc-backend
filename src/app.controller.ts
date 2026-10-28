import {
  Controller,
  Post,
  Get,
  Param,
  Body,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { DataSource } from 'typeorm';
import * as dns from 'dns';
import { FabricService } from './fabric.service';

interface ActiveNfcDevice {
  id_usuario: number;
  nombre: string;
  correo: string;
  banco: string;
  nfc_tag_id?: string;
  lastSeen: number;
}

interface PendingIncomingNotification {
  id_transaccion: number;
  emisor_nombre: string;
  banco: string;
  monto: number;
  hash_auditoria: string;
  time: string;
  timestamp: number;
}

@Controller('auth')
export class AppController {
  // Sesiones activas de dispositivos que están dentro de la pantalla Transferir (NFC)
  private activeNfcSessions = new Map<number, ActiveNfcDevice>();
  // Notificaciones en tiempo real para el dispositivo receptor
  private incomingTransfers = new Map<number, PendingIncomingNotification[]>();

  constructor(
    private dataSource: DataSource,
    private fabricService: FabricService,
  ) {}

  private censorFullName(nombre: string): string {
    if (!nombre) return 'Usu***';
    return nombre
      .split(' ')
      .filter(Boolean)
      .map((part) =>
        part.length <= 3 ? part + '***' : part.substring(0, 3) + '***',
      )
      .join(' ');
  }

  private async verifyEmailDomainMx(email: string): Promise<boolean> {
    const clean = (email || '').trim().toLowerCase();
    const emailRegex = /^[^\s@]+@([^\s@]+\.[^\s@]{2,})$/;
    const match = clean.match(emailRegex);
    if (!match) return false;

    const domain = match[1];
    try {
      const mxRecords = await dns.promises.resolveMx(domain);
      return Array.isArray(mxRecords) && mxRecords.length > 0;
    } catch {
      return false;
    }
  }

  private verifyValidMobilePhone(phone: string): boolean {
    const digits = (phone || '').replace(/[^0-9]/g, '');
    if (digits.length !== 10 || !digits.startsWith('3')) return false;
    if (/^(\d)\1{9}$/.test(digits)) return false;
    const prefix = parseInt(digits.substring(0, 3), 10);
    return (
      (prefix >= 300 && prefix <= 324) ||
      prefix === 333 ||
      (prefix >= 350 && prefix <= 351)
    );
  }

  // ==========================================
  // 1. ENDPOINT DE INICIO DE SESIÓN SEGURO
  // ==========================================
  @Post('login')
  async login(@Body() body: { correo: string; pin_hash: string }) {
    const correo = body?.correo?.trim().toLowerCase();
    const pin = body?.pin_hash;

    if (!correo || !pin) {
      throw new HttpException(
        'Correo y PIN de 4 dígitos requeridos',
        HttpStatus.BAD_REQUEST,
      );
    }

    const candidatos = await this.dataSource.query(
      `SELECT id_usuario, nombre, tipo_documento, documento, correo, telefono,
              intentos_fallidos, bloqueado_hasta, creado_en,
              (pin_hash = crypt($2, pin_hash)) AS pin_valido
       FROM public.usuario
       WHERE lower(correo) = $1
       LIMIT 1`,
      [correo, pin],
    );

    if (candidatos.length === 0) {
      throw new HttpException('Credenciales inválidas', HttpStatus.UNAUTHORIZED);
    }

    const usuario = candidatos[0];

    if (
      usuario.bloqueado_hasta &&
      new Date(usuario.bloqueado_hasta) > new Date()
    ) {
      throw new HttpException(
        'Cuenta bloqueada temporalmente por múltiples intentos fallidos. Intenta de nuevo en 15 minutos.',
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    if (!usuario.pin_valido) {
      await this.dataSource.query(
        `UPDATE public.usuario
         SET intentos_fallidos = COALESCE(intentos_fallidos, 0) + 1,
             bloqueado_hasta = CASE
               WHEN COALESCE(intentos_fallidos, 0) + 1 >= 5
               THEN CURRENT_TIMESTAMP + INTERVAL '15 minutes'
               ELSE bloqueado_hasta
             END
         WHERE id_usuario = $1`,
        [usuario.id_usuario],
      );

      throw new HttpException('Credenciales inválidas', HttpStatus.UNAUTHORIZED);
    }

    if (usuario.intentos_fallidos > 0 || usuario.bloqueado_hasta) {
      await this.dataSource.query(
        `UPDATE public.usuario
         SET intentos_fallidos = 0, bloqueado_hasta = NULL
         WHERE id_usuario = $1`,
        [usuario.id_usuario],
      );
    }

    return {
      success: true,
      message: 'Login exitoso',
      usuario: {
        id_usuario: usuario.id_usuario,
        nombre: usuario.nombre,
        tipo_documento: usuario.tipo_documento,
        documento: usuario.documento,
        correo: usuario.correo,
        telefono: usuario.telefono,
        creado_en: usuario.creado_en,
      },
    };
  }

  // ==========================================
  // 2. ENDPOINT DE REGISTRO SEGURO (CON VERIFICACIÓN DE CORREO, TELÉFONO Y PIN DE 4 DÍGITOS)
  // ==========================================
  @Post('registro')
  async registrar(@Body() body: any) {
    const { nombre, tipo_documento, documento, correo, telefono, pin_hash } =
      body || {};

    if (!nombre || !documento || !correo || !telefono || !pin_hash) {
      throw new HttpException(
        'Todos los campos obligatorios deben ser enviados.',
        HttpStatus.BAD_REQUEST,
      );
    }

    if (!/^[0-9]{4}$/.test(String(pin_hash))) {
      throw new HttpException(
        'El PIN debe tener exactamente 4 dígitos numéricos.',
        HttpStatus.BAD_REQUEST,
      );
    }

    if (!this.verifyValidMobilePhone(String(telefono))) {
      throw new HttpException(
        'El número de teléfono no corresponde a una línea móvil válida.',
        HttpStatus.BAD_REQUEST,
      );
    }

    const emailMxValid = await this.verifyEmailDomainMx(String(correo));
    if (!emailMxValid) {
      throw new HttpException(
        'El dominio del correo electrónico no existe o no tiene servidores de correo activos.',
        HttpStatus.BAD_REQUEST,
      );
    }

    try {
      await this.dataSource.query(
        `INSERT INTO public.usuario (nombre, tipo_documento, documento, correo, telefono, pin_hash) 
         VALUES ($1, upper(trim($2)), trim($3), lower(trim($4)), trim($5), crypt($6, gen_salt('bf', 10)))`,
        [
          nombre.trim(),
          tipo_documento || 'CC',
          documento,
          correo,
          telefono,
          String(pin_hash),
        ],
      );

      return { success: true, message: 'Usuario creado exitosamente' };
    } catch (error) {
      console.error('Error al registrar usuario:', error);

      throw new HttpException(
        'Error al registrar. Verifica que el correo, teléfono o documento no estén duplicados.',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  // ==========================================
  // 3. VERIFICAR PIN (PARA REVELAR DATOS O AUTORIZAR TRANSFERENCIA)
  // ==========================================
  @Post('verificar-pin')
  async verificarPin(
    @Body() body: { id_usuario?: number; correo?: string; pin: string },
  ) {
    const { id_usuario, correo, pin } = body || {};
    if (!pin || !/^[0-9]{4}$/.test(String(pin))) {
      throw new HttpException(
        'Se requiere un PIN numérico de 4 dígitos.',
        HttpStatus.BAD_REQUEST,
      );
    }

    const rows = await this.dataSource.query(
      `SELECT id_usuario, nombre, tipo_documento, documento, correo, telefono,
              (pin_hash = crypt($1, pin_hash)) AS pin_valido
       FROM public.usuario
       WHERE ($2::int IS NOT NULL AND id_usuario = $2::int)
          OR ($3::text IS NOT NULL AND lower(correo) = lower(trim($3::text)))
       LIMIT 1`,
      [String(pin), id_usuario || null, correo || null],
    );

    if (rows.length === 0 || !rows[0].pin_valido) {
      throw new HttpException(
        'PIN incorrecto. No se pudo autorizar la operación.',
        HttpStatus.UNAUTHORIZED,
      );
    }

    const u = rows[0];
    return {
      success: true,
      usuario: {
        id_usuario: u.id_usuario,
        nombre: u.nombre,
        tipo_documento: u.tipo_documento,
        documento: u.documento,
        correo: u.correo,
        telefono: u.telefono,
      },
    };
  }

  // ==========================================
  // 4. EMPAREJAMIENTO Y DETECCIÓN DE DISPOSITIVOS EN PANTALLA NFC
  // ==========================================
  @Post('nfc-presence')
  async nfcPresence(
    @Body()
    body: {
      id_usuario: number;
      nombre: string;
      correo: string;
      banco?: string;
      nfc_tag_id?: string;
    },
  ) {
    const now = Date.now();
    const EXPIRY_MS = 25000;

    // Limpiar sesiones inactivas (> 25s)
    for (const [uid, sess] of this.activeNfcSessions.entries()) {
      if (now - sess.lastSeen > EXPIRY_MS) {
        this.activeNfcSessions.delete(uid);
      }
    }

    const myId = Number(body.id_usuario);
    if (myId) {
      this.activeNfcSessions.set(myId, {
        id_usuario: myId,
        nombre: body.nombre || 'Usuario SPCC',
        correo: body.correo || '',
        banco: body.banco || 'SPCC',
        nfc_tag_id: body.nfc_tag_id,
        lastSeen: now,
      });
    }

    // Buscar otro dispositivo que esté activo simultáneamente en la pantalla de transferencia
    let peerDevice: any = null;
    for (const [uid, sess] of this.activeNfcSessions.entries()) {
      if (uid !== myId && now - sess.lastSeen <= EXPIRY_MS) {
        peerDevice = {
          id_usuario: sess.id_usuario,
          nombre_censurado: this.censorFullName(sess.nombre),
          nombre: sess.nombre,
          banco: sess.banco,
        };
        break;
      }
    }

    // Revisar si este dispositivo acaba de recibir una transferencia entrante
    const pending = this.incomingTransfers.get(myId) || [];
    if (pending.length > 0) {
      this.incomingTransfers.delete(myId);
    }

    return {
      success: true,
      peerDetected: Boolean(peerDevice),
      peer: peerDevice,
      incomingTransfers: pending,
    };
  }

  @Post('nfc-leave')
  async nfcLeave(@Body() body: { id_usuario: number }) {
    if (body?.id_usuario) {
      this.activeNfcSessions.delete(Number(body.id_usuario));
    }
    return { success: true };
  }

  // ==========================================
  // 5. TRANSFERENCIA NFC BIDIRECCIONAL + AUDITORÍA HYPERLEDGER FABRIC
  // ==========================================
  @Post('transferir')
  async transferir(
    @Body()
    body: {
      id_usuario_emisor: number;
      id_usuario_receptor: number;
      monto: number;
      banco_destino?: string;
    },
  ) {
    const idEmisor = Number(body?.id_usuario_emisor);
    let idReceptor = Number(body?.id_usuario_receptor);
    const monto = Number(body?.monto);

    if (!idEmisor || isNaN(monto) || monto <= 0) {
      throw new HttpException(
        'Datos de transferencia inválidos (monto debe ser mayor a 0).',
        HttpStatus.BAD_REQUEST,
      );
    }

    if (!idReceptor || idReceptor === idEmisor) {
      const otros = await this.dataSource.query(
        `SELECT id_usuario, nombre FROM public.usuario WHERE id_usuario <> $1 ORDER BY id_usuario ASC LIMIT 1`,
        [idEmisor],
      );
      if (otros.length === 0) {
        throw new HttpException(
          'No se encontró un usuario receptor distinto al emisor.',
          HttpStatus.BAD_REQUEST,
        );
      }
      idReceptor = otros[0].id_usuario;
    }

    const usuarios = await this.dataSource.query(
      `SELECT id_usuario, nombre FROM public.usuario WHERE id_usuario IN ($1, $2)`,
      [idEmisor, idReceptor],
    );
    const emisorObj = usuarios.find((u: any) => u.id_usuario === idEmisor);
    const receptorObj = usuarios.find((u: any) => u.id_usuario === idReceptor);

    const nombreEmisorCensurado = this.censorFullName(
      emisorObj?.nombre || 'Emisor SPCC',
    );
    const nombreReceptorCensurado = this.censorFullName(
      receptorObj?.nombre || 'Receptor SPCC',
    );

    const prevAuditRows = await this.dataSource.query(
      `SELECT hash FROM public.registro_auditoria ORDER BY id_registro DESC LIMIT 1`,
    );
    const prevHash = prevAuditRows.length > 0 ? prevAuditRows[0].hash : null;

    const claveIdempotencia = `nfc_${idEmisor}_${idReceptor}_${Date.now()}`;
    const insertRows = await this.dataSource.query(
      `INSERT INTO public.transaccion (
         id_usuario_emisor,
         id_usuario_receptor,
         monto,
         moneda,
         estado,
         clave_idempotencia
       ) VALUES ($1, $2, $3, 'COP', 'aprobada', $4)
       RETURNING id_transaccion, creado_en`,
      [idEmisor, idReceptor, monto, claveIdempotencia],
    );

    const nuevaTx = insertRows[0];

    const fabricAudit = await this.fabricService.registrarEventoEnBlockchain({
      idTransaccion: nuevaTx.id_transaccion,
      idEmisor,
      idReceptor,
      monto,
      moneda: 'COP',
      evento: 'aprobada',
      hashAnterior: prevHash,
    });

    const auditRows = await this.dataSource.query(
      `SELECT hash, hash_anterior FROM public.registro_auditoria WHERE id_transaccion = $1 ORDER BY id_registro DESC LIMIT 1`,
      [nuevaTx.id_transaccion],
    );
    const finalHash =
      auditRows.length > 0 ? auditRows[0].hash : fabricAudit.hashBloque;

    const horaFormateada = new Date().toLocaleTimeString('es-CO', {
      hour: '2-digit',
      minute: '2-digit',
    });

    const list = this.incomingTransfers.get(idReceptor) || [];
    list.push({
      id_transaccion: Number(nuevaTx.id_transaccion),
      emisor_nombre: nombreEmisorCensurado,
      banco: body?.banco_destino || 'SPCC',
      monto,
      hash_auditoria: finalHash,
      time: horaFormateada,
      timestamp: Date.now(),
    });
    this.incomingTransfers.set(idReceptor, list);

    return {
      success: true,
      transaccion: {
        id_transaccion: Number(nuevaTx.id_transaccion),
        id_usuario_emisor: idEmisor,
        id_usuario_receptor: idReceptor,
        emisor_nombre: nombreEmisorCensurado,
        receptor_nombre: nombreReceptorCensurado,
        banco: body?.banco_destino || 'SPCC',
        monto,
        estado: 'Aprobada',
        time: horaFormateada,
        hash_auditoria: finalHash,
        fabric_tx_id: fabricAudit.txIdFabric,
        modo_blockchain: fabricAudit.modo,
      },
    };
  }

  // ==========================================
  // 6. HISTORIAL DE TRANSACCIONES POR USUARIO (SALIDAS E INGRESOS)
  // ==========================================
  @Get('transacciones/:idUsuario')
  async obtenerTransacciones(@Param('idUsuario') idUsuarioParam: string) {
    const idUsuario = Number(idUsuarioParam);
    if (!idUsuario) {
      return { success: true, transacciones: [] };
    }

    const rows = await this.dataSource.query(
      `SELECT
         t.id_transaccion,
         t.id_usuario_emisor,
         t.id_usuario_receptor,
         t.monto,
         t.estado,
         t.creado_en,
         u_emisor.nombre AS nombre_emisor,
         u_receptor.nombre AS nombre_receptor,
         ra.hash AS hash_auditoria
       FROM public.transaccion t
       LEFT JOIN public.usuario u_emisor ON u_emisor.id_usuario = t.id_usuario_emisor
       LEFT JOIN public.usuario u_receptor ON u_receptor.id_usuario = t.id_usuario_receptor
       LEFT JOIN LATERAL (
         SELECT hash FROM public.registro_auditoria
         WHERE id_transaccion = t.id_transaccion
         ORDER BY id_registro DESC LIMIT 1
       ) ra ON true
       WHERE t.id_usuario_emisor = $1 OR t.id_usuario_receptor = $1
       ORDER BY t.creado_en DESC`,
      [idUsuario],
    );

    const transacciones = rows.map((r: any) => {
      const esSalida = Number(r.id_usuario_emisor) === idUsuario;
      const fechaObj = r.creado_en ? new Date(r.creado_en) : new Date();
      const hora = fechaObj.toLocaleTimeString('es-CO', {
        hour: '2-digit',
        minute: '2-digit',
      });

      return {
        id: `db-tx-${r.id_transaccion}`,
        type: esSalida ? 'sent' : 'received',
        title: esSalida
          ? this.censorFullName(r.nombre_receptor || 'Receptor SPCC')
          : this.censorFullName(r.nombre_emisor || 'Emisor SPCC'),
        bank: esSalida ? 'Envío NFC' : 'Ingreso NFC',
        time: hora,
        status:
          r.estado === 'aprobada'
            ? 'Aprobada'
            : r.estado === 'rechazada'
              ? 'Rechazada'
              : 'Pendiente',
        amount: Number(r.monto),
        hash_auditoria: r.hash_auditoria || null,
      };
    });

    return {
      success: true,
      transacciones,
    };
  }
}
