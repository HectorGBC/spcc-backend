import { Injectable, Logger } from '@nestjs/common';
import * as crypto from 'crypto';
import * as fs from 'fs';

export interface FabricAuditPayload {
  idTransaccion: number | string;
  idEmisor: number | string;
  idReceptor: number | string;
  monto: number;
  moneda: string;
  evento: 'creada' | 'aprobada' | 'rechazada';
  hashAnterior: string | null;
}

export interface FabricAuditResult {
  txIdFabric: string;
  hashBloque: string;
  hashAnterior: string | null;
  modo: 'HYPERLEDGER_FABRIC_PEER' | 'HYPERLEDGER_LOCAL_LEDGER';
  timestamp: string;
}

/**
 * Servicio de integración con Hyperledger Fabric (Canal: spcc-channel, Chaincode: spcc-audit).
 * - Si las variables de entorno de conexión al Peer de Hyperledger Fabric (FABRIC_PEER_ENDPOINT,
 *   FABRIC_CERT_PATH, FABRIC_KEY_PATH) están configuradas y el contenedor Docker del Peer está activo,
 *   envía la transacción directamente al Chaincode `SpccAuditContract:RegistrarAuditoria`.
 * - Si el entorno Docker de Hyperledger Fabric aún no está levantado localmente, firma el bloque
 *   con la misma estructura determinística SHA-256 encadenada para que la app funcione sin interrupción.
 */
@Injectable()
export class FabricService {
  private readonly logger = new Logger(FabricService.name);

  private readonly channelName = process.env.FABRIC_CHANNEL || 'spcc-channel';
  private readonly chaincodeName = process.env.FABRIC_CHAINCODE || 'spcc-audit';
  private readonly mspId = process.env.FABRIC_MSP_ID || 'Org1MSP';
  private readonly peerEndpoint = process.env.FABRIC_PEER_ENDPOINT || '';
  private readonly certPath = process.env.FABRIC_CERT_PATH || '';
  private readonly keyPath = process.env.FABRIC_KEY_PATH || '';

  async registrarEventoEnBlockchain(
    payload: FabricAuditPayload,
  ): Promise<FabricAuditResult> {
    const timestamp = new Date().toISOString();
    const prevHash = payload.hashAnterior || '0'.repeat(64);

    // Calcular hash SHA-256 determinístico del bloque de auditoría
    const rawBlockString = [
      prevHash,
      String(payload.idTransaccion),
      String(payload.idEmisor),
      String(payload.idReceptor),
      Number(payload.monto).toFixed(2),
      payload.moneda || 'COP',
      payload.evento,
      timestamp,
    ].join('|');

    const hashBloque = crypto
      .createHash('sha256')
      .update(rawBlockString)
      .digest('hex');

    // Verificar si hay credenciales de un nodo Peer de Hyperledger Fabric configuradas
    if (
      this.peerEndpoint &&
      this.certPath &&
      this.keyPath &&
      fs.existsSync(this.certPath) &&
      fs.existsSync(this.keyPath)
    ) {
      try {
        // Carga dinámica de @hyperledger/fabric-gateway si fue instalado
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const fabricGateway = require('@hyperledger/fabric-gateway');
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const grpc = require('@grpc/grpc-js');

        const certPem = fs.readFileSync(this.certPath);
        const keyPem = fs.readFileSync(this.keyPath);
        const privateKey = crypto.createPrivateKey(keyPem);
        const signer = fabricGateway.signers.newPrivateKeySigner(privateKey);

        const client = new grpc.Client(
          this.peerEndpoint,
          grpc.credentials.createInsecure(),
        );

        const gateway = fabricGateway.connect({
          client,
          identity: { mspId: this.mspId, credentials: certPem },
          signer,
        });

        try {
          const network = gateway.getNetwork(this.channelName);
          const contract = network.getContract(this.chaincodeName);

          await contract.submitTransaction(
            'RegistrarAuditoria',
            String(payload.idTransaccion),
            String(payload.idEmisor),
            String(payload.idReceptor),
            Number(payload.monto).toFixed(2),
            payload.evento,
            hashBloque,
            prevHash,
            timestamp,
          );

          this.logger.log(
            `[Hyperledger Fabric] Bloque confirmado en ${this.channelName}/${this.chaincodeName}: ${hashBloque}`,
          );

          return {
            txIdFabric: `hlf-${hashBloque.substring(0, 16)}`,
            hashBloque,
            hashAnterior: payload.hashAnterior,
            modo: 'HYPERLEDGER_FABRIC_PEER',
            timestamp,
          };
        } finally {
          gateway.close();
          client.close();
        }
      } catch (err: any) {
        this.logger.warn(
          `[Hyperledger Fabric] Peer no alcanzable (${err?.message || err}), usando Ledger Criptográfico Local encadenado.`,
        );
      }
    }

    return {
      txIdFabric: `hlf-sim-${hashBloque.substring(0, 16)}`,
      hashBloque,
      hashAnterior: payload.hashAnterior,
      modo: 'HYPERLEDGER_LOCAL_LEDGER',
      timestamp,
    };
  }
}
