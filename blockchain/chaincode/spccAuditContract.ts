import { Context, Contract, Info, Returns, Transaction } from 'fabric-contract-api';

export interface RegistroAuditoriaAsset {
  docType: 'registro_auditoria';
  idTransaccion: string;
  idEmisor: string;
  idReceptor: string;
  monto: string;
  evento: string;
  hash: string;
  hashAnterior: string;
  timestampBlockchain: string;
}

@Info({
  title: 'SpccAuditContract',
  description: 'Smart Contract (Chaincode) en Hyperledger Fabric para auditoría inmutable de transferencias NFC en SPCC',
})
export class SpccAuditContract extends Contract {
  @Transaction()
  public async RegistrarAuditoria(
    ctx: Context,
    idTransaccion: string,
    idEmisor: string,
    idReceptor: string,
    monto: string,
    evento: string,
    hash: string,
    hashAnterior: string,
    timestampBlockchain: string,
  ): Promise<string> {
    const key = `AUDIT_${idTransaccion}_${evento}`;
    const existing = await ctx.stub.getState(key);
    if (existing && existing.length > 0) {
      throw new Error(`El registro de auditoría ${key} ya existe en el ledger y es inmutable.`);
    }

    const asset: RegistroAuditoriaAsset = {
      docType: 'registro_auditoria',
      idTransaccion,
      idEmisor,
      idReceptor,
      monto,
      evento,
      hash,
      hashAnterior,
      timestampBlockchain,
    };

    await ctx.stub.putState(key, Buffer.from(JSON.stringify(asset)));
    ctx.stub.setEvent('AuditoriaRegistrada', Buffer.from(JSON.stringify(asset)));
    return JSON.stringify(asset);
  }

  @Transaction(false)
  @Returns('string')
  public async ConsultarAuditoria(
    ctx: Context,
    idTransaccion: string,
    evento: string,
  ): Promise<string> {
    const key = `AUDIT_${idTransaccion}_${evento}`;
    const bytes = await ctx.stub.getState(key);
    if (!bytes || bytes.length === 0) {
      throw new Error(`No existe auditoría para la transacción ${idTransaccion} (${evento})`);
    }
    return bytes.toString();
  }
}
