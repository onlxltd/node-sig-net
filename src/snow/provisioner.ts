import { buildIdentifyTlv, buildKeyTlv, buildPomPublicKeyTlv, buildScopeTlv, buildSnowTlvs } from './tlv.js'
import { buildSnowManagerPacket } from './packet.js'
import { deriveSnowKeys } from './credentials.js'
import { parseSnowManifest, type SnowManifest } from './manifest.js'
import { SnowIdentity } from './identity.js'
import { SnowTlsClient } from './tls.js'
import type { SnowDeviceRole, SnowProvisioningOptions } from './types.js'
import { TOTW_RT_KEY_K0, TOTW_RT_KEY_KC, TOTW_RT_KEY_KM_GLOBAL, TOTW_RT_KEY_KM_LOCAL, TOTW_RT_KEY_KS } from '../core/constants.js'

export interface SnowProvisionerOptions {
    managerTuid: Uint8Array
    mfgCode: number
    k0: Uint8Array
    identity?: SnowIdentity
    pomPublicKey?: Uint8Array
    manifest?: SnowManifest | string
    sessionId?: number
}

export interface SnowProvisioningResult {
    tuid: Buffer
    publicKey: Buffer
    keys: { senderKey?: Buffer; citizenKey?: Buffer; managerGlobalKey?: Buffer; managerLocalKey?: Buffer; k0?: Buffer }
}

export class SnowProvisioner {
    readonly managerTuid: Buffer
    readonly mfgCode: number
    readonly k0: Buffer
    readonly identity: SnowIdentity
    private readonly options: SnowProvisionerOptions
    private readonly trusted = new Map<string, Buffer>()

    constructor(options: SnowProvisionerOptions) {
        if (options.managerTuid.length !== 6 || options.k0.length !== 32) throw new RangeError('invalid manager credentials')
        this.managerTuid = Buffer.from(options.managerTuid)
        this.mfgCode = options.mfgCode
        this.k0 = Buffer.from(options.k0)
        this.identity = options.identity ?? new SnowIdentity()
        this.options = options
        if (options.manifest) this.importManifest(options.manifest)
    }

    importManifest(manifest: SnowManifest | string): void {
        const parsed = parseSnowManifest(manifest)
        for (const device of parsed['sig - net_snow_manifest'].devices) this.trusted.set(device.tuid.toUpperCase(), Buffer.from(device.public_key, 'base64'))
    }

    trust(tuid: Uint8Array, publicKey: Uint8Array): void { this.trusted.set(Buffer.from(tuid).toString('hex').toUpperCase(), Buffer.from(publicKey)) }

    async provision(host: string, port: number, tuid: Uint8Array, options: SnowProvisioningOptions, tlsOptions: ConstructorParameters<typeof SnowTlsClient>[0] = {} as never): Promise<SnowProvisioningResult> {
        const session = new SnowTlsClient({ ...tlsOptions, host, port })
        await session.connect()
        try {
            const publicKey = session.getApplicationPublicKey() ?? session.getPeerPublicKey()
            if (!publicKey) throw new Error('SNOW peer certificate does not contain a P-256 public key')
            await this.authenticate(session, tuid, publicKey, options)
            const keys = deriveSnowKeys(this.k0, tuid)
            const tlvs = [buildScopeTlv(options.scope ?? 'local')]
            if (options.role === 'sender') tlvs.push(buildKeyTlv(TOTW_RT_KEY_KS, keys.senderKey), buildKeyTlv(TOTW_RT_KEY_KC, keys.citizenKey))
            else if (options.role === 'node') tlvs.push(buildKeyTlv(TOTW_RT_KEY_KM_GLOBAL, keys.managerGlobalKey), buildKeyTlv(TOTW_RT_KEY_KM_LOCAL, keys.managerLocalKey))
            else if (options.role === 'manager') {
                tlvs.push(buildKeyTlv(TOTW_RT_KEY_KS, keys.senderKey), buildKeyTlv(TOTW_RT_KEY_KC, keys.citizenKey), buildKeyTlv(TOTW_RT_KEY_KM_GLOBAL, keys.managerGlobalKey))
                if (options.equalManager) tlvs.push(buildKeyTlv(TOTW_RT_KEY_K0, this.k0))
            }
            tlvs.push(buildPomPublicKeyTlv(this.options.pomPublicKey ?? this.identity.getRawPublicKey()))
            session.send(buildSnowManagerPacket({ ...this.sessionArgs(), targetTuid: tuid, mfgCode: this.mfgCode, tlvs: buildSnowTlvs(...tlvs), messageId: 1 }))
            await session.waitForClose()
            return { tuid: Buffer.from(tuid), publicKey, keys: options.role === 'sender' ? { senderKey: keys.senderKey, citizenKey: keys.citizenKey } : options.role === 'node' ? { managerGlobalKey: keys.managerGlobalKey, managerLocalKey: keys.managerLocalKey } : { senderKey: keys.senderKey, citizenKey: keys.citizenKey, managerGlobalKey: keys.managerGlobalKey, ...(options.equalManager ? { k0: this.k0 } : {}) } }
        } finally { session.close() }
    }

    private async authenticate(session: SnowTlsClient, tuid: Uint8Array, publicKey: Buffer, options: SnowProvisioningOptions): Promise<void> {
        const key = Buffer.from(tuid).toString('hex').toUpperCase()
        const trusted = this.trusted.get(key)
        if (options.authentication === 'manifest') {
            if (!trusted || !trusted.equals(publicKey)) throw new Error('SNOW device is not trusted by the manifest')
            return
        }
        if (trusted?.equals(publicKey)) return
        const details: { tuid: Buffer; publicKey: Buffer; pin?: string } = { tuid: Buffer.from(tuid), publicKey }
        if (options.authentication === 'pin') {
            const material = session.exportKeyingMaterial(4, 'EXPORTER-Sig-Net-SNOW-PIN')
            details.pin = String(material.readUInt32BE(0) % 1000000).padStart(6, '0')
        } else {
            const fingerprint = session.exportKeyingMaterial(32, 'EXPORTER-Sig-Net-SNOW-Identify')
            session.send(buildSnowManagerPacket({ ...this.sessionArgs(), targetTuid: tuid, mfgCode: this.mfgCode, tlvs: buildIdentifyTlv(fingerprint), messageId: 1 }))
        }
        if (!options.confirm || !(await options.confirm(details))) throw new Error('SNOW device identity was not confirmed')
        this.trust(tuid, publicKey)
    }

    private sessionArgs(): { managerTuid: Buffer; sessionId?: number } {
        return this.options.sessionId === undefined ? { managerTuid: this.managerTuid } : { managerTuid: this.managerTuid, sessionId: this.options.sessionId }
    }
}

export default SnowProvisioner
