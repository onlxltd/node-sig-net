import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { dirname } from 'node:path'
import tls, { type Server } from 'node:tls'
import { EventEmitter } from 'node:events'
import { randomBytes } from 'node:crypto'
import dgram from 'node:dgram'
import { decodeCoapTcpFrame, encodeCoapTcpFrame } from './tls.js'
import { buildSnowNodePacket } from './packet.js'
import { buildPublicKeyTlv } from './tlv.js'
import { SnowIdentity } from './identity.js'
import { parsePacket } from '../core/parse.js'
import { MULTICAST_NODE_BEACON_IP, SECURITY_MODE_UNPROVISIONED, SIGNET_UDP_PORT, TOTW_RT_KEY_K0, TOTW_RT_KEY_KC, TOTW_RT_KEY_KM_GLOBAL, TOTW_RT_KEY_KM_LOCAL, TOTW_RT_KEY_KS, TOTW_RT_OTW_REOPEN, TOTW_RT_POM_WIPE, TOTW_RT_POM_PUBLIC_KEY, TOTW_RT_SCOPE } from '../core/constants.js'
import { SigNetNode } from '../core/node.js'
import { SigNetSender } from '../core/sender.js'
import { verifyRawEcdsa } from './identity.js'
import { verifyHmacOtwReopen, otwReopenAuthorizationInput } from './signatures.js'
import { hmacSha256 } from '../core/crypto.js'

export type SnowDeviceKeys = {
    [TOTW_RT_KEY_KS]?: Buffer
    [TOTW_RT_KEY_KC]?: Buffer
    [TOTW_RT_KEY_KM_GLOBAL]?: Buffer
    [TOTW_RT_KEY_KM_LOCAL]?: Buffer
    [TOTW_RT_KEY_K0]?: Buffer
}

export interface SnowDeviceState {
    tuid: string
    publicKey: string
    scope?: string
    pomPublicKey?: string
    keys: Record<string, string>
    provisioned: boolean
}

export class SnowDeviceStore {
    constructor(readonly path: string) {}

    async load(tuid: Uint8Array, publicKey: Uint8Array): Promise<SnowDeviceState> {
        try {
            const state = JSON.parse(await readFile(this.path, 'utf8')) as SnowDeviceState
            if (state.tuid !== Buffer.from(tuid).toString('hex').toUpperCase()) throw new Error('stored TUID mismatch')
            return state
        } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
            return { tuid: Buffer.from(tuid).toString('hex').toUpperCase(), publicKey: Buffer.from(publicKey).toString('base64'), keys: {}, provisioned: false }
        }
    }

    async save(state: SnowDeviceState): Promise<void> {
        const temp = `${this.path}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`
        await mkdir(dirname(this.path), { recursive: true })
        await writeFile(temp, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 })
        await rename(temp, this.path)
    }
}

export interface SnowDeviceOptions {
    tuid: Uint8Array
    mfgCode: number
    store: SnowDeviceStore
    tlsKey: string | Buffer
    tlsCertificate: string | Buffer
    tlsHost?: string
    tlsPort?: number
    autoStartOperational?: boolean
}

export declare interface SnowDevice {
    on(event: 'provisioned', listener: (state: SnowDeviceState) => void): this
    on(event: 'identify', listener: () => void): this
    on(event: 'error', listener: (error: Error) => void): this
    on(event: 'wiped', listener: () => void): this
}

/** Device-side SNOW endpoint with atomic persistence and UDP-role handoff. */
export class SnowDevice extends EventEmitter {
    private readonly options: SnowDeviceOptions
    private readonly identity = new SnowIdentity()
    private server: Server | undefined
    private state?: SnowDeviceState
    private node: SigNetNode | undefined
    private sender: SigNetSender | undefined
    private readonly snrpSocket = dgram.createSocket({ type: 'udp4', reuseAddr: true })

    constructor(options: SnowDeviceOptions) {
        super()
        if (options.tuid.length !== 6) throw new RangeError('tuid must be 6 bytes')
        this.options = options
    }

    async start(): Promise<void> {
        this.state = await this.options.store.load(this.options.tuid, this.identity.getRawPublicKey())
        await this.startSNRPListener()
        if (this.state.provisioned) {
            if (this.options.autoStartOperational) await this.startOperational()
            return
        }
        await this.openTlsServer()
    }

    private async openTlsServer(): Promise<void> {
        if (this.server) return
        this.server = tls.createServer({ key: this.options.tlsKey, cert: this.options.tlsCertificate, minVersion: 'TLSv1.3' }, (socket) => this.handleSession(socket))
        this.server.on('error', (error) => this.emit('error', error))
        await new Promise<void>((resolve, reject) => {
            const onError = (error: Error) => { this.server?.off('listening', onListening); reject(error) }
            const onListening = () => { this.server?.off('error', onError); resolve() }
            this.server?.once('error', onError)
            this.server?.once('listening', onListening)
            this.server?.listen(this.options.tlsPort ?? 0, this.options.tlsHost ?? '0.0.0.0')
        })
    }

    getTlsPort(): number {
        const address = this.server?.address()
        if (!address || typeof address === 'string') throw new Error('TLS server is not listening')
        return address.port
    }

    getState(): SnowDeviceState | undefined { return this.state && JSON.parse(JSON.stringify(this.state)) as SnowDeviceState }

    async startOperational(): Promise<void> {
        if (!this.state?.provisioned) throw new Error('device is not provisioned')
        const keys = decodeKeys(this.state.keys)
        if (keys[TOTW_RT_KEY_KM_GLOBAL] && keys[TOTW_RT_KEY_KM_LOCAL]) {
            this.node = new SigNetNode({ tuid: this.options.tuid, mfgCode: this.options.mfgCode, managerGlobalKey: keys[TOTW_RT_KEY_KM_GLOBAL], managerLocalKey: keys[TOTW_RT_KEY_KM_LOCAL], citizenKey: keys[TOTW_RT_KEY_KC] ?? Buffer.alloc(32) })
            await this.node.start()
        } else if (keys[TOTW_RT_KEY_KS]) {
            this.sender = new SigNetSender({ tuid: this.options.tuid, senderKey: keys[TOTW_RT_KEY_KS] })
            await this.sender.start()
        }
        this.server?.close()
        this.server = undefined
    }

    getNode(): SigNetNode | undefined { return this.node }
    getSender(): SigNetSender | undefined { return this.sender }

    async close(): Promise<void> {
        this.node?.close()
        this.sender?.close()
        this.snrpSocket.close()
        await new Promise<void>((resolve) => this.server ? this.server.close(() => resolve()) : resolve())
        this.server = undefined
    }

    private async startSNRPListener(): Promise<void> {
        this.snrpSocket.on('error', (error) => this.emit('error', error))
        this.snrpSocket.on('message', (message) => {
            try { void this.handleSNRP(parsePacket(message)) } catch (error) { this.emit('error', error instanceof Error ? error : new Error(String(error))) }
        })
        await new Promise<void>((resolve, reject) => {
            const onError = (error: Error) => { this.snrpSocket.off('listening', onListening); reject(error) }
            const onListening = () => { this.snrpSocket.off('error', onError); resolve() }
            this.snrpSocket.once('error', onError)
            this.snrpSocket.once('listening', onListening)
            this.snrpSocket.bind(SIGNET_UDP_PORT, '0.0.0.0')
        })
        this.snrpSocket.addMembership(MULTICAST_NODE_BEACON_IP)
    }

    private async handleSNRP(packet: ReturnType<typeof parsePacket>): Promise<void> {
        if (!packet.uri.endsWith('/snrp') || !this.state?.provisioned) return
        const wipe = packet.tlvs.find((tlv) => tlv.typeId === TOTW_RT_POM_WIPE)
        if (wipe && wipe.value.length === 78) {
            const target = wipe.value.subarray(0, 6)
            if (!target.equals(this.options.tuid)) return
            const pom = this.state.pomPublicKey && Buffer.from(this.state.pomPublicKey, 'base64')
            if (!pom || !verifyRawEcdsa(pom, Buffer.concat([target, wipe.value.subarray(6, 14)]), wipe.value.subarray(14))) return
            await this.resetProvisioning()
            this.emit('wiped')
            return
        }
        const reopen = packet.tlvs.find((tlv) => tlv.typeId === TOTW_RT_OTW_REOPEN)
        if (!reopen || (reopen.value.length !== 48 && reopen.value.length !== 80)) return
        const target = reopen.value.subarray(0, 6)
        if (!target.equals(this.options.tuid)) return
        const type = reopen.value[6]
        const timeout = reopen.value[7] || 60
        const nonce = reopen.value.subarray(8, 16)
        const signature = reopen.value.subarray(16)
        const keys = decodeKeys(this.state.keys)
        let valid = false
        if (type === 0 && keys[TOTW_RT_KEY_KM_LOCAL]) valid = verifyHmacOtwReopen({ tuid: target, managerLocalKey: keys[TOTW_RT_KEY_KM_LOCAL], timeoutSeconds: reopen.value[7]!, nonce, signature })
        else if (type === 1 && this.state.pomPublicKey) valid = verifyRawEcdsa(Buffer.from(this.state.pomPublicKey, 'base64'), otwReopenAuthorizationInput(target, 'ecdsa', reopen.value[7]!, nonce), signature)
        if (!valid) return
        await this.openTlsServer()
        setTimeout(() => this.server?.close(), timeout * 1000).unref()
    }

    private async resetProvisioning(): Promise<void> {
        this.node?.close(); this.sender?.close(); this.node = undefined; this.sender = undefined
        this.server?.close(); this.server = undefined
        this.state = await this.options.store.load(this.options.tuid, this.identity.getRawPublicKey())
        this.state.keys = {}
        delete this.state.scope
        delete this.state.pomPublicKey
        this.state.provisioned = false
        await this.options.store.save(this.state)
        await this.openTlsServer()
    }

    private handleSession(socket: tls.TLSSocket): void {
        socket.setMaxSendFragment(2048)
        const publicKey = Buffer.from(this.state?.publicKey ?? this.identity.getRawPublicKey().toString('base64'), 'base64')
        socket.write(encodeCoapTcpFrame(buildSnowNodePacket({ deviceTuid: this.options.tuid, mfgCode: this.options.mfgCode, tlvs: buildPublicKeyTlv(publicKey) })))
        let buffer = Buffer.alloc(0)
        socket.on('data', (chunk) => {
            buffer = Buffer.concat([buffer, Buffer.from(chunk)])
            while (true) {
                const frame = decodeCoapTcpFrame(buffer)
                if (!frame) return
                buffer = buffer.subarray(frame.bytesConsumed)
                try { this.handlePacket(socket, frame.packet) } catch (error) { this.emit('error', error instanceof Error ? error : new Error(String(error))); socket.destroy() }
            }
        })
    }

    private async handlePacket(socket: tls.TLSSocket, raw: Buffer): Promise<void> {
        const packet = parsePacket(raw)
        if (packet.options.securityMode !== SECURITY_MODE_UNPROVISIONED || packet.options.hmac.length !== 0 || !packet.uri.includes(`/manager/${Buffer.from(this.options.tuid).toString('hex').toUpperCase()}/0`)) return
        const pending = this.state ? { ...this.state, keys: { ...this.state.keys } } : await this.options.store.load(this.options.tuid, this.identity.getRawPublicKey())
        for (const tlv of packet.tlvs) {
            if (tlv.typeId === TOTW_RT_SCOPE) pending.scope = validateScope(tlv.value)
            else if (tlv.typeId === TOTW_RT_POM_PUBLIC_KEY) pending.pomPublicKey = Buffer.from(tlv.value).toString('base64')
            else if ([TOTW_RT_KEY_KS, TOTW_RT_KEY_KC, TOTW_RT_KEY_KM_GLOBAL, TOTW_RT_KEY_KM_LOCAL, TOTW_RT_KEY_K0].includes(tlv.typeId)) {
                if (tlv.value.length !== 32) throw new RangeError(`invalid key length for 0x${tlv.typeId.toString(16)}`)
                pending.keys[String(tlv.typeId)] = Buffer.from(tlv.value).toString('base64')
            } else if (tlv.typeId === 0x7003) this.emit('identify')
        }
        if (!isCompleteProvisioning(pending.keys, pending.scope)) return
        pending.provisioned = true
        await this.options.store.save(pending)
        this.state = pending
        this.emit('provisioned', pending)
        socket.end()
        if (this.options.autoStartOperational) await this.startOperational()
    }
}

function validateScope(value: Uint8Array): string {
    const scope = Buffer.from(value).toString('utf8')
    if (Buffer.byteLength(scope, 'utf8') < 1 || Buffer.byteLength(scope, 'utf8') > 32 || !/^[A-Za-z0-9._~-]+$/.test(scope)) throw new RangeError('invalid SNOW scope')
    return scope
}

function isCompleteProvisioning(keys: Record<string, string>, scope?: string): boolean {
    if (!scope) return false
    const has = (id: number) => typeof keys[String(id)] === 'string'
    return (has(TOTW_RT_KEY_KS) && has(TOTW_RT_KEY_KC)) || (has(TOTW_RT_KEY_KM_GLOBAL) && has(TOTW_RT_KEY_KM_LOCAL)) || has(TOTW_RT_KEY_K0)
}

function decodeKeys(keys: Record<string, string>): SnowDeviceKeys {
    const result: SnowDeviceKeys = {}
    const ids = [TOTW_RT_KEY_KS, TOTW_RT_KEY_KC, TOTW_RT_KEY_KM_GLOBAL, TOTW_RT_KEY_KM_LOCAL, TOTW_RT_KEY_K0] as const
    for (const id of ids) if (keys[String(id)]) result[id] = Buffer.from(keys[String(id)]!, 'base64')
    return result
}

export default SnowDevice
