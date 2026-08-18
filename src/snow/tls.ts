import tls, { type ConnectionOptions } from 'node:tls'
import { EventEmitter } from 'node:events'
import { X509Certificate } from 'node:crypto'
import { SNOW_TLS_MAX_RECORD_SIZE } from '../core/constants.js'
import { TOTW_RT_PUBLIC_KEY } from '../core/constants.js'
import { parsePacket } from '../core/parse.js'

export interface SnowTlsClientOptions extends Omit<ConnectionOptions, 'port' | 'host'> {
    host: string
    port: number
    maxRecordSize?: number
}

export declare interface SnowTlsClient {
    on(event: 'packet', listener: (packet: Buffer) => void): this
    on(event: 'error', listener: (error: Error) => void): this
    on(event: 'close', listener: () => void): this
}

/** TLS transport for SNOW's CoAP-over-stream tunnel. */
export class SnowTlsClient extends EventEmitter {
    private readonly options: SnowTlsClientOptions
    private socket: tls.TLSSocket | undefined
    private receiveBuffer = Buffer.alloc(0)
    private applicationPublicKey?: Buffer

    constructor(options: SnowTlsClientOptions) {
        super()
        if (!Number.isInteger(options.port) || options.port < 1 || options.port > 65535) throw new RangeError('invalid TLS port')
        this.options = options
    }

    async connect(): Promise<void> {
        if (this.socket && !this.socket.destroyed) return
        const { host, port, maxRecordSize, ...tlsOptions } = this.options
        const socket = tls.connect({ ...tlsOptions, host, port, rejectUnauthorized: tlsOptions.rejectUnauthorized ?? false })
        this.socket = socket
        const fragmentSize = maxRecordSize ?? SNOW_TLS_MAX_RECORD_SIZE
        if (!Number.isInteger(fragmentSize) || fragmentSize < 512 || fragmentSize > 16384) throw new RangeError('invalid TLS record size')
        socket.setMaxSendFragment(fragmentSize)
        socket.on('data', (chunk) => this.consume(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)))
        socket.on('error', (error) => this.emit('error', error))
        socket.on('close', () => this.emit('close'))
        await new Promise<void>((resolve, reject) => {
            const onSecure = () => { socket.off('error', onError); resolve() }
            const onError = (error: Error) => { socket.off('secureConnect', onSecure); reject(error) }
            socket.once('secureConnect', onSecure)
            socket.once('error', onError)
        })
    }

    send(packet: Uint8Array): void {
        if (!this.socket || this.socket.destroyed) throw new Error('SNOW TLS session is not connected')
        this.socket.write(encodeCoapTcpFrame(packet))
    }

    exportKeyingMaterial(length: number, label: string): Buffer {
        if (!this.socket || this.socket.destroyed) throw new Error('SNOW TLS session is not connected')
        return this.socket.exportKeyingMaterial(length, label, Buffer.alloc(0))
    }

    getPeerPublicKey(): Buffer | undefined {
        const raw = this.socket?.getPeerCertificate(true).raw
        if (!raw) return undefined
        const certificate = new X509Certificate(raw)
        const jwk = certificate.publicKey.export({ format: 'jwk' })
        if (!('x' in jwk) || !('y' in jwk) || typeof jwk.x !== 'string' || typeof jwk.y !== 'string') return undefined
        return Buffer.concat([Buffer.from([0x04]), decodeBase64Url(jwk.x), decodeBase64Url(jwk.y)])
    }

    getApplicationPublicKey(): Buffer | undefined {
        return this.applicationPublicKey && Buffer.from(this.applicationPublicKey)
    }

    close(): void { this.socket?.end(); this.socket = undefined }

    async waitForClose(timeoutMs = 5000): Promise<void> {
        const socket = this.socket
        if (!socket || socket.destroyed) return
        await new Promise<void>((resolve, reject) => {
            const cleanup = () => { clearTimeout(timer); socket.off('close', onClose); socket.off('error', onError) }
            const onClose = () => { cleanup(); resolve() }
            const onError = (error: Error) => { cleanup(); reject(error) }
            const timer = setTimeout(() => { cleanup(); reject(new Error('SNOW TLS peer did not acknowledge and close the session')) }, timeoutMs)
            socket.once('close', onClose)
            socket.once('error', onError)
        })
    }

    private consume(chunk: Buffer): void {
        this.receiveBuffer = Buffer.concat([this.receiveBuffer, chunk])
        while (true) {
            const frame = decodeCoapTcpFrame(this.receiveBuffer)
            if (!frame) return
            this.receiveBuffer = this.receiveBuffer.subarray(frame.bytesConsumed)
            try {
                const packet = parsePacket(frame.packet)
                const key = packet.tlvs.find((tlv) => tlv.typeId === TOTW_RT_PUBLIC_KEY)
                if (key && key.value.length > 0) this.applicationPublicKey = Buffer.from(key.value)
            } catch {
                // The packet event remains available to callers; malformed data is rejected there.
            }
            this.emit('packet', frame.packet)
        }
    }
}

export function encodeCoapTcpFrame(packet: Uint8Array): Buffer {
    if (packet.length < 4) throw new RangeError('CoAP packet too small')
    const tokenLength = packet[0]! & 0x0f
    if (tokenLength > 8 || packet.length < 4 + tokenLength) throw new RangeError('invalid CoAP token')
    const body = Buffer.concat([Buffer.from([packet[1]!]), Buffer.from(packet.subarray(4))])
    const length = body.length
    const encoded = encodeLength(length)
    return Buffer.concat([Buffer.from([(encoded.nibble << 4) | tokenLength]), encoded.ext, body])
}

export function decodeCoapTcpFrame(buffer: Buffer): { packet: Buffer; bytesConsumed: number } | undefined {
    if (buffer.length < 2) return undefined
    const first = buffer[0]!
    const tokenLength = first & 0x0f
    if (tokenLength > 8) throw new RangeError('invalid CoAP token')
    const decoded = decodeLength(first >> 4, buffer, 1)
    if (!decoded || buffer.length < decoded.headerBytes + decoded.length) return undefined
    const start = decoded.headerBytes
    const code = buffer[start]!
    const body = buffer.subarray(start + 1, start + decoded.length)
    if (body.length < tokenLength) throw new RangeError('truncated CoAP token')
    const packet = Buffer.alloc(4 + body.length)
    packet[0] = 0x50 | tokenLength
    packet[1] = code
    packet.writeUInt16BE(0, 2)
    body.copy(packet, 4)
    return { packet, bytesConsumed: decoded.headerBytes + decoded.length }
}

function encodeLength(length: number): { nibble: number; ext: Buffer } {
    if (length <= 12) return { nibble: length, ext: Buffer.alloc(0) }
    if (length <= 268) return { nibble: 13, ext: Buffer.from([length - 13]) }
    if (length <= 65804) { const ext = Buffer.alloc(2); ext.writeUInt16BE(length - 269); return { nibble: 14, ext } }
    const ext = Buffer.alloc(4); ext.writeUInt32BE(length - 65805); return { nibble: 15, ext }
}

function decodeLength(nibble: number, buffer: Buffer, offset: number): { length: number; headerBytes: number } | undefined {
    if (nibble <= 12) return { length: nibble, headerBytes: offset }
    if (nibble === 13) return buffer.length < offset + 1 ? undefined : { length: buffer[offset]! + 13, headerBytes: offset + 1 }
    if (nibble === 14) return buffer.length < offset + 2 ? undefined : { length: buffer.readUInt16BE(offset) + 269, headerBytes: offset + 2 }
    return buffer.length < offset + 4 ? undefined : { length: buffer.readUInt32BE(offset) + 65805, headerBytes: offset + 4 }
}

function decodeBase64Url(value: string): Buffer {
    return Buffer.from(value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - (value.length % 4)) % 4), 'base64')
}

export default SnowTlsClient
