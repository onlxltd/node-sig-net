import dgram from 'dgram'
import { EventEmitter } from 'events'
import { MULTICAST_MAX_INDEX, SIGNET_SUCCESS, SIGNET_UDP_PORT, TID_LEVEL, TID_SYNC } from './constants.js'
import { parsePacket } from './parse.js'
import { verifyPacketHmac } from './security.js'

export type SigNetLevelMessage = {
    fromIp: string
    fromPort: number
    universe: number
    endpoint: number
    sequence: number
    sessionId: number
    dmx: Buffer
    packet: ReturnType<typeof parsePacket>
}
export type SigNetReceiverOptions = {
    listenAddress?: string
    port?: number
    interfaceAddress?: string
    senderKey?: Uint8Array
    senderKeys?: Map<string, Uint8Array> | Record<string, Uint8Array>
    verifyHmac?: boolean
    universes?: number[]
}

export declare interface SigNetReceiver {
    on(event: 'level', listener: (message: SigNetLevelMessage) => void): this
    on(event: 'sync', listener: (message: { fromIp: string; packet: ReturnType<typeof parsePacket> }) => void): this
    on(event: 'packet', listener: (packet: ReturnType<typeof parsePacket>, fromIp: string) => void): this
    on(event: 'error', listener: (error: Error) => void): this
}

export class SigNetReceiver extends EventEmitter {
    private readonly socket = dgram.createSocket({ type: 'udp4', reuseAddr: true })
    private readonly options: Required<Pick<SigNetReceiverOptions, 'listenAddress' | 'port' | 'verifyHmac'>> & SigNetReceiverOptions
    private started = false

    constructor(options: SigNetReceiverOptions = {}) {
        super()
        this.options = {
            ...options,
            listenAddress: options.listenAddress ?? '0.0.0.0',
            port: options.port ?? SIGNET_UDP_PORT,
            verifyHmac: options.verifyHmac ?? true,
        }
        if (options.senderKey && options.senderKey.length !== 32) throw new RangeError('senderKey must be 32 bytes')
    }

    async start(): Promise<void> {
        if (this.started) return
        this.socket.on('error', (error) => this.emit('error', error))
        this.socket.on('message', (message, remote) => {
            try {
                this.handlePacket(message, remote.address, remote.port)
            } catch (error) {
                this.emit('error', error instanceof Error ? error : new Error(String(error)))
            }
        })
        await new Promise<void>((resolve, reject) => {
            const onError = (error: Error) => {
                this.socket.off('listening', onListening)
                reject(error)
            }
            const onListening = () => {
                this.socket.off('error', onError)
                resolve()
            }
            this.socket.once('error', onError)
            this.socket.once('listening', onListening)
            this.socket.bind(this.options.port, this.options.listenAddress)
        })
        const indices =
            this.options.universes?.map((universe) => ((universe - 1) % MULTICAST_MAX_INDEX) + 1) ??
            Array.from({ length: MULTICAST_MAX_INDEX }, (_, index) => index + 1)
        for (const index of new Set(indices)) this.socket.addMembership(`239.254.0.${index}`, this.options.interfaceAddress)
        this.started = true
    }

    close(): void {
        if (this.started) this.socket.close()
        this.started = false
    }

    private handlePacket(message: Buffer, fromIp: string, fromPort: number): void {
        const packet = parsePacket(message)
        const segments = packet.uri.split('/')
        if (segments[4] === 'level') {
            const universe = Number(segments[5])
            if (!Number.isInteger(universe)) return
            if (this.options.universes && !this.options.universes.includes(universe)) return
            const key = this.keyFor(packet.options.senderId.toString('hex'))
            if (this.options.verifyHmac && (!key || verifyPacketHmac(packet.uri, packet.options, packet.payload, key) !== SIGNET_SUCCESS)) return
            const level = packet.tlvs.find((tlv) => tlv.typeId === TID_LEVEL)
            if (!level) return
            this.emit('packet', packet, fromIp)
            this.emit('level', {
                fromIp,
                fromPort,
                universe,
                endpoint: packet.options.senderId.readUInt16BE(6),
                sequence: packet.options.seqNum,
                sessionId: packet.options.sessionId,
                dmx: level.value,
                packet,
            })
        } else if (packet.tlvs.some((tlv) => tlv.typeId === TID_SYNC)) this.emit('sync', { fromIp, packet })
    }

    private keyFor(senderId: string): Uint8Array | undefined {
        if (this.options.senderKey) return this.options.senderKey
        if (this.options.senderKeys instanceof Map) return this.options.senderKeys.get(senderId)
        return this.options.senderKeys?.[senderId]
    }
}

export { SigNetReceiver as SignNetReceiver }
export default SigNetReceiver
