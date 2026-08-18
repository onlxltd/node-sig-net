import dgram from 'dgram'
import { EventEmitter } from 'events'
import { MULTICAST_NODE_BEACON_IP, SIGNET_UDP_PORT, TID_RT_OTW_CAPABILITY } from '../core/constants.js'
import { parsePacket } from '../core/parse.js'
import type { SnowControllerOptions, SnowDiscoveredDevice } from './types.js'

export declare interface SnowController {
    on(event: 'deviceDiscovered', listener: (device: SnowDiscoveredDevice) => void): this
    on(event: 'packet', listener: (packet: ReturnType<typeof parsePacket>, fromIp: string) => void): this
    on(event: 'error', listener: (error: Error) => void): this
}

/** Optional SNOW discovery controller. TLS provisioning will build on this lifecycle. */
export class SnowController extends EventEmitter {
    private readonly socket = dgram.createSocket({ type: 'udp4', reuseAddr: true })
    private readonly options: Required<Pick<SnowControllerOptions, 'listenAddress' | 'port'>> & SnowControllerOptions
    private started = false

    constructor(options: SnowControllerOptions) {
        super()
        if (options.managerTuid.length !== 6) throw new RangeError('managerTuid must be 6 bytes')
        this.options = { ...options, listenAddress: options.listenAddress ?? '0.0.0.0', port: options.port ?? SIGNET_UDP_PORT }
    }

    async start(): Promise<void> {
        if (this.started) return
        this.socket.on('error', (error) => this.emit('error', error))
        this.socket.on('message', (message, remote) => {
            try {
                const packet = parsePacket(message)
                this.emit('packet', packet, remote.address)
                const tuid = extractTuid(packet.uri)
                if (!tuid) return
                this.emit('deviceDiscovered', {
                    tuid,
                    ip: remote.address,
                    port: remote.port,
                    packet,
                    supportsSnow: packet.tlvs.some((tlv) => tlv.typeId === TID_RT_OTW_CAPABILITY),
                } satisfies SnowDiscoveredDevice)
            } catch {
                // Discovery is intentionally best-effort; malformed multicast is ignored.
            }
        })
        await new Promise<void>((resolve, reject) => {
            const onError = (error: Error) => { this.socket.off('listening', onListening); reject(error) }
            const onListening = () => { this.socket.off('error', onError); resolve() }
            this.socket.once('error', onError)
            this.socket.once('listening', onListening)
            this.socket.bind(this.options.port, this.options.listenAddress)
        })
        this.socket.addMembership(MULTICAST_NODE_BEACON_IP, this.options.interfaceAddress)
        this.started = true
    }

    close(): void {
        if (this.started) this.socket.close()
        this.started = false
    }
}

function extractTuid(uri: string): Buffer | undefined {
    const match = uri.match(/\/(?:node|node_beacon)\/([0-9a-fA-F]{12})(?:\/|$)/)
    return match ? Buffer.from(match[1]!, 'hex') : undefined
}
