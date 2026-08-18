import dgram from 'node:dgram'
import { EventEmitter } from 'node:events'
import { randomBytes } from 'node:crypto'
import {
    MULTICAST_MANAGER_POLL_IP,
    MULTICAST_MANAGER_SEND_IP,
    MULTICAST_NODE_SEND_IP,
    SIGNET_SUCCESS,
    SIGNET_UDP_PORT,
    TID_POLL,
    TID_POLL_REPLY,
    TID_SET_REPLY,
    TUID_LENGTH,
} from './constants.js'
import { deriveCitizenKey, deriveManagerGlobalKey, deriveManagerLocalKey } from './crypto.js'
import { parsePacket } from './parse.js'
import { verifyPacketHmac } from './security.js'
import { buildAnnouncePacket, buildNodeResponsePacket } from './send.js'
import { buildPayload, parseTidPoll } from './tlv.js'

export type SigNetNodeOptions = {
    tuid: Uint8Array
    mfgCode: number
    productVariantId?: number
    firmwareVersionId?: number
    firmwareVersionString?: string
    protocolVersion?: number
    roleCapabilityBits?: number
    k0?: Uint8Array
    citizenKey?: Uint8Array
    managerGlobalKey?: Uint8Array
    managerLocalKey?: Uint8Array
    values?: Map<number, Uint8Array> | Record<number, Uint8Array>
    listenAddress?: string
    port?: number
    interfaceAddress?: string
    sessionId?: number
}

export declare interface SigNetNode {
    on(event: 'announce', listener: (packet: Buffer) => void): this
    on(event: 'set', listener: (event: { typeId: number; value: Buffer }) => void): this
    on(event: 'error', listener: (error: Error) => void): this
}

/** Stateful manager/poll responder following the upstream SDK node flow. */
export class SigNetNode extends EventEmitter {
    private readonly socket = dgram.createSocket({ type: 'udp4', reuseAddr: true })
    private readonly tuid: Buffer
    private readonly options: Required<Pick<SigNetNodeOptions, 'listenAddress' | 'port' | 'productVariantId' | 'firmwareVersionId' | 'firmwareVersionString' | 'protocolVersion' | 'roleCapabilityBits'>> & SigNetNodeOptions
    private readonly values = new Map<number, Buffer>()
    private readonly citizenKey: Buffer
    private readonly managerGlobalKey: Buffer
    private readonly managerLocalKey: Buffer
    private started = false
    private messageId = 1
    private sequence = 1
    private readonly sessionId: number
    private changeCount = 0

    constructor(options: SigNetNodeOptions) {
        super()
        if (options.tuid.length !== TUID_LENGTH) throw new RangeError('tuid must be 6 bytes')
        this.tuid = Buffer.from(options.tuid)
        const k0 = options.k0
        this.citizenKey = Buffer.from(options.citizenKey ?? (k0 ? deriveCitizenKey(k0) : Buffer.alloc(0)))
        this.managerGlobalKey = Buffer.from(options.managerGlobalKey ?? (k0 ? deriveManagerGlobalKey(k0) : Buffer.alloc(0)))
        this.managerLocalKey = Buffer.from(options.managerLocalKey ?? (k0 ? deriveManagerLocalKey(k0, options.tuid) : Buffer.alloc(0)))
        if (this.citizenKey.length !== 32 || this.managerGlobalKey.length !== 32 || this.managerLocalKey.length !== 32) throw new RangeError('node keys must be supplied or derivable from a 32-byte k0')
        this.options = {
            ...options,
            listenAddress: options.listenAddress ?? '0.0.0.0',
            port: options.port ?? SIGNET_UDP_PORT,
            productVariantId: options.productVariantId ?? 0,
            firmwareVersionId: options.firmwareVersionId ?? 0,
            firmwareVersionString: options.firmwareVersionString ?? '',
            protocolVersion: options.protocolVersion ?? 1,
            roleCapabilityBits: options.roleCapabilityBits ?? 1,
        }
        this.sessionId = options.sessionId ?? (randomUint32() || 1)
        if (options.values instanceof Map) for (const [typeId, value] of options.values) this.values.set(typeId, Buffer.from(value))
        else for (const [typeId, value] of Object.entries(options.values ?? {})) this.values.set(Number(typeId), Buffer.from(value))
    }

    async start(): Promise<void> {
        if (this.started) return
        this.socket.on('error', (error) => this.emit('error', error))
        this.socket.on('message', (message, remote) => {
            try { this.handlePacket(message, remote.address) } catch (error) { this.emit('error', error instanceof Error ? error : new Error(String(error))) }
        })
        await new Promise<void>((resolve, reject) => {
            const onError = (error: Error) => { this.socket.off('listening', onListening); reject(error) }
            const onListening = () => { this.socket.off('error', onError); resolve() }
            this.socket.once('error', onError)
            this.socket.once('listening', onListening)
            this.socket.bind(this.options.port, this.options.listenAddress)
        })
        this.socket.addMembership(MULTICAST_MANAGER_POLL_IP, this.options.interfaceAddress)
        this.socket.addMembership(MULTICAST_MANAGER_SEND_IP, this.options.interfaceAddress)
        this.started = true
    }

    close(): void {
        if (this.started) this.socket.close()
        this.started = false
    }

    getChangeCount(): number { return this.changeCount }

    getValue(typeId: number): Buffer | undefined {
        const value = this.values.get(typeId)
        return value && Buffer.from(value)
    }

    private handlePacket(message: Buffer, fromIp: string): void {
        const packet = parsePacket(message)
        const segments = packet.uri.split('/')
        if (segments[4] === 'poll') {
            if (verifyPacketHmac(packet.uri, packet.options, packet.payload, this.managerGlobalKey) !== SIGNET_SUCCESS) return
            const poll = packet.tlvs.find((tlv) => tlv.typeId === TID_POLL)
            if (!poll) return
            const request = parseTidPoll(poll.value)
            if (Buffer.compare(this.tuid, request.tuidLo) < 0 || Buffer.compare(this.tuid, request.tuidHi) > 0) return
            if (request.targetEndpoint !== 0 && request.targetEndpoint !== 0xffff) return
            const announce = buildAnnouncePacket({
                tuid: this.tuid,
                mfgCode: this.options.mfgCode,
                productVariantId: this.options.productVariantId,
                firmwareVersionId: this.options.firmwareVersionId,
                firmwareVersionString: this.options.firmwareVersionString,
                protocolVersion: this.options.protocolVersion,
                roleCapabilityBits: this.options.roleCapabilityBits,
                changeCount: this.changeCount,
                sessionId: this.sessionId,
                seqNum: this.nextSequence(),
                citizenKey: this.citizenKey,
                messageId: this.nextMessageId(),
            })
            this.send(announce, MULTICAST_NODE_SEND_IP)
            this.emit('announce', announce)
        } else if (segments[4] === 'manager' && segments[5]?.toUpperCase() === Buffer.from(this.tuid).toString('hex').toUpperCase()) {
            if (verifyPacketHmac(packet.uri, packet.options, packet.payload, this.managerLocalKey) !== SIGNET_SUCCESS) return
            this.handleManagerPayload(packet, Number(segments[6]), fromIp)
        }
    }

    private handleManagerPayload(packet: ReturnType<typeof parsePacket>, endpoint: number, _fromIp: string): void {
        const response: { typeId: number; value: Buffer }[] = []
        const changed: number[] = []
        for (const tlv of packet.tlvs) {
            if (tlv.typeId === TID_SET_REPLY || tlv.typeId === TID_POLL_REPLY) continue
            if (tlv.length === 0) {
                const value = this.values.get(tlv.typeId)
                if (value?.length) response.push({ typeId: tlv.typeId, value })
                continue
            }
            const previous = this.values.get(tlv.typeId)
            const value = Buffer.from(tlv.value)
            this.values.set(tlv.typeId, value)
            if (!previous || !previous.equals(value)) { changed.push(tlv.typeId); this.emit('set', { typeId: tlv.typeId, value }) }
        }
        if (changed.length) this.changeCount = (this.changeCount + 1) & 0xffff
        if (response.length || changed.length) {
            for (const typeId of changed) response.push({ typeId, value: this.values.get(typeId)! })
            const payload = buildPayload([...response, { typeId: TID_SET_REPLY, value: Buffer.from([0, this.changeCount >>> 8, this.changeCount & 0xff]) }])
            const reply = buildNodeResponsePacket({ tuid: this.tuid, endpoint: Number.isInteger(endpoint) ? endpoint : 0, sessionId: this.sessionId, seqNum: this.nextSequence(), citizenKey: this.citizenKey, messageId: this.nextMessageId(), payload })
            this.send(reply, MULTICAST_NODE_SEND_IP)
        }
    }

    private send(packet: Buffer, address: string): void { this.socket.setMulticastTTL(32); this.socket.send(packet, this.options.port, address) }
    private nextMessageId(): number { this.messageId = this.messageId >= 0xffff ? 1 : this.messageId + 1; return this.messageId }
    private nextSequence(): number { const current = this.sequence; this.sequence = this.sequence >= 0xffffffff ? 1 : this.sequence + 1; return current }
}

function randomUint32(): number { return randomBytes(4).readUInt32BE(0) }

export default SigNetNode
