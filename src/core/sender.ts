import dgram from 'dgram'
import { EventEmitter } from 'events'
import { MAX_DMX_SLOTS, MAX_UNIVERSE, MIN_UNIVERSE, SIGNET_UDP_PORT } from './constants.js'
import { buildDMXPacket, calculateMulticastAddress, incrementSequence, shouldIncrementSession } from './send.js'

export type SigNetSenderOptions = {
    tuid: Uint8Array
    senderKey: Uint8Array
    mfgCode?: number
    endpoint?: number
    sessionId?: number
    bindAddress?: string
    bindPort?: number
    targetPort?: number
    defaultTargetIp?: string
    defaultFps?: number
    universeFps?: Record<number, number>
}

type UniverseState = {
    lastSentMs: number
    timer: NodeJS.Timeout | undefined
    pending: Uint8Array | undefined
    resolve: (() => void) | undefined
    reject: ((error: Error) => void) | undefined
}

export declare interface SigNetSender {
    on(event: 'error', listener: (error: Error) => void): this
}

export class SigNetSender extends EventEmitter {
    private readonly socket = dgram.createSocket('udp4')
    private readonly opts: Required<Pick<SigNetSenderOptions, 'mfgCode' | 'endpoint' | 'bindAddress' | 'bindPort' | 'targetPort' | 'defaultTargetIp'>> &
        SigNetSenderOptions
    private readonly universeFps = new Map<number, number>()
    private readonly states = new Map<number, UniverseState>()
    private bound = false
    private sequence = 1
    private messageId = 1
    private sessionId: number

    constructor(options: SigNetSenderOptions) {
        super()
        if (options.tuid.length !== 6) throw new RangeError('tuid must be 6 bytes')
        if (options.senderKey.length !== 32) throw new RangeError('senderKey must be 32 bytes')
        this.opts = {
            ...options,
            mfgCode: options.mfgCode ?? 0,
            endpoint: options.endpoint ?? 1,
            bindAddress: options.bindAddress ?? '0.0.0.0',
            bindPort: options.bindPort ?? 0,
            targetPort: options.targetPort ?? SIGNET_UDP_PORT,
            defaultTargetIp: options.defaultTargetIp ?? '',
        }
        if (this.opts.endpoint < 1) throw new RangeError('endpoint must be >= 1')
        this.sessionId = options.sessionId ?? SigNetSender.randomSessionId()
        for (const [universe, fps] of Object.entries(options.universeFps ?? {})) this.setUniverseFps(Number(universe), fps)
    }

    async start(): Promise<void> {
        if (this.bound) return
        this.socket.on('error', (error) => this.emit('error', error))
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
            this.socket.bind(this.opts.bindPort, this.opts.bindAddress)
        })
        this.bound = true
    }

    close(): void {
        for (const state of this.states.values()) if (state.timer) clearTimeout(state.timer)
        if (this.bound) this.socket.close()
        this.bound = false
    }

    getSessionId(): number {
        return this.sessionId
    }

    setUniverseFps(universe: number, fps?: number): void {
        SigNetSender.assertUniverse(universe)
        if (fps === undefined) {
            this.universeFps.delete(universe)
            return
        }
        if (!Number.isFinite(fps) || fps <= 0) throw new RangeError('fps must be > 0')
        this.universeFps.set(universe, fps)
    }

    sendDmx(dmx: Uint8Array, universe: number, targetIp?: string): Promise<void> {
        SigNetSender.assertUniverse(universe)
        if (dmx.length < 1 || dmx.length > MAX_DMX_SLOTS) throw new RangeError(`DMX length must be 1..${MAX_DMX_SLOTS}`)
        const fps = this.universeFps.get(universe) ?? this.opts.defaultFps
        return fps ? this.sendThrottled(Uint8Array.from(dmx), universe, targetIp, fps) : this.sendImmediate(dmx, universe, targetIp)
    }

    private async sendThrottled(dmx: Uint8Array, universe: number, targetIp: string | undefined, fps: number): Promise<void> {
        const interval = Math.max(1, Math.floor(1000 / fps))
        const state = this.states.get(universe) ?? { lastSentMs: 0, timer: undefined, pending: undefined, resolve: undefined, reject: undefined }
        this.states.set(universe, state)
        const elapsed = Date.now() - state.lastSentMs
        if (elapsed >= interval && !state.timer) {
            await this.sendImmediate(dmx, universe, targetIp)
            state.lastSentMs = Date.now()
            return
        }
        state.pending = dmx
        return new Promise<void>((resolve, reject) => {
            state.resolve = resolve
            state.reject = reject
            if (state.timer) return
            state.timer = setTimeout(
                async () => {
                    state.timer = undefined
                    const pending = state.pending
                    const done = state.resolve
                    const failed = state.reject
                    state.pending = undefined
                    state.resolve = undefined
                    state.reject = undefined
                    if (!pending) {
                        done?.()
                        return
                    }
                    try {
                        await this.sendImmediate(pending, universe, targetIp)
                        state.lastSentMs = Date.now()
                        done?.()
                    } catch (error) {
                        failed?.(error instanceof Error ? error : new Error(String(error)))
                    }
                },
                Math.max(0, interval - elapsed),
            )
        })
    }

    private sendImmediate(dmx: Uint8Array, universe: number, targetIp?: string): Promise<void> {
        const packet = buildDMXPacket({
            universe,
            dmxData: dmx,
            tuid: this.opts.tuid,
            endpoint: this.opts.endpoint,
            mfgCode: this.opts.mfgCode,
            sessionId: this.sessionId,
            seqNum: this.sequence,
            senderKey: this.opts.senderKey,
            messageId: this.messageId,
        })
        if (shouldIncrementSession(this.sequence)) {
            this.sequence = incrementSequence(this.sequence)
            this.sessionId = (this.sessionId + 1) >>> 0 || 1
        } else this.sequence = incrementSequence(this.sequence)
        this.messageId = this.messageId >= 0xffff ? 1 : this.messageId + 1
        return this.sendRaw(packet, targetIp ?? (this.opts.defaultTargetIp || calculateMulticastAddress(universe)))
    }

    private sendRaw(packet: Buffer, ip: string): Promise<void> {
        return new Promise((resolve, reject) => this.socket.send(packet, this.opts.targetPort, ip, (error) => (error ? reject(error) : resolve())))
    }

    private static randomSessionId(): number {
        return Math.floor(Math.random() * 0xffffffff) >>> 0 || 1
    }
    private static assertUniverse(universe: number): void {
        if (!Number.isInteger(universe) || universe < MIN_UNIVERSE || universe > MAX_UNIVERSE)
            throw new RangeError(`universe must be ${MIN_UNIVERSE}..${MAX_UNIVERSE}`)
    }
}

export default SigNetSender
