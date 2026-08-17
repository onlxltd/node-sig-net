import { MAX_UDP_PAYLOAD, SIGNET_ERROR_BUFFER_FULL, SIGNET_SUCCESS } from './constants.js'

//==============================================================================
// Sig-Net Protocol Framework - Packet Buffer
//==============================================================================
// TypeScript counterpart of the upstream PacketBuffer helper. It keeps packet
// construction bounded to MAX_UDP_PAYLOAD and writes multibyte values in network
// byte order (big-endian), matching the C++ SDK behavior.
//==============================================================================

export class PacketBuffer {
    private readonly chunks: number[] = []
    constructor(public readonly capacity = MAX_UDP_PAYLOAD) {}

    reset(): void {
        this.chunks.length = 0
    }

    get size(): number {
        return this.chunks.length
    }

    writeByte(value: number): number {
        if (this.size + 1 > this.capacity) return SIGNET_ERROR_BUFFER_FULL
        this.chunks.push(value & 0xff)
        return SIGNET_SUCCESS
    }

    writeUInt16(value: number): number {
        if (this.size + 2 > this.capacity) return SIGNET_ERROR_BUFFER_FULL
        this.chunks.push((value >>> 8) & 0xff, value & 0xff)
        return SIGNET_SUCCESS
    }

    writeUInt32(value: number): number {
        if (this.size + 4 > this.capacity) return SIGNET_ERROR_BUFFER_FULL
        this.chunks.push((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff)
        return SIGNET_SUCCESS
    }

    writeBytes(data: Uint8Array): number {
        if (this.size + data.length > this.capacity) return SIGNET_ERROR_BUFFER_FULL
        for (const byte of data) this.chunks.push(byte)
        return SIGNET_SUCCESS
    }

    toBuffer(): Buffer {
        return Buffer.from(this.chunks)
    }
}

export function ok(result: number): boolean {
    return result === SIGNET_SUCCESS
}
