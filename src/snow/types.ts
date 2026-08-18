import type { ParsedPacket } from '../core/types.js'

export type SnowDeviceRole = 'node' | 'sender' | 'manager' | 'visualiser'

export interface SnowDiscoveredDevice {
    tuid: Buffer
    ip: string
    port: number
    packet: ParsedPacket
    supportsSnow: boolean
}

export interface SnowControllerOptions {
    managerTuid: Uint8Array
    mfgCode: number
    listenAddress?: string
    port?: number
    interfaceAddress?: string
}

export interface SnowPacketArgs {
    managerTuid: Uint8Array
    mfgCode: number
    sessionId?: number
    seqNum?: number
    messageId?: number
    tlvs: Uint8Array
}

export interface SnowBeaconArgs {
    deviceTuid: Uint8Array
    mfgCode: number
    otwPort: number
    otwFlags?: number
    sessionId?: number
    seqNum?: number
    messageId?: number
}
