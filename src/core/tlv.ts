import { PacketBuffer } from './buffer.js'
import {
    MAX_DMX_SLOTS,
    QUERY_EXTENDED,
    SIGNET_ERROR_INVALID_ARG,
    SIGNET_SUCCESS,
    TID_LEVEL,
    TID_POLL,
    TID_POLL_REPLY,
    TID_PRIORITY,
    TID_RT_ENDPOINT_COUNT,
    TID_RT_MULT_OVERRIDE,
    TID_RT_PROTOCOL_VERSION,
    TID_RT_ROLE_CAPABILITY,
    TID_SYNC,
    TUID_LENGTH,
} from './constants.js'
import type { TLVBlock } from './types.js'

//==============================================================================
// Sig-Net Protocol Framework - TLV Payload Construction Implementation
//==============================================================================
// Upstream description:
// TLV encoding for Sig-Net application payloads. Supports TID_LEVEL,
// TID_PRIORITY, TID_SYNC, poll, and startup announce payloads with network byte
// order (big-endian) encoding.
//==============================================================================

//------------------------------------------------------------------------------
// Encode Generic TLV Block
//------------------------------------------------------------------------------
export function encodeTlv(buffer: PacketBuffer, typeId: number, value: Uint8Array = Buffer.alloc(0)): number {
    let result = buffer.writeUInt16(typeId)
    if (result !== SIGNET_SUCCESS) return result
    result = buffer.writeUInt16(value.length)
    if (result !== SIGNET_SUCCESS) return result
    return value.length ? buffer.writeBytes(value) : SIGNET_SUCCESS
}

//------------------------------------------------------------------------------
// Encode TID_LEVEL (DMX Level Data)
//------------------------------------------------------------------------------
export function encodeTidLevel(buffer: PacketBuffer, dmxData: Uint8Array): number {
    if (!dmxData || dmxData.length < 1 || dmxData.length > MAX_DMX_SLOTS) return SIGNET_ERROR_INVALID_ARG
    return encodeTlv(buffer, TID_LEVEL, dmxData)
}

//------------------------------------------------------------------------------
// Encode TID_PRIORITY (Priority Data)
//------------------------------------------------------------------------------
export function encodeTidPriority(buffer: PacketBuffer, priorityData: Uint8Array): number {
    if (!priorityData || priorityData.length < 1 || priorityData.length > MAX_DMX_SLOTS) return SIGNET_ERROR_INVALID_ARG
    return encodeTlv(buffer, TID_PRIORITY, priorityData)
}

//------------------------------------------------------------------------------
// Encode TID_SYNC (Synchronization Trigger)
//------------------------------------------------------------------------------
export function encodeTidSync(buffer: PacketBuffer): number {
    return encodeTlv(buffer, TID_SYNC)
}

//------------------------------------------------------------------------------
// Encode TID_POLL (Manager poll request)
//------------------------------------------------------------------------------
export function encodeTidPoll(
    buffer: PacketBuffer,
    managerTuid: Uint8Array,
    mfgCode: number,
    productVariantId: number,
    tuidLo: Uint8Array,
    tuidHi: Uint8Array,
    targetEndpoint: number,
    queryLevel: number,
): number {
    if (managerTuid.length !== TUID_LENGTH || tuidLo.length !== TUID_LENGTH || tuidHi.length !== TUID_LENGTH || queryLevel > QUERY_EXTENDED)
        return SIGNET_ERROR_INVALID_ARG
    const value = Buffer.alloc(25)
    Buffer.from(managerTuid).copy(value, 0)
    value.writeUInt32BE(((mfgCode & 0xffff) << 16) | (productVariantId & 0xffff), 6)
    Buffer.from(tuidLo).copy(value, 10)
    Buffer.from(tuidHi).copy(value, 16)
    value.writeUInt16BE(targetEndpoint & 0xffff, 22)
    value[24] = queryLevel
    return encodeTlv(buffer, TID_POLL, value)
}

//------------------------------------------------------------------------------
// Encode TID_POLL_REPLY (Startup Announce)
//------------------------------------------------------------------------------
export function encodeTidPollReply(buffer: PacketBuffer, tuid: Uint8Array, mfgCode: number, productVariantId: number, changeCount: number): number {
    if (tuid.length !== TUID_LENGTH) return SIGNET_ERROR_INVALID_ARG
    const value = Buffer.alloc(12)
    Buffer.from(tuid).copy(value, 0)
    value.writeUInt32BE(((mfgCode & 0xffff) << 16) | (productVariantId & 0xffff), 6)
    value.writeUInt16BE(changeCount & 0xffff, 10)
    return encodeTlv(buffer, TID_POLL_REPLY, value)
}

//------------------------------------------------------------------------------
// Build DMX Payload (TID_LEVEL)
//------------------------------------------------------------------------------
export function buildDmxLevelPayload(dmxData: Uint8Array): Buffer {
    const payload = new PacketBuffer()
    const result = encodeTidLevel(payload, dmxData)
    if (result !== SIGNET_SUCCESS) throw new RangeError('invalid DMX data')
    return payload.toBuffer()
}

//------------------------------------------------------------------------------
// Build Poll Payload (single TID_POLL TLV)
//------------------------------------------------------------------------------
export function buildPollPayload(
    managerTuid: Uint8Array,
    mfgCode: number,
    productVariantId: number,
    tuidLo: Uint8Array,
    tuidHi: Uint8Array,
    targetEndpoint: number,
    queryLevel: number,
): Buffer {
    const payload = new PacketBuffer()
    const result = encodeTidPoll(payload, managerTuid, mfgCode, productVariantId, tuidLo, tuidHi, targetEndpoint, queryLevel)
    if (result !== SIGNET_SUCCESS) throw new RangeError('invalid poll payload')
    return payload.toBuffer()
}

//------------------------------------------------------------------------------
// Build Startup Announce Payload (Section 10.2.5)
//------------------------------------------------------------------------------
export function buildStartupAnnouncePayload(args: {
    tuid: Uint8Array
    mfgCode: number
    productVariantId: number
    firmwareVersionId: number
    firmwareVersionString: string
    protocolVersion: number
    roleCapabilityBits: number
    changeCount: number
}): Buffer {
    const payload = new PacketBuffer()
    let result = encodeTidPollReply(payload, args.tuid, args.mfgCode, args.productVariantId, args.changeCount)
    if (result !== SIGNET_SUCCESS) throw new RangeError('invalid announce payload')
    result = encodeTlv(payload, TID_RT_PROTOCOL_VERSION, Buffer.from([args.protocolVersion & 0xff]))
    if (result !== SIGNET_SUCCESS) throw new RangeError('invalid announce payload')
    const roleCapability = Buffer.alloc(4)
    roleCapability.writeUInt32BE(args.roleCapabilityBits >>> 0, 0)
    result = encodeTlv(payload, TID_RT_ROLE_CAPABILITY, roleCapability)
    if (result !== SIGNET_SUCCESS) throw new RangeError('invalid announce payload')
    result = encodeTlv(payload, TID_RT_ENDPOINT_COUNT, Buffer.from([0x00, 0x01]))
    if (result !== SIGNET_SUCCESS) throw new RangeError('invalid announce payload')
    result = encodeTlv(payload, TID_RT_MULT_OVERRIDE, Buffer.from([0x00]))
    if (result !== SIGNET_SUCCESS) throw new RangeError('invalid announce payload')
    return payload.toBuffer()
}

//------------------------------------------------------------------------------
// Parse TLV Blocks
//------------------------------------------------------------------------------
export function parseTlvs(payload: Uint8Array): TLVBlock[] {
    const tlvs: TLVBlock[] = []
    let pos = 0
    while (pos < payload.length) {
        if (pos + 4 > payload.length) throw new RangeError('truncated TLV')
        const typeId = (payload[pos]! << 8) | payload[pos + 1]!
        const length = (payload[pos + 2]! << 8) | payload[pos + 3]!
        pos += 4
        if (pos + length > payload.length) throw new RangeError('truncated TLV value')
        tlvs.push({ typeId, length, value: Buffer.from(payload.subarray(pos, pos + length)) })
        pos += length
    }
    return tlvs
}
