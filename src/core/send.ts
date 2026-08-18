import dgram from 'dgram'
import { PacketBuffer } from './buffer.js'
import {
    COAP_OPTION_URI_PATH,
    COAP_PAYLOAD_MARKER,
    MAX_DMX_SLOTS,
    MAX_UNIVERSE,
    MIN_UNIVERSE,
    MULTICAST_TTL,
    SIGNET_ERROR_INVALID_ARG,
    SIGNET_ERROR_NETWORK,
    SIGNET_OPTION_SEQ_NUM,
    SIGNET_SUCCESS,
    SIGNET_UDP_PORT,
    TUID_LENGTH,
    SIGNET_URI_NODE,
    SIGNET_URI_NODE_LOST,
    SIGNET_URI_MANAGER,
    SIGNET_URI_POLL,
    SIGNET_URI_PRIORITY,
    SIGNET_URI_PREFIX,
    SIGNET_URI_SYNC,
    SIGNET_URI_TIMECODE,
    SIGNET_URI_VERSION,
} from './constants.js'
import { buildCoapHeader, buildUriPathOptions, buildUriString, encodeCoapOption, getUriScope } from './coap.js'
import { tuidToHexString } from './crypto.js'
import { buildDmxLevelPayload, buildPayload, buildPollPayload, buildPriorityPayload, buildStartupAnnouncePayload, buildSyncPayload, encodeTidTimecode } from './tlv.js'
import { buildSigNetOptionsWithoutHmac, calculateAndEncodeHmac, createSigNetOptions } from './security.js'

//==============================================================================
// Sig-Net Protocol Framework - Packet Assembly Implementation
//==============================================================================
// Upstream description:
// High-level packet assembly orchestrating CoAP, security, HMAC, and TLV
// components. Multicast address calculation and sequence number management for
// Sig-Net transmitter applications.
//==============================================================================

export interface BuildDMXPacketArgs {
    universe: number
    dmxData: Uint8Array
    tuid: Uint8Array
    endpoint: number
    mfgCode: number
    sessionId: number
    seqNum: number
    senderKey: Uint8Array
    messageId: number
}

//------------------------------------------------------------------------------
// Calculate Multicast Address (String Format)
//------------------------------------------------------------------------------
export function calculateMulticastAddress(universe: number): string {
    if (universe < MIN_UNIVERSE || universe > MAX_UNIVERSE) throw new RangeError('invalid universe')
    const index = ((universe - 1) % 109) + 1
    return `239.254.0.${index}`
}

//------------------------------------------------------------------------------
// Get Multicast IP Octets (for direct socket API use)
//------------------------------------------------------------------------------
export function getMulticastOctets(universe: number): [number, number, number, number] {
    if (universe < MIN_UNIVERSE || universe > MAX_UNIVERSE) throw new RangeError('invalid universe')
    return [239, 254, 0, ((universe - 1) % 109) + 1]
}

//------------------------------------------------------------------------------
// Sequence Number Management
//------------------------------------------------------------------------------
export function incrementSequence(seqNum: number): number {
    return seqNum >= 0xffffffff ? 1 : (seqNum + 1) >>> 0
}

export function shouldIncrementSession(seqNum: number): boolean {
    return seqNum >= 0xffffffff
}

//------------------------------------------------------------------------------
// Build Complete DMX Packet
//------------------------------------------------------------------------------
export function buildDMXPacket(args: BuildDMXPacketArgs): Buffer {
    if (!args.dmxData || !args.tuid || !args.senderKey) throw new RangeError('missing packet input')
    if (args.universe < MIN_UNIVERSE || args.universe > MAX_UNIVERSE) throw new RangeError('invalid universe')
    if (args.dmxData.length < 1 || args.dmxData.length > MAX_DMX_SLOTS) throw new RangeError('invalid DMX slot count')
    if (args.endpoint === 0) throw new RangeError('senders must use endpoint >= 1')

    const buffer = new PacketBuffer()
    must(buildCoapHeader(buffer, args.messageId))
    must(buildUriPathOptions(buffer, args.universe))
    const options = createSigNetOptions(args)
    must(buildSigNetOptionsWithoutHmac(buffer, options, COAP_OPTION_URI_PATH))
    const payload = buildDmxLevelPayload(args.dmxData)
    must(finalizePacketWithHmacAndPayload(buffer, buildUriString(args.universe), options, payload, args.senderKey))
    return buffer.toBuffer()
}

export function buildPriorityPacket(args: Omit<BuildDMXPacketArgs, 'dmxData'> & { priorityData: Uint8Array }): Buffer {
    return buildDataPacket({ ...args, payload: buildPriorityPayload(args.priorityData), uriSegments: [SIGNET_URI_PREFIX, SIGNET_URI_VERSION, getUriScope(), SIGNET_URI_PRIORITY, String(args.universe)] })
}

export function buildSyncPacket(args: Omit<BuildDMXPacketArgs, 'universe' | 'dmxData'>): Buffer {
    return buildDataPacket({ ...args, payload: buildSyncPayload(), uriSegments: [SIGNET_URI_PREFIX, SIGNET_URI_VERSION, getUriScope(), SIGNET_URI_SYNC] })
}

export function buildTimecodePacket(args: Omit<BuildDMXPacketArgs, 'universe' | 'dmxData'> & { stream: number; hours: number; minutes: number; seconds: number; frames: number; type: number }): Buffer {
    const payloadBuffer = new PacketBuffer()
    if (encodeTidTimecode(payloadBuffer, args.hours, args.minutes, args.seconds, args.frames, args.type) !== SIGNET_SUCCESS) throw new RangeError('invalid timecode')
    return buildDataPacket({ ...args, payload: payloadBuffer.toBuffer(), uriSegments: [SIGNET_URI_PREFIX, SIGNET_URI_VERSION, getUriScope(), SIGNET_URI_TIMECODE, String(args.stream)] })
}

function buildDataPacket(args: { tuid: Uint8Array; endpoint: number; mfgCode: number; sessionId: number; seqNum: number; senderKey: Uint8Array; messageId: number; payload: Uint8Array; uriSegments: string[] }): Buffer {
    const buffer = new PacketBuffer()
    must(buildCoapHeader(buffer, args.messageId))
    const uri = buildUriPathOptionsForSegments(buffer, args.uriSegments)
    const options = createSigNetOptions(args)
    must(buildSigNetOptionsWithoutHmac(buffer, options, COAP_OPTION_URI_PATH))
    must(finalizePacketWithHmacAndPayload(buffer, uri, options, args.payload, args.senderKey))
    return buffer.toBuffer()
}

//------------------------------------------------------------------------------
// Build Startup Announce Packet
//------------------------------------------------------------------------------
export function buildAnnouncePacket(args: {
    tuid: Uint8Array
    mfgCode: number
    productVariantId: number
    firmwareVersionId: number
    firmwareVersionString: string
    protocolVersion: number
    roleCapabilityBits: number
    changeCount: number
    sessionId: number
    seqNum: number
    citizenKey: Uint8Array
    messageId: number
}): Buffer {
    if (args.tuid.length !== TUID_LENGTH) throw new RangeError('tuid must be 6 bytes')
    const buffer = new PacketBuffer()
    must(buildCoapHeader(buffer, args.messageId))
    const uri = buildNodeUriPathOptions(buffer, args.tuid, 0)
    const options = createSigNetOptions({ tuid: args.tuid, endpoint: 0, mfgCode: args.mfgCode, sessionId: args.sessionId, seqNum: args.seqNum })
    must(buildSigNetOptionsWithoutHmac(buffer, options, COAP_OPTION_URI_PATH))
    const payload = buildStartupAnnouncePayload(args)
    must(finalizePacketWithHmacAndPayload(buffer, uri, options, payload, args.citizenKey))
    return buffer.toBuffer()
}

/** Build the lost-mode announcement sent to the fixed node-lost multicast group. */
export function buildNodeLostPacket(args: {
    tuid: Uint8Array
    mfgCode: number
    productVariantId: number
    firmwareVersionId: number
    firmwareVersionString: string
    protocolVersion: number
    roleCapabilityBits: number
    changeCount: number
    sessionId: number
    seqNum: number
    citizenKey: Uint8Array
    messageId: number
}): Buffer {
    if (args.tuid.length !== TUID_LENGTH) throw new RangeError('tuid must be 6 bytes')
    const buffer = new PacketBuffer()
    must(buildCoapHeader(buffer, args.messageId))
    const uri = buildNodeLostUriPathOptions(buffer, args.tuid)
    const options = createSigNetOptions({ tuid: args.tuid, endpoint: 0, mfgCode: args.mfgCode, sessionId: args.sessionId, seqNum: args.seqNum })
    must(buildSigNetOptionsWithoutHmac(buffer, options, COAP_OPTION_URI_PATH))
    const payload = buildStartupAnnouncePayload(args)
    must(finalizePacketWithHmacAndPayload(buffer, uri, options, payload, args.citizenKey))
    return buffer.toBuffer()
}

//------------------------------------------------------------------------------
// Build Manager Poll Packet (/sig-net/v1/{scope}/poll)
//------------------------------------------------------------------------------
export function buildPollPacket(args: {
    managerTuid: Uint8Array
    mfgCode: number
    productVariantId: number
    tuidLo: Uint8Array
    tuidHi: Uint8Array
    targetEndpoint: number
    queryLevel: number
    sessionId: number
    seqNum: number
    managerGlobalKey: Uint8Array
    messageId: number
}): Buffer {
    const buffer = new PacketBuffer()
    must(buildCoapHeader(buffer, args.messageId))
    const uri = buildPollUriPathOptions(buffer)
    const options = createSigNetOptions({ tuid: args.managerTuid, endpoint: 0, mfgCode: 0x0000, sessionId: args.sessionId, seqNum: args.seqNum })
    must(buildSigNetOptionsWithoutHmac(buffer, options, COAP_OPTION_URI_PATH))
    const payload = buildPollPayload(args.managerTuid, args.mfgCode, args.productVariantId, args.tuidLo, args.tuidHi, args.targetEndpoint, args.queryLevel)
    must(finalizePacketWithHmacAndPayload(buffer, uri, options, payload, args.managerGlobalKey))
    return buffer.toBuffer()
}

export function buildManagerPacket(args: {
    managerTuid: Uint8Array
    targetTuid: Uint8Array
    targetEndpoint: number
    payload?: Uint8Array
    sessionId: number
    seqNum: number
    managerLocalKey: Uint8Array
    messageId: number
    mfgCode?: number
}): Buffer {
    if (args.managerTuid.length !== TUID_LENGTH || args.targetTuid.length !== TUID_LENGTH) throw new RangeError('TUIDs must be 6 bytes')
    if (!Number.isInteger(args.targetEndpoint) || args.targetEndpoint < 0 || args.targetEndpoint > 0xffff) throw new RangeError('invalid target endpoint')
    const buffer = new PacketBuffer()
    must(buildCoapHeader(buffer, args.messageId))
    const uri = buildUriPathOptionsForSegments(buffer, [SIGNET_URI_PREFIX, SIGNET_URI_VERSION, getUriScope(), SIGNET_URI_MANAGER, tuidToHexString(args.targetTuid), String(args.targetEndpoint)])
    const options = createSigNetOptions({ tuid: args.managerTuid, endpoint: 0, mfgCode: args.mfgCode ?? 0, sessionId: args.sessionId, seqNum: args.seqNum })
    must(buildSigNetOptionsWithoutHmac(buffer, options, COAP_OPTION_URI_PATH))
    const payload = Buffer.from(args.payload ?? Buffer.alloc(0))
    must(finalizePacketWithHmacAndPayload(buffer, uri, options, payload, args.managerLocalKey))
    return buffer.toBuffer()
}

export function buildNodeResponsePacket(args: {
    tuid: Uint8Array
    endpoint: number
    mfgCode?: number
    sessionId: number
    seqNum: number
    citizenKey: Uint8Array
    messageId: number
    payload: Uint8Array
}): Buffer {
    if (args.tuid.length !== TUID_LENGTH) throw new RangeError('tuid must be 6 bytes')
    const buffer = new PacketBuffer()
    must(buildCoapHeader(buffer, args.messageId))
    const uri = buildNodeUriPathOptions(buffer, args.tuid, args.endpoint)
    const options = createSigNetOptions({ tuid: args.tuid, endpoint: args.endpoint, mfgCode: args.mfgCode ?? 0, sessionId: args.sessionId, seqNum: args.seqNum })
    must(buildSigNetOptionsWithoutHmac(buffer, options, COAP_OPTION_URI_PATH))
    must(finalizePacketWithHmacAndPayload(buffer, uri, options, args.payload, args.citizenKey))
    return buffer.toBuffer()
}

export function buildGetPayload(typeId: number): Buffer {
    return buildPayload([{ typeId }])
}

export function buildSetPayload(tlvs: readonly { typeId: number; value: Uint8Array }[]): Buffer {
    return buildPayload(tlvs)
}

//------------------------------------------------------------------------------
// Send via UDP multicast
//------------------------------------------------------------------------------
export async function sendMulticast(packet: Uint8Array, multicastIp: string, port = SIGNET_UDP_PORT): Promise<number> {
    return new Promise((resolve) => {
        const socket = dgram.createSocket('udp4')
        socket.on('error', () => {
            socket.close()
            resolve(SIGNET_ERROR_NETWORK)
        })
        socket.bind(() => {
            try {
                socket.setMulticastTTL(MULTICAST_TTL)
                socket.setMulticastLoopback(true)
            } catch {
                socket.close()
                resolve(SIGNET_ERROR_NETWORK)
                return
            }
            socket.send(packet, port, multicastIp, (err) => {
                socket.close()
                resolve(err ? SIGNET_ERROR_NETWORK : SIGNET_SUCCESS)
            })
        })
    })
}

//------------------------------------------------------------------------------
// Extract IPv4 token from adapter strings
//------------------------------------------------------------------------------
export function extractIpv4Token(raw: string): string {
    const match = raw.match(/[0-9.]+/)
    return match?.[0] ?? ''
}

//------------------------------------------------------------------------------
// Finalize Packet: HMAC option + payload marker + payload
//------------------------------------------------------------------------------
function finalizePacketWithHmacAndPayload(
    buffer: PacketBuffer,
    uri: string,
    options: Parameters<typeof calculateAndEncodeHmac>[2],
    payload: Uint8Array,
    signingKey: Uint8Array,
): number {
    let result = calculateAndEncodeHmac(buffer, uri, options, payload, signingKey)
    if (result !== SIGNET_SUCCESS) return result
    if (payload.length > 0) {
        result = buffer.writeByte(COAP_PAYLOAD_MARKER)
        if (result !== SIGNET_SUCCESS) return result
        return buffer.writeBytes(payload)
    }
    return SIGNET_SUCCESS
}

//------------------------------------------------------------------------------
// Build Node URI-Path Options and URI String
// (/sig-net/v1/{scope}/node/{tuid}/{endpoint})
//------------------------------------------------------------------------------
function buildNodeUriPathOptions(buffer: PacketBuffer, tuid: Uint8Array, endpoint: number): string {
    return buildUriPathOptionsForSegments(buffer, [SIGNET_URI_PREFIX, SIGNET_URI_VERSION, getUriScope(), SIGNET_URI_NODE, tuidToHexString(tuid), String(endpoint)])
}

function buildNodeLostUriPathOptions(buffer: PacketBuffer, tuid: Uint8Array): string {
    return buildUriPathOptionsForSegments(buffer, [SIGNET_URI_PREFIX, SIGNET_URI_VERSION, getUriScope(), SIGNET_URI_NODE_LOST, tuidToHexString(tuid), '0'])
}

function buildUriPathOptionsForSegments(buffer: PacketBuffer, segments: string[]): string {
    let prev = 0
    for (const segment of segments) {
        must(encodeCoapOption(buffer, COAP_OPTION_URI_PATH, prev, Buffer.from(segment, 'ascii')))
        prev = COAP_OPTION_URI_PATH
    }
    return `/${segments.join('/')}`
}

//------------------------------------------------------------------------------
// Build Poll URI-Path Options and URI String (/sig-net/v1/{scope}/poll)
//------------------------------------------------------------------------------
function buildPollUriPathOptions(buffer: PacketBuffer): string {
    const segments = [SIGNET_URI_PREFIX, SIGNET_URI_VERSION, getUriScope(), SIGNET_URI_POLL]
    let prev = 0
    for (const segment of segments) {
        must(encodeCoapOption(buffer, COAP_OPTION_URI_PATH, prev, Buffer.from(segment, 'ascii')))
        prev = COAP_OPTION_URI_PATH
    }
    return `/${segments.join('/')}`
}

function must(result: number): void {
    if (result !== SIGNET_SUCCESS) {
        if (result === SIGNET_ERROR_INVALID_ARG) throw new RangeError('invalid argument')
        throw new Error(`Sig-Net operation failed: ${result}`)
    }
}
