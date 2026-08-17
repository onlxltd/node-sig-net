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
    SIGNET_URI_POLL,
    SIGNET_URI_PREFIX,
    SIGNET_URI_VERSION,
} from './constants.js'
import { buildCoapHeader, buildUriPathOptions, buildUriString, encodeCoapOption, getUriScope } from './coap.js'
import { tuidToHexString } from './crypto.js'
import { buildDmxLevelPayload, buildPollPayload, buildStartupAnnouncePayload } from './tlv.js'
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
    const tuidHex = tuidToHexString(tuid)
    const segments = [SIGNET_URI_PREFIX, SIGNET_URI_VERSION, getUriScope(), SIGNET_URI_NODE, tuidHex, String(endpoint)]
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
