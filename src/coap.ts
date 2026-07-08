import {
    COAP_CODE_POST,
    COAP_HEADER_SIZE,
    COAP_OPTION_EXT16_BASE,
    COAP_OPTION_EXT16_NIBBLE,
    COAP_OPTION_EXT8_BASE,
    COAP_OPTION_EXT8_NIBBLE,
    COAP_OPTION_INLINE_MAX,
    COAP_OPTION_URI_PATH,
    COAP_PAYLOAD_MARKER,
    COAP_TYPE_NON,
    COAP_VERSION,
    MAX_UNIVERSE,
    MIN_UNIVERSE,
    SIGNET_ERROR_ENCODE,
    SIGNET_ERROR_INVALID_ARG,
    SIGNET_SUCCESS,
    SIGNET_URI_LEVEL,
    SIGNET_URI_PREFIX,
    SIGNET_URI_SCOPE_DEFAULT,
    SIGNET_URI_SCOPE_MAX_LENGTH,
    SIGNET_URI_VERSION,
} from './constants.js'
import { PacketBuffer } from './buffer.js'

//==============================================================================
// Sig-Net Protocol Framework - CoAP Packet Building Implementation
//==============================================================================
// Upstream description:
// CoAP packet construction with extended delta encoding and URI-Path option
// building for Sig-Net packets. Implements RFC 7252 CoAP protocol requirements.
//==============================================================================

let uriScope = ''

//------------------------------------------------------------------------------
// URI scope configuration
//------------------------------------------------------------------------------
export function setUriScope(scope: string): number {
    if (!scope || scope.length > SIGNET_URI_SCOPE_MAX_LENGTH || !/^[A-Za-z0-9._~-]+$/.test(scope)) {
        return SIGNET_ERROR_INVALID_ARG
    }
    uriScope = scope
    return SIGNET_SUCCESS
}

export function getUriScope(): string {
    if (!uriScope) uriScope = SIGNET_URI_SCOPE_DEFAULT
    return uriScope
}

//------------------------------------------------------------------------------
// Build CoAP Header
//------------------------------------------------------------------------------
export function buildCoapHeader(buffer: PacketBuffer, messageId: number): number {
    const first = ((COAP_VERSION & 0x03) << 6) | ((COAP_TYPE_NON & 0x03) << 4)
    let result = buffer.writeByte(first)
    if (result !== SIGNET_SUCCESS) return result
    result = buffer.writeByte(COAP_CODE_POST)
    if (result !== SIGNET_SUCCESS) return result
    return buffer.writeUInt16(messageId & 0xffff)
}

//------------------------------------------------------------------------------
// Encode CoAP Option (RFC 7252 Section 3.1)
//
// Delta/Length encoding:
//   0-12: Value fits in 4-bit field
//   13:   8-bit extended value follows (actual value = extended + 13)
//   14:   16-bit extended value follows (actual value = extended + 269)
//   15:   Reserved (payload marker or error)
//------------------------------------------------------------------------------
export function encodeCoapOption(buffer: PacketBuffer, optionNumber: number, prevOption: number, optionValue: Uint8Array = Buffer.alloc(0)): number {
    if (optionNumber < prevOption) return SIGNET_ERROR_ENCODE
    const delta = optionNumber - prevOption
    const deltaEncoded = encodeNibble(delta)
    const lengthEncoded = encodeNibble(optionValue.length)
    let result = buffer.writeByte((deltaEncoded.nibble << 4) | lengthEncoded.nibble)
    if (result !== SIGNET_SUCCESS) return result
    result = writeExtended(buffer, deltaEncoded.ext)
    if (result !== SIGNET_SUCCESS) return result
    result = writeExtended(buffer, lengthEncoded.ext)
    if (result !== SIGNET_SUCCESS) return result
    return optionValue.length > 0 ? buffer.writeBytes(optionValue) : SIGNET_SUCCESS
}

//------------------------------------------------------------------------------
// Build URI-Path Options for Sig-Net
//
// Constructs: /sig-net/v1/{scope}/level/{universe}
// As 5 separate Uri-Path options.
//------------------------------------------------------------------------------
export function buildUriPathOptions(buffer: PacketBuffer, universe: number): number {
    if (universe < MIN_UNIVERSE || universe > MAX_UNIVERSE) return SIGNET_ERROR_INVALID_ARG
    const segments = [SIGNET_URI_PREFIX, SIGNET_URI_VERSION, getUriScope(), SIGNET_URI_LEVEL, String(universe)]
    let prev = 0
    for (const segment of segments) {
        const result = encodeCoapOption(buffer, COAP_OPTION_URI_PATH, prev, Buffer.from(segment, 'ascii'))
        if (result !== SIGNET_SUCCESS) return result
        prev = COAP_OPTION_URI_PATH
    }
    return SIGNET_SUCCESS
}

//------------------------------------------------------------------------------
// Build URI String for HMAC Calculation
//
// Returns: "/sig-net/v1/{scope}/level/{universe}"
// This is used as part of the HMAC input per Section 8.5.
//------------------------------------------------------------------------------
export function buildUriString(universe: number): string {
    if (universe < MIN_UNIVERSE || universe > MAX_UNIVERSE) throw new RangeError('invalid universe')
    return `/${SIGNET_URI_PREFIX}/${SIGNET_URI_VERSION}/${getUriScope()}/${SIGNET_URI_LEVEL}/${universe}`
}

export function decodeOptions(packet: Uint8Array): { options: DecodedOption[]; payloadOffset: number } {
    if (packet.length < COAP_HEADER_SIZE) throw new RangeError('packet too small')
    const tokenLength = packet[0]! & 0x0f
    let pos = COAP_HEADER_SIZE + tokenLength
    let prev = 0
    const options: DecodedOption[] = []
    while (pos < packet.length) {
        if (packet[pos] === COAP_PAYLOAD_MARKER) return { options, payloadOffset: pos + 1 }
        const header = packet[pos++]!
        const delta = decodeNibble(packet, header >> 4, () => pos++)
        const length = decodeNibble(packet, header & 0x0f, () => pos++)
        const optionNumber = prev + delta
        if (pos + length > packet.length) throw new RangeError('truncated option')
        options.push({ optionNumber, value: Buffer.from(packet.subarray(pos, pos + length)) })
        pos += length
        prev = optionNumber
    }
    return { options, payloadOffset: packet.length }
}

export function uriFromOptions(options: readonly DecodedOption[]): string {
    const segments = options.filter((option) => option.optionNumber === COAP_OPTION_URI_PATH).map((option) => option.value.toString('ascii'))
    return `/${segments.join('/')}`
}

export interface DecodedOption {
    optionNumber: number
    value: Buffer
}

function encodeNibble(value: number): { nibble: number; ext: number[] } {
    if (value <= COAP_OPTION_INLINE_MAX) return { nibble: value, ext: [] }
    if (value < COAP_OPTION_EXT16_BASE) return { nibble: COAP_OPTION_EXT8_NIBBLE, ext: [value - COAP_OPTION_EXT8_BASE] }
    const ext = value - COAP_OPTION_EXT16_BASE
    return { nibble: COAP_OPTION_EXT16_NIBBLE, ext: [(ext >>> 8) & 0xff, ext & 0xff] }
}

function writeExtended(buffer: PacketBuffer, bytes: number[]): number {
    for (const byte of bytes) {
        const result = buffer.writeByte(byte)
        if (result !== SIGNET_SUCCESS) return result
    }
    return SIGNET_SUCCESS
}

function decodeNibble(packet: Uint8Array, nibble: number, advance: () => number): number {
    if (nibble <= 12) return nibble
    if (nibble === 13) {
        const pos = advance()
        if (pos >= packet.length) throw new RangeError('truncated extended option')
        return (packet[pos] ?? 0) + 13
    }
    if (nibble === 14) {
        const hiPos = advance()
        const loPos = advance()
        if (loPos >= packet.length) throw new RangeError('truncated extended option')
        return (((packet[hiPos] ?? 0) << 8) | (packet[loPos] ?? 0)) + 269
    }
    throw new RangeError('reserved option nibble')
}
