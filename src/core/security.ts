import { timingSafeEqual } from 'crypto'
import { PacketBuffer } from './buffer.js'
import {
    DERIVED_KEY_LENGTH,
    HMAC_SHA256_LENGTH,
    SECURITY_MODE_HMAC_SHA256,
    SENDER_ID_LENGTH,
    SIGNET_ERROR_HMAC_FAILED,
    SIGNET_ERROR_INVALID_ARG,
    SIGNET_OPTION_HMAC,
    SIGNET_OPTION_MFG_CODE,
    SIGNET_OPTION_SECURITY_MODE,
    SIGNET_OPTION_SENDER_ID,
    SIGNET_OPTION_SEQ_NUM,
    SIGNET_OPTION_SESSION_ID,
    SIGNET_SUCCESS,
    TUID_LENGTH,
} from './constants.js'
import { hmacSha256 } from './crypto.js'
import type { SigNetOptions } from './types.js'
import { encodeCoapOption } from './coap.js'

//==============================================================================
// Sig-Net Protocol Framework - Security Layer Implementation
//==============================================================================
// Upstream description:
// Sig-Net custom CoAP options encoding and HMAC-SHA256 signature calculation
// per Section 8.5 of the spec. Handles Security-Mode, Sender-ID, Mfg-Code,
// Session, Seq, and HMAC.
//==============================================================================

//------------------------------------------------------------------------------
// Build Sender-ID from TUID and Endpoint
//------------------------------------------------------------------------------
export function buildSenderId(tuid: Uint8Array, endpoint: number): Buffer {
    if (!tuid || tuid.length !== TUID_LENGTH) throw new RangeError('tuid must be 6 bytes')
    const senderId = Buffer.alloc(SENDER_ID_LENGTH)
    Buffer.from(tuid).copy(senderId, 0)
    senderId.writeUInt16BE(endpoint & 0xffff, 6)
    return senderId
}

export function createSigNetOptions(params: { tuid: Uint8Array; endpoint: number; mfgCode: number; sessionId: number; seqNum: number }): SigNetOptions {
    return {
        securityMode: SECURITY_MODE_HMAC_SHA256,
        senderId: buildSenderId(params.tuid, params.endpoint),
        mfgCode: params.mfgCode,
        sessionId: params.sessionId >>> 0,
        seqNum: params.seqNum >>> 0,
        hmac: Buffer.alloc(HMAC_SHA256_LENGTH),
    }
}

//------------------------------------------------------------------------------
// Build SigNet Custom Options (Without HMAC)
//------------------------------------------------------------------------------
export function buildSigNetOptionsWithoutHmac(buffer: PacketBuffer, options: SigNetOptions, prevOption: number): number {
    let result = encodeCoapOption(buffer, SIGNET_OPTION_SECURITY_MODE, prevOption, Buffer.from([options.securityMode]))
    if (result !== SIGNET_SUCCESS) return result
    result = encodeCoapOption(buffer, SIGNET_OPTION_SENDER_ID, SIGNET_OPTION_SECURITY_MODE, options.senderId)
    if (result !== SIGNET_SUCCESS) return result
    const mfg = Buffer.alloc(2)
    mfg.writeUInt16BE(options.mfgCode & 0xffff, 0)
    result = encodeCoapOption(buffer, SIGNET_OPTION_MFG_CODE, SIGNET_OPTION_SENDER_ID, mfg)
    if (result !== SIGNET_SUCCESS) return result
    const session = Buffer.alloc(4)
    session.writeUInt32BE(options.sessionId >>> 0, 0)
    result = encodeCoapOption(buffer, SIGNET_OPTION_SESSION_ID, SIGNET_OPTION_MFG_CODE, session)
    if (result !== SIGNET_SUCCESS) return result
    const seq = Buffer.alloc(4)
    seq.writeUInt32BE(options.seqNum >>> 0, 0)
    return encodeCoapOption(buffer, SIGNET_OPTION_SEQ_NUM, SIGNET_OPTION_SESSION_ID, seq)
}

//------------------------------------------------------------------------------
// Build HMAC Input Buffer (Section 8.5)
//------------------------------------------------------------------------------
export function buildHmacInput(uri: string, options: SigNetOptions, payload: Uint8Array): Buffer {
    const fixed = Buffer.alloc(1 + SENDER_ID_LENGTH + 2 + 4 + 4)
    let pos = 0
    fixed[pos++] = options.securityMode
    options.senderId.copy(fixed, pos)
    pos += SENDER_ID_LENGTH
    fixed.writeUInt16BE(options.mfgCode & 0xffff, pos)
    pos += 2
    fixed.writeUInt32BE(options.sessionId >>> 0, pos)
    pos += 4
    fixed.writeUInt32BE(options.seqNum >>> 0, pos)
    return Buffer.concat([Buffer.from(uri, 'ascii'), fixed, Buffer.from(payload)])
}

//------------------------------------------------------------------------------
// Calculate and Encode HMAC Option
//------------------------------------------------------------------------------
export function calculateAndEncodeHmac(buffer: PacketBuffer, uri: string, options: SigNetOptions, payload: Uint8Array, signingKey: Uint8Array): number {
    if (!uri || !signingKey || signingKey.length !== DERIVED_KEY_LENGTH) return SIGNET_ERROR_INVALID_ARG
    options.hmac = hmacSha256(signingKey, buildHmacInput(uri, options, payload))
    return encodeCoapOption(buffer, SIGNET_OPTION_HMAC, SIGNET_OPTION_SEQ_NUM, options.hmac)
}

//------------------------------------------------------------------------------
// Verify Packet HMAC
//------------------------------------------------------------------------------
export function verifyPacketHmac(uri: string, options: SigNetOptions, payload: Uint8Array, roleKey: Uint8Array): number {
    if (!uri || !roleKey || roleKey.length !== DERIVED_KEY_LENGTH) return SIGNET_ERROR_INVALID_ARG
    const expected = hmacSha256(roleKey, buildHmacInput(uri, options, payload))
    return expected.length === options.hmac.length && timingSafeEqual(expected, options.hmac) ? SIGNET_SUCCESS : SIGNET_ERROR_HMAC_FAILED
}
