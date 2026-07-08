import {
    COAP_CODE_POST,
    COAP_OPTION_URI_PATH,
    HMAC_SHA256_LENGTH,
    SECURITY_MODE_UNPROVISIONED,
    SENDER_ID_LENGTH,
    SIGNET_ERROR_INVALID_OPTION,
    SIGNET_ERROR_INVALID_PACKET,
    SIGNET_SUCCESS,
    SIGNET_OPTION_HMAC,
    SIGNET_OPTION_MFG_CODE,
    SIGNET_OPTION_SECURITY_MODE,
    SIGNET_OPTION_SENDER_ID,
    SIGNET_OPTION_SEQ_NUM,
    SIGNET_OPTION_SESSION_ID,
    SIGNET_URI_PREFIX,
    SIGNET_URI_VERSION,
} from './constants.js'
import { decodeOptions, getUriScope, uriFromOptions } from './coap.js'
import { parseTlvs } from './tlv.js'
import type { ParsedPacket, SigNetOptions } from './types.js'

//==============================================================================
// Sig-Net Protocol Framework - Packet Parsing Implementation
//==============================================================================
// Upstream description:
// Packet parsing for Sig-Net receivers. CoAP option parsing, custom option
// extraction, TLV parsing, and HMAC verification wrapper functions.
//==============================================================================

//------------------------------------------------------------------------------
// Parse Complete Packet
//------------------------------------------------------------------------------
export function parsePacket(packet: Uint8Array): ParsedPacket {
    if (packet.length < 4) throw new RangeError('packet too small')
    const header0 = packet[0]!
    const messageId = (packet[2]! << 8) | packet[3]!
    const { options: rawOptions, payloadOffset } = decodeOptions(packet)
    const uri = uriFromOptions(rawOptions)
    const payload = Buffer.from(packet.subarray(payloadOffset))
    const options = parseSigNetOptions(rawOptions)
    return {
        version: (header0 >> 6) & 0x03,
        type: (header0 >> 4) & 0x03,
        tokenLength: header0 & 0x0f,
        code: packet[1] ?? COAP_CODE_POST,
        messageId,
        uri,
        options,
        payload,
        tlvs: parseTlvs(payload),
    }
}

//------------------------------------------------------------------------------
// Validate Sig-Net URI
//------------------------------------------------------------------------------
export function validateSigNetUri(uri: string): number {
    const segments = uri.split('/')
    if (segments.length < 4 || segments[0] !== '' || segments[1] !== SIGNET_URI_PREFIX || segments[2] !== SIGNET_URI_VERSION || segments[3] !== getUriScope()) {
        return SIGNET_ERROR_INVALID_PACKET
    }
    return SIGNET_SUCCESS
}

//------------------------------------------------------------------------------
// Parse SigNet Options
//------------------------------------------------------------------------------
export function parseSigNetOptions(rawOptions: readonly { optionNumber: number; value: Buffer }[]): SigNetOptions {
    const out: SigNetOptions = {
        securityMode: 0,
        senderId: Buffer.alloc(SENDER_ID_LENGTH),
        mfgCode: 0,
        sessionId: 0,
        seqNum: 0,
        hmac: Buffer.alloc(HMAC_SHA256_LENGTH),
    }
    const found = new Set<number>()
    for (const option of rawOptions) {
        if (option.optionNumber === COAP_OPTION_URI_PATH) continue
        found.add(option.optionNumber)
        switch (option.optionNumber) {
            case SIGNET_OPTION_SECURITY_MODE:
                if (option.value.length !== 1) throw new RangeError('invalid Security-Mode option')
                out.securityMode = option.value[0]!
                break
            case SIGNET_OPTION_SENDER_ID:
                if (option.value.length !== SENDER_ID_LENGTH) throw new RangeError('invalid Sender-ID option')
                out.senderId = option.value
                break
            case SIGNET_OPTION_MFG_CODE:
                if (option.value.length !== 2) throw new RangeError('invalid Mfg-Code option')
                out.mfgCode = option.value.readUInt16BE(0)
                break
            case SIGNET_OPTION_SESSION_ID:
                if (option.value.length !== 4) throw new RangeError('invalid Session-ID option')
                out.sessionId = option.value.readUInt32BE(0)
                break
            case SIGNET_OPTION_SEQ_NUM:
                if (option.value.length !== 4) throw new RangeError('invalid Seq-Num option')
                out.seqNum = option.value.readUInt32BE(0)
                break
            case SIGNET_OPTION_HMAC:
                if (option.value.length !== HMAC_SHA256_LENGTH) throw new RangeError('invalid HMAC option')
                out.hmac = option.value
                break
        }
    }
    if (!found.has(SIGNET_OPTION_SECURITY_MODE)) throw new RangeError(`Sig-Net option error ${SIGNET_ERROR_INVALID_OPTION}`)
    if (out.securityMode !== SECURITY_MODE_UNPROVISIONED) {
        for (const required of [SIGNET_OPTION_SENDER_ID, SIGNET_OPTION_MFG_CODE, SIGNET_OPTION_SESSION_ID, SIGNET_OPTION_SEQ_NUM, SIGNET_OPTION_HMAC]) {
            if (!found.has(required)) throw new RangeError(`Sig-Net option error ${SIGNET_ERROR_INVALID_OPTION}`)
        }
    }
    return out
}

//------------------------------------------------------------------------------
// Parse Packet Result Wrapper
//------------------------------------------------------------------------------
export function parsePacketResult(packet: Uint8Array): { code: number; packet?: ParsedPacket } {
    try {
        return { code: SIGNET_SUCCESS, packet: parsePacket(packet) }
    } catch {
        return { code: SIGNET_ERROR_INVALID_PACKET }
    }
}
