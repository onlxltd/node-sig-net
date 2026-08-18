import { PacketBuffer } from '../core/buffer.js'
import { buildCoapHeader, encodeCoapOption } from '../core/coap.js'
import { COAP_OPTION_URI_PATH, SECURITY_MODE_UNPROVISIONED, SIGNET_OPTION_HMAC, SIGNET_OPTION_MFG_CODE, SIGNET_OPTION_SECURITY_MODE, SIGNET_OPTION_SENDER_ID, SIGNET_OPTION_SEQ_NUM, SIGNET_OPTION_SESSION_ID, SIGNET_URI_PREFIX, SIGNET_URI_VERSION, SIGNET_URI_SCOPE_DEFAULT, SIGNET_SUCCESS } from '../core/constants.js'
import { buildSenderId } from '../core/security.js'
import type { SnowBeaconArgs, SnowPacketArgs } from './types.js'
import { buildOtwCapabilityTlv } from './tlv.js'

export function buildSnowSNRPPacket(args: SnowPacketArgs): Buffer {
    return buildSnowPacket(args, [SIGNET_URI_PREFIX, SIGNET_URI_VERSION, SIGNET_URI_SCOPE_DEFAULT, 'snrp'])
}

export function buildSnowManagerPacket(args: SnowPacketArgs & { targetTuid: Uint8Array }): Buffer {
    if (args.targetTuid.length !== 6) throw new RangeError('targetTuid must be 6 bytes')
    return buildSnowPacket(args, [SIGNET_URI_PREFIX, SIGNET_URI_VERSION, SIGNET_URI_SCOPE_DEFAULT, 'manager', Buffer.from(args.targetTuid).toString('hex').toUpperCase(), '0'])
}

export function buildSnowNodePacket(args: Omit<SnowPacketArgs, 'managerTuid'> & { deviceTuid: Uint8Array }): Buffer {
    if (args.deviceTuid.length !== 6) throw new RangeError('deviceTuid must be 6 bytes')
    return buildSnowPacket({ ...args, managerTuid: args.deviceTuid }, [SIGNET_URI_PREFIX, SIGNET_URI_VERSION, SIGNET_URI_SCOPE_DEFAULT, 'node', Buffer.from(args.deviceTuid).toString('hex').toUpperCase(), '0'])
}

export function buildSnowBeaconPacket(args: SnowBeaconArgs): Buffer {
    if (args.deviceTuid.length !== 6) throw new RangeError('deviceTuid must be 6 bytes')
    return buildSnowPacket(
        {
            managerTuid: args.deviceTuid,
            mfgCode: args.mfgCode,
            tlvs: buildOtwCapabilityTlv(args.otwPort, args.otwFlags),
            ...(args.sessionId === undefined ? {} : { sessionId: args.sessionId }),
            ...(args.seqNum === undefined ? {} : { seqNum: args.seqNum }),
            ...(args.messageId === undefined ? {} : { messageId: args.messageId }),
        },
        [SIGNET_URI_PREFIX, SIGNET_URI_VERSION, SIGNET_URI_SCOPE_DEFAULT, 'node_beacon', Buffer.from(args.deviceTuid).toString('hex').toUpperCase()],
    )
}

function buildSnowPacket(args: SnowPacketArgs, segments: string[]): Buffer {
    if (args.managerTuid.length !== 6) throw new RangeError('managerTuid must be 6 bytes')
    const buffer = new PacketBuffer()
    const messageId = args.messageId ?? 1
    if (buildCoapHeader(buffer, messageId) !== SIGNET_SUCCESS) throw new Error('unable to build CoAP header')
    let previous = 0
    for (const segment of segments) {
        if (encodeCoapOption(buffer, COAP_OPTION_URI_PATH, previous, Buffer.from(segment, 'ascii')) !== SIGNET_SUCCESS) throw new Error('unable to build SNOW URI')
        previous = COAP_OPTION_URI_PATH
    }
    const options: Array<[number, Buffer]> = [
        [SIGNET_OPTION_SECURITY_MODE, Buffer.from([SECURITY_MODE_UNPROVISIONED])],
        [SIGNET_OPTION_SENDER_ID, buildSenderId(args.managerTuid, 0)],
        [SIGNET_OPTION_MFG_CODE, uint16(args.mfgCode)],
        [SIGNET_OPTION_SESSION_ID, uint32(args.sessionId ?? 1)],
        [SIGNET_OPTION_SEQ_NUM, uint32(args.seqNum ?? 1)],
        [SIGNET_OPTION_HMAC, Buffer.alloc(0)],
    ]
    for (const [number, value] of options) {
        if (encodeCoapOption(buffer, number, previous, value) !== SIGNET_SUCCESS) throw new Error('unable to build SNOW options')
        previous = number
    }
    if (args.tlvs.length > 0) {
        buffer.writeByte(0xff)
        buffer.writeBytes(args.tlvs)
    }
    return buffer.toBuffer()
}

function uint16(value: number): Buffer { const out = Buffer.alloc(2); out.writeUInt16BE(value & 0xffff); return out }
function uint32(value: number): Buffer { const out = Buffer.alloc(4); out.writeUInt32BE(value >>> 0); return out }
