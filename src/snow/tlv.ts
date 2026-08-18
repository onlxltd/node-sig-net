import { PacketBuffer } from '../core/buffer.js'
import {
    K0_KEY_LENGTH,
    TUID_LENGTH,
    TOTW_RT_COME_HOME,
    TOTW_RT_IDENTIFY,
    TOTW_RT_KEY_K0,
    TOTW_RT_KEY_KC,
    TOTW_RT_KEY_KM_GLOBAL,
    TOTW_RT_KEY_KM_LOCAL,
    TOTW_RT_KEY_KS,
    TOTW_RT_POM_PUBLIC_KEY,
    TOTW_RT_PUBLIC_KEY,
    TOTW_RT_SCOPE,
    TOTW_RT_OTW_REOPEN,
    TOTW_RT_POM_WIPE,
    TOTW_RT_UPDATE_POM,
    TID_RT_OTW_CAPABILITY,
} from '../core/constants.js'
import { encodeTlv } from '../core/tlv.js'

function bytes(value: Uint8Array, length?: number): Buffer {
    if (length !== undefined && value.length !== length) throw new RangeError(`value must be ${length} bytes`)
    return Buffer.from(value)
}

export function buildSnowTlv(typeId: number, value: Uint8Array = Buffer.alloc(0)): Buffer {
    const buffer = new PacketBuffer()
    if (encodeTlv(buffer, typeId, value) !== 0) throw new RangeError('SNOW TLV is too large')
    return buffer.toBuffer()
}

export function buildComeHomeTlv(tuid: Uint8Array, address: Uint8Array, netmask: Uint8Array, gateway: Uint8Array): Buffer {
    return buildSnowTlv(TOTW_RT_COME_HOME, Buffer.concat([bytes(tuid, TUID_LENGTH), bytes(address, 4), bytes(netmask, 4), bytes(gateway, 4)]))
}

export function buildPublicKeyTlv(publicKey: Uint8Array): Buffer {
    if (publicKey.length === 0) throw new RangeError('public key is required')
    return buildSnowTlv(TOTW_RT_PUBLIC_KEY, publicKey)
}

export function buildIdentifyTlv(fingerprint: Uint8Array): Buffer {
    return buildSnowTlv(TOTW_RT_IDENTIFY, bytes(fingerprint, 32))
}

export function buildKeyTlv(typeId: typeof TOTW_RT_KEY_KS | typeof TOTW_RT_KEY_KC | typeof TOTW_RT_KEY_KM_GLOBAL | typeof TOTW_RT_KEY_KM_LOCAL | typeof TOTW_RT_KEY_K0, key: Uint8Array): Buffer {
    return buildSnowTlv(typeId, bytes(key, K0_KEY_LENGTH))
}

export function buildPomPublicKeyTlv(publicKey: Uint8Array): Buffer {
    if (publicKey.length === 0) throw new RangeError('POM public key is required')
    return buildSnowTlv(TOTW_RT_POM_PUBLIC_KEY, publicKey)
}

export function buildScopeTlv(scope: string): Buffer {
    const value = Buffer.from(scope, 'utf8')
    if (value.length < 1 || value.length > 32) throw new RangeError('scope must be 1..32 UTF-8 bytes')
    return buildSnowTlv(TOTW_RT_SCOPE, value)
}

export function buildPomWipeTlv(tuid: Uint8Array, nonce: Uint8Array, signature: Uint8Array): Buffer {
    return buildSnowTlv(TOTW_RT_POM_WIPE, Buffer.concat([bytes(tuid, TUID_LENGTH), bytes(nonce, 8), bytes(signature, 64)]))
}

export function buildOtwReopenTlv(args: {
    tuid: Uint8Array
    signatureType: 'hmac' | 'ecdsa'
    timeoutSeconds?: number
    nonce: Uint8Array
    signature: Uint8Array
}): Buffer {
    if (args.tuid.length !== TUID_LENGTH) throw new RangeError('tuid must be 6 bytes')
    if (args.nonce.length !== 8) throw new RangeError('nonce must be 8 bytes')
    const timeout = args.timeoutSeconds ?? 0
    if (!Number.isInteger(timeout) || timeout < 0 || timeout > 255) throw new RangeError('timeout must be 0..255 seconds')
    const expectedSignatureLength = args.signatureType === 'hmac' ? 32 : args.signatureType === 'ecdsa' ? 64 : 0
    if (!expectedSignatureLength || args.signature.length !== expectedSignatureLength) throw new RangeError('invalid OTW reopen signature')
    return buildSnowTlv(
        TOTW_RT_OTW_REOPEN,
        Buffer.concat([bytes(args.tuid, TUID_LENGTH), Buffer.from([args.signatureType === 'hmac' ? 0 : 1, timeout]), bytes(args.nonce, 8), bytes(args.signature, expectedSignatureLength)]),
    )
}

export function buildUpdatePomTlv(publicKey: Uint8Array): Buffer {
    if (publicKey.length === 0) throw new RangeError('POM public key must be raw or DER encoded')
    return buildSnowTlv(TOTW_RT_UPDATE_POM, publicKey)
}

/** Encodes the Sig-Net OTW capability announcement: ephemeral port + flags. */
export function buildOtwCapabilityTlv(port: number, flags = 0): Buffer {
    if (!Number.isInteger(port) || port < 1 || port > 0xffff) throw new RangeError('OTW port must be 1..65535')
    const value = Buffer.alloc(3)
    value.writeUInt16BE(port, 0)
    value[2] = flags & 0xff
    return buildSnowTlv(TID_RT_OTW_CAPABILITY, value)
}

export function buildSnowTlvs(...tlvs: Uint8Array[]): Buffer {
    return Buffer.concat(tlvs.map((tlv) => Buffer.from(tlv)))
}
