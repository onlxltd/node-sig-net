import { randomBytes } from 'node:crypto'
import { hmacSha256 } from '../core/crypto.js'
import { TUID_LENGTH } from '../core/constants.js'
import { SnowIdentity, verifyRawEcdsa } from './identity.js'
import { buildOtwReopenTlv, buildPomWipeTlv } from './tlv.js'

export function pomWipeAuthorizationInput(tuid: Uint8Array, nonce: Uint8Array): Buffer {
    if (tuid.length !== TUID_LENGTH || nonce.length !== 8) throw new RangeError('invalid POM wipe authorization fields')
    return Buffer.concat([Buffer.from(tuid), Buffer.from(nonce)])
}

export function otwReopenAuthorizationInput(tuid: Uint8Array, signatureType: 'hmac' | 'ecdsa', timeoutSeconds: number, nonce: Uint8Array): Buffer {
    if (tuid.length !== TUID_LENGTH || nonce.length !== 8 || !Number.isInteger(timeoutSeconds) || timeoutSeconds < 0 || timeoutSeconds > 255) throw new RangeError('invalid OTW reopen authorization fields')
    return Buffer.concat([Buffer.from(tuid), Buffer.from([signatureType === 'hmac' ? 0 : 1, timeoutSeconds]), Buffer.from(nonce)])
}

export function buildSignedPomWipe(tuid: Uint8Array, identity: SnowIdentity, nonce = randomBytes(8)): Buffer {
    return buildPomWipeTlv(tuid, nonce, identity.sign(pomWipeAuthorizationInput(tuid, nonce)))
}

export function verifyPomWipe(tuid: Uint8Array, nonce: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
    return verifyRawEcdsa(publicKey, pomWipeAuthorizationInput(tuid, nonce), signature)
}

export function buildSignedOtwReopen(args: { tuid: Uint8Array; identity: SnowIdentity; timeoutSeconds?: number; nonce?: Uint8Array }): Buffer {
    const timeoutSeconds = args.timeoutSeconds ?? 0
    const nonce = args.nonce ?? randomBytes(8)
    const signature = args.identity.sign(otwReopenAuthorizationInput(args.tuid, 'ecdsa', timeoutSeconds, nonce))
    return buildOtwReopenTlv({ tuid: args.tuid, signatureType: 'ecdsa', timeoutSeconds, nonce, signature })
}

export function buildHmacOtwReopen(args: { tuid: Uint8Array; managerLocalKey: Uint8Array; timeoutSeconds?: number; nonce?: Uint8Array }): Buffer {
    const timeoutSeconds = args.timeoutSeconds ?? 0
    const nonce = args.nonce ?? randomBytes(8)
    const signature = hmacSha256(args.managerLocalKey, otwReopenAuthorizationInput(args.tuid, 'hmac', timeoutSeconds, nonce))
    return buildOtwReopenTlv({ tuid: args.tuid, signatureType: 'hmac', timeoutSeconds, nonce, signature })
}

export function verifyHmacOtwReopen(args: { tuid: Uint8Array; managerLocalKey: Uint8Array; timeoutSeconds: number; nonce: Uint8Array; signature: Uint8Array }): boolean {
    const expected = hmacSha256(args.managerLocalKey, otwReopenAuthorizationInput(args.tuid, 'hmac', args.timeoutSeconds, args.nonce))
    return expected.length === args.signature.length && expected.equals(Buffer.from(args.signature))
}
