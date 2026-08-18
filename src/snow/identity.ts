import { createPublicKey, generateKeyPairSync, sign, verify, type KeyObject } from 'node:crypto'

export class SnowIdentity {
    readonly privateKey: KeyObject
    readonly publicKey: KeyObject

    constructor(keys?: { privateKey: KeyObject; publicKey?: KeyObject }) {
        if (keys) {
            this.privateKey = keys.privateKey
            this.publicKey = keys.publicKey ?? createPublicKey(keys.privateKey.export({ format: 'pem', type: 'pkcs8' }))
        } else {
            const generated = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
            this.privateKey = generated.privateKey
            this.publicKey = generated.publicKey
        }
    }

    /** Raw uncompressed secp256r1 point (04 || X || Y), as used by SNOW. */
    getRawPublicKey(): Buffer {
        const jwk = this.publicKey.export({ format: 'jwk' })
        if (!('x' in jwk) || !('y' in jwk) || typeof jwk.x !== 'string' || typeof jwk.y !== 'string') throw new Error('invalid EC public key')
        return Buffer.concat([Buffer.from([0x04]), base64UrlDecode(jwk.x), base64UrlDecode(jwk.y)])
    }

    sign(data: Uint8Array): Buffer {
        return sign('sha256', Buffer.from(data), { key: this.privateKey, dsaEncoding: 'ieee-p1363' })
    }

    verify(data: Uint8Array, signature: Uint8Array): boolean {
        return signature.length === 64 && verify('sha256', Buffer.from(data), { key: this.publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(signature))
    }
}

export function publicKeyFromRaw(raw: Uint8Array): KeyObject {
    if (raw.length !== 65 || raw[0] !== 0x04) throw new RangeError('raw EC public key must be 65 bytes')
    return createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: base64UrlEncode(raw.subarray(1, 33)), y: base64UrlEncode(raw.subarray(33, 65)) }, format: 'jwk' })
}

export function verifyRawEcdsa(publicKey: Uint8Array, data: Uint8Array, signature: Uint8Array): boolean {
    return signature.length === 64 && verify('sha256', Buffer.from(data), { key: publicKeyFromRaw(publicKey), dsaEncoding: 'ieee-p1363' }, Buffer.from(signature))
}

function base64UrlEncode(value: Uint8Array): string {
    return Buffer.from(value).toString('base64').replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
}

function base64UrlDecode(value: string): Buffer {
    return Buffer.from(value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - (value.length % 4)) % 4), 'base64')
}
