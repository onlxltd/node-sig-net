import { analysePassphrase, deriveK0FromPassphrase, deriveSenderKey, generateEphemeralTuid, generateRandomPassphrase, parseK0Hex } from './crypto.js'
import { K0_KEY_LENGTH, SIGNET_PASSPHRASE_VALID } from './constants.js'

export type SigNetKeySource = 'passphrase' | 'generated-passphrase' | 'machine-transfer' | 'k0'

export type SigNetGeneratorOptions = {
    mfgCode: number
    /** Existing binary root key. */
    k0?: Uint8Array
    /** Passphrase, 64-character machine-transfer K0, or blank to generate one. */
    key?: string | Uint8Array
    /** Explicit passphrase alternative to `key`. */
    passphrase?: string
}

/** Generates the identity and sender credentials for a Sig-Net controller. */
export class SigNetGenerator {
    readonly k0: Buffer
    readonly tuid: Buffer
    readonly senderKey: Buffer
    readonly passphrase: string | undefined
    readonly keySource: SigNetKeySource

    constructor(options: SigNetGeneratorOptions) {
        const key = SigNetGenerator.resolveKey(options)
        this.k0 = key.k0
        this.passphrase = key.passphrase
        this.keySource = key.source
        this.tuid = generateEphemeralTuid(options.mfgCode)
        this.senderKey = deriveSenderKey(this.k0)
    }

    getK0(): Buffer {
        return Buffer.from(this.k0)
    }

    getTuid(): Buffer {
        return Buffer.from(this.tuid)
    }

    getSenderKey(): Buffer {
        return Buffer.from(this.senderKey)
    }

    getPassphrase(): string | undefined {
        return this.passphrase
    }

    private static resolveKey(options: SigNetGeneratorOptions): { k0: Buffer; passphrase: string | undefined; source: SigNetKeySource } {
        if (options.k0 !== undefined && (options.key !== undefined || options.passphrase !== undefined)) {
            throw new RangeError('provide only one of k0, key, or passphrase')
        }

        if (options.k0 !== undefined) {
            if (options.k0.length !== K0_KEY_LENGTH) throw new RangeError(`k0 must be ${K0_KEY_LENGTH} bytes`)
            return { k0: Buffer.from(options.k0), passphrase: undefined, source: 'k0' }
        }

        const input = options.passphrase ?? options.key
        if (input instanceof Uint8Array) {
            if (input.length !== K0_KEY_LENGTH) throw new RangeError(`machine-transfer key must be ${K0_KEY_LENGTH} bytes`)
            return { k0: Buffer.from(input), passphrase: undefined, source: 'machine-transfer' }
        }

        const text = input?.trim() ?? ''
        if (/^[0-9a-f]{64}$/i.test(text)) return { k0: parseK0Hex(text), passphrase: undefined, source: 'machine-transfer' }

        if (text.length === 0) {
            for (let attempt = 0; attempt < 100; attempt++) {
                const generated = generateRandomPassphrase()
                if (analysePassphrase(generated).code === SIGNET_PASSPHRASE_VALID) {
                    return { k0: deriveK0FromPassphrase(generated), passphrase: generated, source: 'generated-passphrase' }
                }
            }
            throw new Error('unable to generate a valid passphrase')
        }

        const checks = analysePassphrase(text)
        if (checks.code !== SIGNET_PASSPHRASE_VALID) throw new RangeError(`invalid passphrase (error ${checks.code})`)
        return { k0: deriveK0FromPassphrase(text), passphrase: text, source: 'passphrase' }
    }
}

export default SigNetGenerator
