import { deriveCitizenKey, deriveK0FromPassphrase, deriveManagerGlobalKey, deriveManagerLocalKey, deriveSenderKey } from '../core/crypto.js'
import { K0_KEY_LENGTH } from '../core/constants.js'

export interface SnowDerivedKeys {
    senderKey: Buffer
    citizenKey: Buffer
    managerGlobalKey: Buffer
    managerLocalKey: Buffer
}

export function deriveSnowKeys(k0: Uint8Array, deviceTuid: Uint8Array): SnowDerivedKeys {
    if (k0.length !== K0_KEY_LENGTH) throw new RangeError('k0 must be 32 bytes')
    if (deviceTuid.length !== 6) throw new RangeError('deviceTuid must be 6 bytes')
    return {
        senderKey: deriveSenderKey(k0),
        citizenKey: deriveCitizenKey(k0),
        managerGlobalKey: deriveManagerGlobalKey(k0),
        managerLocalKey: deriveManagerLocalKey(k0, deviceTuid),
    }
}

export function deriveSnowKeysFromPassphrase(passphrase: string, deviceTuid: Uint8Array): SnowDerivedKeys {
    return deriveSnowKeys(deriveK0FromPassphrase(passphrase), deviceTuid)
}
