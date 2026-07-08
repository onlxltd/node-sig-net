import { createHmac, pbkdf2Sync, randomBytes } from 'crypto'
import {
    DERIVED_KEY_LENGTH,
    HKDF_COUNTER_T1,
    HKDF_INFO_CITIZEN,
    HKDF_INFO_INPUT_MAX,
    HKDF_INFO_MANAGER_GLOBAL,
    HKDF_INFO_MANAGER_LOCAL_PREFIX,
    HKDF_INFO_SENDER,
    K0_KEY_LENGTH,
    PASSPHRASE_GEN_DIGITS,
    PASSPHRASE_GEN_LOWERCASE,
    PASSPHRASE_GEN_SYMBOLS,
    PASSPHRASE_GEN_UPPERCASE,
    PASSPHRASE_GENERATED_LENGTH,
    PASSPHRASE_MAX_LENGTH,
    PASSPHRASE_MIN_LENGTH,
    PASSPHRASE_SYMBOLS,
    PBKDF2_ITERATIONS,
    PBKDF2_SALT,
    SIGNET_ERROR_INVALID_ARG,
    SIGNET_PASSPHRASE_CONSECUTIVE_IDENTICAL,
    SIGNET_PASSPHRASE_CONSECUTIVE_SEQUENTIAL,
    SIGNET_PASSPHRASE_INSUFFICIENT_CLASSES,
    SIGNET_PASSPHRASE_TOO_LONG,
    SIGNET_PASSPHRASE_TOO_SHORT,
    SIGNET_PASSPHRASE_VALID,
    TUID_HEX_LENGTH,
    TUID_LENGTH,
} from './constants.js'
import type { PassphraseChecks } from './types.js'

//==============================================================================
// Sig-Net Protocol Framework - Cryptographic Functions
//==============================================================================
// Upstream description:
// Cryptographic primitives: HMAC-SHA256 (RFC 2104), HKDF-Expand (RFC 5869),
// and key derivation for Sender, Citizen, Manager.
// The C++ SDK uses Windows backends; this native Node port uses crypto
// with the same inputs, outputs, and role info strings.
//==============================================================================

function asBuffer(data: Uint8Array | string): Buffer {
    return Buffer.isBuffer(data) ? data : Buffer.from(data)
}

//------------------------------------------------------------------------------
// HMAC-SHA256 Implementation (RFC 2104)
//
// Computes HMAC-SHA256 digest of a message using the provided key.
//------------------------------------------------------------------------------
export function hmacSha256(key: Uint8Array, message: Uint8Array | string): Buffer {
    return createHmac('sha256', asBuffer(key)).update(asBuffer(message)).digest()
}

//------------------------------------------------------------------------------
// HKDF-Expand Implementation (RFC 5869 Section 2.3)
//
// For Sig-Net, we always need exactly 32 bytes of output (L=32).
// When L <= HashLen (SHA-256 = 32 bytes), HKDF-Expand simplifies to:
//   OKM = HMAC-SHA256(PRK, info || 0x01)
//------------------------------------------------------------------------------
export function hkdfExpand(prk: Uint8Array, info: Uint8Array | string): Buffer {
    const infoBuffer = asBuffer(info)
    if (!prk || !infoBuffer || infoBuffer.length > HKDF_INFO_INPUT_MAX) {
        throw new RangeError('Invalid HKDF arguments')
    }
    return hmacSha256(prk, Buffer.concat([infoBuffer, Buffer.from([HKDF_COUNTER_T1])]))
}

//------------------------------------------------------------------------------
// Key Derivation Helper Functions
//
// These functions derive role-specific keys from the K0 root key using
// HKDF-Expand with the standardized info strings defined in Section 7.3
// of the Sig-Net specification.
//------------------------------------------------------------------------------

// Derive Sender Key (Ks) from K0.
// Uses info string: "Sig-Net-Sender-v1"
export function deriveSenderKey(k0: Uint8Array): Buffer {
    requireLength(k0, K0_KEY_LENGTH, 'k0')
    return hkdfExpand(k0, HKDF_INFO_SENDER)
}

// Derive Citizen Key (Kc) from K0.
// Uses info string: "Sig-Net-Citizen-v1"
export function deriveCitizenKey(k0: Uint8Array): Buffer {
    requireLength(k0, K0_KEY_LENGTH, 'k0')
    return hkdfExpand(k0, HKDF_INFO_CITIZEN)
}

// Derive Manager Global Key (Km_global) from K0.
// Uses info string: "Sig-Net-Manager-v1"
export function deriveManagerGlobalKey(k0: Uint8Array): Buffer {
    requireLength(k0, K0_KEY_LENGTH, 'k0')
    return hkdfExpand(k0, HKDF_INFO_MANAGER_GLOBAL)
}

// Derive Manager Local Key (Km_local) from K0 for a specific TUID.
// Uses info string: "Sig-Net-Manager-v1-{TUID}" where TUID is 12 hex chars.
export function deriveManagerLocalKey(k0: Uint8Array, tuid: Uint8Array): Buffer {
    requireLength(k0, K0_KEY_LENGTH, 'k0')
    requireLength(tuid, TUID_LENGTH, 'tuid')
    return hkdfExpand(k0, `${HKDF_INFO_MANAGER_LOCAL_PREFIX}${tuidToHexString(tuid)}`)
}

//------------------------------------------------------------------------------
// PBKDF2-HMAC-SHA256 Implementation (Section 7.2.3)
//------------------------------------------------------------------------------
export function deriveK0FromPassphrase(passphrase: string): Buffer {
    if (!passphrase) throw new RangeError('passphrase is required')
    return pbkdf2Sync(Buffer.from(passphrase, 'utf8'), PBKDF2_SALT, PBKDF2_ITERATIONS, K0_KEY_LENGTH, 'sha256')
}

// Convert 6-byte TUID to 12-character uppercase hexadecimal string.
export function tuidToHexString(tuid: Uint8Array): string {
    requireLength(tuid, TUID_LENGTH, 'tuid')
    return Buffer.from(tuid).toString('hex').toUpperCase()
}

// Convert 12-character hex string to 6-byte TUID.
export function tuidFromHexString(hex: string): Buffer {
    if (!/^[0-9a-fA-F]{12}$/.test(hex)) throw new RangeError('TUID must be 12 hexadecimal characters')
    return Buffer.from(hex, 'hex')
}

// Generate an ephemeral TUID for software applications (Spec Section 6.6).
// Combines the manufacturer code with a CSPRNG-generated Device ID in the
// ephemeral range 0x80000000-0xFFFFFFEF.
export function generateEphemeralTuid(mfgCode: number): Buffer {
    const random = randomBytes(4)
    let deviceId = random.readUInt32BE(0) | 0x80000000
    if (deviceId >= 0xfffffff0) deviceId = 0xffffffef
    const out = Buffer.alloc(TUID_LENGTH)
    out.writeUInt16BE(mfgCode & 0xffff, 0)
    out.writeUInt32BE(deviceId >>> 0, 2)
    return out
}

//------------------------------------------------------------------------------
// Analyse Passphrase - All Checks in One Pass (Section 7.2.3)
//------------------------------------------------------------------------------
export function analysePassphrase(passphrase: string): { code: number; checks: PassphraseChecks } {
    const length = Buffer.byteLength(passphrase ?? '', 'utf8')
    const checks: PassphraseChecks = {
        length,
        lengthOk: length >= PASSPHRASE_MIN_LENGTH && length <= PASSPHRASE_MAX_LENGTH,
        classCount: 0,
        hasUpper: false,
        hasLower: false,
        hasDigit: false,
        hasSymbol: false,
        classesOk: false,
        noIdentical: true,
        noSequential: true,
    }

    for (const c of passphrase) {
        if (c >= 'A' && c <= 'Z') checks.hasUpper = true
        else if (c >= 'a' && c <= 'z') checks.hasLower = true
        else if (c >= '0' && c <= '9') checks.hasDigit = true
        else if (PASSPHRASE_SYMBOLS.includes(c)) checks.hasSymbol = true
    }
    checks.classCount = [checks.hasUpper, checks.hasLower, checks.hasDigit, checks.hasSymbol].filter(Boolean).length
    checks.classesOk = checks.classCount >= 3
    checks.noIdentical = !/(.)\1\1/u.test(passphrase)
    checks.noSequential = !hasSequentialRun(passphrase)

    let code = SIGNET_PASSPHRASE_VALID
    if (!checks.noIdentical) code = SIGNET_PASSPHRASE_CONSECUTIVE_IDENTICAL
    else if (!checks.noSequential) code = SIGNET_PASSPHRASE_CONSECUTIVE_SEQUENTIAL
    else if (!checks.classesOk) code = SIGNET_PASSPHRASE_INSUFFICIENT_CLASSES
    else if (!checks.lengthOk) code = length < PASSPHRASE_MIN_LENGTH ? SIGNET_PASSPHRASE_TOO_SHORT : SIGNET_PASSPHRASE_TOO_LONG

    return { code, checks }
}

//------------------------------------------------------------------------------
// Passphrase Validation (Section 7.2.3)
//------------------------------------------------------------------------------
export function validatePassphrase(passphrase: string): number {
    return analysePassphrase(passphrase).code
}

//------------------------------------------------------------------------------
// Generate Random Passphrase
//------------------------------------------------------------------------------
export function generateRandomPassphrase(): string {
    const random = randomBytes(PASSPHRASE_GENERATED_LENGTH)
    const all = PASSPHRASE_GEN_UPPERCASE + PASSPHRASE_GEN_LOWERCASE + PASSPHRASE_GEN_DIGITS + PASSPHRASE_GEN_SYMBOLS
    const chars = [pick(PASSPHRASE_GEN_UPPERCASE, random[0] ?? 0), pick(PASSPHRASE_GEN_LOWERCASE, random[1] ?? 0), pick(PASSPHRASE_GEN_DIGITS, random[2] ?? 0)]
    for (let i = 3; i < PASSPHRASE_GENERATED_LENGTH; i++) {
        let c = pick(all, random[i] ?? 0)
        if (c === chars[i - 1]) c = pick(PASSPHRASE_GEN_LOWERCASE, (random[i] ?? 0) + 1)
        chars.push(c)
    }
    return chars.join('')
}

export function parseHexBytes(text: string, byteCount: number): Buffer {
    const token = text.trim().replace(/^0x/i, '')
    if (token.length !== byteCount * 2 || !/^[0-9a-fA-F]+$/.test(token)) {
        throw new RangeError(`Expected ${byteCount} hex bytes`)
    }
    return Buffer.from(token, 'hex')
}

export function parseK0Hex(text: string): Buffer {
    return parseHexBytes(text, K0_KEY_LENGTH)
}

export function parseTuidHex(text: string): Buffer {
    return parseHexBytes(text, TUID_LENGTH)
}

export function parseEndpointValue(text: string): number {
    const token = text.trim()
    const parsed = token.startsWith('$') ? Number.parseInt(token.slice(1), 16) : Number(token)
    if (!Number.isInteger(parsed) || parsed < 0 || parsed > 0xffff) throw new RangeError('endpoint must be 0..65535')
    return parsed
}

export function parseHexWord(text: string): number {
    const token = text.trim().replace(/^0x/i, '')
    if (!/^[0-9a-fA-F]{1,4}$/.test(token)) throw new RangeError('word must be 1..4 hex digits')
    return Number.parseInt(token, 16)
}

export function resultFromThrown(fn: () => unknown): number {
    try {
        fn()
        return 0
    } catch {
        return SIGNET_ERROR_INVALID_ARG
    }
}

function requireLength(data: Uint8Array, len: number, name: string): void {
    if (!data || data.length !== len) throw new RangeError(`${name} must be ${len} bytes`)
}

function pick(chars: string, byte: number): string {
    return chars[byte % chars.length] ?? chars[0]!
}

function hasSequentialRun(passphrase: string): boolean {
    const bytes = Buffer.from(passphrase, 'utf8')
    for (let i = 0; i <= bytes.length - 4; i++) {
        const a = bytes[i]!
        if (bytes[i + 1] === a + 1 && bytes[i + 2] === a + 2 && bytes[i + 3] === a + 3) return true
        if (bytes[i + 1] === a - 1 && bytes[i + 2] === a - 2 && bytes[i + 3] === a - 3) return true
    }
    return false
}

export const DERIVED_KEY_BYTES = DERIVED_KEY_LENGTH
export const TUID_PARSE_ERROR = SIGNET_ERROR_INVALID_ARG
