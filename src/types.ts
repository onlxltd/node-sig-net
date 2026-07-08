//==============================================================================
// Sig-Net Protocol Framework - Type Definitions
//==============================================================================
// TypeScript counterparts for upstream data structures including SigNet custom
// options, TLV blocks, passphrase checks, and parsed packet results.
//==============================================================================

export interface SigNetOptions {
    securityMode: number
    senderId: Buffer
    mfgCode: number
    sessionId: number
    seqNum: number
    hmac: Buffer
}

export interface TLVBlock {
    typeId: number
    length: number
    value: Buffer
}

export interface PassphraseChecks {
    length: number
    lengthOk: boolean
    classCount: number
    hasUpper: boolean
    hasLower: boolean
    hasDigit: boolean
    hasSymbol: boolean
    classesOk: boolean
    noIdentical: boolean
    noSequential: boolean
}

export interface ParsedPacket {
    version: number
    type: number
    tokenLength: number
    code: number
    messageId: number
    uri: string
    options: SigNetOptions
    payload: Buffer
    tlvs: TLVBlock[]
}
