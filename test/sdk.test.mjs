import assert from 'node:assert/strict'
import test from 'node:test'
import {
    TID_LEVEL,
    TEST_K0,
    TEST_PASSPHRASE,
    TEST_TUID,
    buildDMXPacket,
    calculateMulticastAddress,
    deriveCitizenKey,
    deriveK0FromPassphrase,
    deriveManagerGlobalKey,
    deriveSenderKey,
    parseK0Hex,
    parsePacket,
    parseTuidHex,
    validatePassphrase,
    verifyPacketHmac,
} from '../dist/index.js'

test('README crypto vectors match upstream', () => {
    const k0 = deriveK0FromPassphrase(TEST_PASSPHRASE)
    assert.equal(k0.toString('hex'), TEST_K0)
    assert.equal(deriveSenderKey(k0).toString('hex'), '78981fe02576b2e9e47d916853d5967f34f8ae8aaae46db0495b178a75620e89')
    assert.equal(deriveCitizenKey(k0).toString('hex'), '1973cecb72f2506f8b5c442c565f0c6a68aee8a873b8ef26e957b88a7fc54b80')
    assert.equal(deriveManagerGlobalKey(k0).toString('hex'), '2f6b76ffe666dc65504be86828277ec9ef8a04fe329652c233ab537ad434fa0d')
})

test('packet builds, parses, and verifies HMAC', () => {
    const k0 = parseK0Hex(TEST_K0)
    const senderKey = deriveSenderKey(k0)
    const dmxData = Buffer.alloc(512, 0x7f)
    const packet = buildDMXPacket({
        universe: 517,
        dmxData,
        tuid: parseTuidHex(TEST_TUID),
        endpoint: 1,
        mfgCode: 0,
        sessionId: 1,
        seqNum: 1,
        senderKey,
        messageId: 1,
    })
    const parsed = parsePacket(packet)
    assert.equal(parsed.uri, '/sig-net/v1/local/level/517')
    assert.equal(parsed.tlvs[0].typeId, TID_LEVEL)
    assert.equal(parsed.tlvs[0].length, 512)
    assert.equal(verifyPacketHmac(parsed.uri, parsed.options, parsed.payload, senderKey), 0)
})

test('helpers match upstream behavior', () => {
    assert.equal(calculateMulticastAddress(517), '239.254.0.17')
    assert.equal(validatePassphrase(TEST_PASSPHRASE), 0)
})
