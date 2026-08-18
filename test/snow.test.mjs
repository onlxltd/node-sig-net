import assert from 'node:assert/strict'
import test from 'node:test'
import {
    SnowIdentity,
    buildOtwReopenTlv,
    buildPomWipeTlv,
    buildPublicKeyTlv,
    buildSnowNodePacket,
    deriveSnowKeys,
    parseSnowManifest,
    parseTuidHex,
    TEST_K0,
    TOTW_RT_OTW_REOPEN,
    TOTW_RT_POM_WIPE,
    parseTlvs,
    encodeCoapTcpFrame,
    decodeCoapTcpFrame,
    parsePacket,
    buildSignedPomWipe,
    buildHmacOtwReopen,
    verifyHmacOtwReopen,
    parseK0Hex,
} from '../dist/index.js'

test('SNOW identity signs and verifies raw P-256 signatures', () => {
    const identity = new SnowIdentity()
    const message = Buffer.from('snow-test')
    const signature = identity.sign(message)
    assert.equal(identity.getRawPublicKey().length, 65)
    assert.equal(signature.length, 64)
    assert.equal(identity.verify(message, signature), true)
    assert.equal(identity.verify(Buffer.from('tampered'), signature), false)
})

test('SNOW security TLVs use the specified wire lengths', () => {
    const tuid = parseTuidHex('537900000001')
    const wipe = buildPomWipeTlv(tuid, Buffer.alloc(8), Buffer.alloc(64))
    const reopen = buildOtwReopenTlv({ tuid, signatureType: 'hmac', nonce: Buffer.alloc(8), signature: Buffer.alloc(32) })
    assert.deepEqual(parseTlvs(Buffer.concat([wipe, reopen])).map(tlv => [tlv.typeId, tlv.length]), [[TOTW_RT_POM_WIPE, 78], [TOTW_RT_OTW_REOPEN, 48]])
})

test('SNOW manifests and role keys are derived independently of instances', () => {
    const tuid = parseTuidHex('537900000001')
    const manifest = parseSnowManifest({ 'sig - net_snow_manifest': { pom_public_key: 'key', devices: [{ tuid: '537900000001', public_key: 'device-key' }] } })
    assert.equal(manifest['sig - net_snow_manifest'].devices[0].tuid, '537900000001')
    const keys = deriveSnowKeys(Buffer.from(TEST_K0, 'hex'), tuid)
    assert.equal(keys.managerLocalKey.length, 32)
    assert.notEqual(keys.managerLocalKey.toString('hex'), keys.managerGlobalKey.toString('hex'))
})

test('SNOW CoAP-over-TCP framing round-trips the application packet', () => {
    const packet = buildSnowNodePacket({
        deviceTuid: parseTuidHex('537900000010'),
        mfgCode: 0x5379,
        tlvs: buildPublicKeyTlv(Buffer.alloc(65, 0x04)),
    })
    const frame = encodeCoapTcpFrame(packet)
    const decoded = decodeCoapTcpFrame(frame)
    assert.ok(decoded)
    assert.deepEqual(parsePacket(decoded.packet).tlvs.map(tlv => tlv.typeId), [0x7002])
})

test('SNOW recovery signatures use stable authorization inputs', () => {
    const tuid = parseTuidHex('537900000010')
    const identity = new SnowIdentity()
    const wipe = buildSignedPomWipe(tuid, identity, Buffer.alloc(8, 1))
    assert.equal(parseTlvs(wipe)[0].length, 78)
    const key = parseK0Hex(TEST_K0)
    const reopen = buildHmacOtwReopen({ tuid, managerLocalKey: key, timeoutSeconds: 60, nonce: Buffer.alloc(8, 2) })
    const value = parseTlvs(reopen)[0].value
    assert.equal(verifyHmacOtwReopen({ tuid, managerLocalKey: key, timeoutSeconds: value[7], nonce: value.subarray(8, 16), signature: value.subarray(16) }), true)
})
