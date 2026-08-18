import assert from 'node:assert/strict'
import test from 'node:test'
import {
    SnowIdentity,
    buildOtwReopenTlv,
    buildPomWipeTlv,
    deriveSnowKeys,
    parseSnowManifest,
    parseTuidHex,
    TEST_K0,
    TOTW_RT_OTW_REOPEN,
    TOTW_RT_POM_WIPE,
    parseTlvs,
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
