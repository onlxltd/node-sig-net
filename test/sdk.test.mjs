import assert from 'node:assert/strict'
import test from 'node:test'
import {
    TID_LEVEL,
    TID_POLL_REPLY,
    TID_RT_PROTOCOL_VERSION,
    TID_RT_ROLE_CAPABILITY,
    TID_RT_ENDPOINT_COUNT,
    TID_RT_MULT_OVERRIDE,
    SECURITY_MODE_OPEN,
    SIGNET_OPTION_SECURITY_MODE,
    SIGNET_OPTION_SENDER_ID,
    SIGNET_OPTION_MFG_CODE,
    SIGNET_OPTION_SESSION_ID,
    SIGNET_OPTION_SEQ_NUM,
    SIGNET_OPTION_HMAC,
    TEST_K0,
    TEST_PASSPHRASE,
    TEST_TUID,
    buildDMXPacket,
    buildAnnouncePacket,
    buildNodeLostPacket,
    buildManagerPacket,
    buildGetPayload,
    buildPollPacket,
    buildPollPayload,
    deriveManagerLocalKey,
    parseTidPoll,
    parseTidSetReply,
    calculateMulticastAddress,
    deriveCitizenKey,
    deriveK0FromPassphrase,
    deriveManagerGlobalKey,
    deriveSenderKey,
    SigNetGenerator,
    parseK0Hex,
    parsePacket,
    parseSigNetOptions,
    parseTuidHex,
    validatePassphrase,
    verifyPacketHmac,
    buildComeHomeTlv,
    buildIdentifyTlv,
    buildSnowSNRPPacket,
    parseTlvs,
    TOTW_RT_COME_HOME,
    TOTW_RT_IDENTIFY,
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
    assert.equal(calculateMulticastAddress(517), '239.254.0.81')
    assert.equal(validatePassphrase(TEST_PASSPHRASE), 0)
})

test('generator creates an ephemeral TUID and sender key', () => {
    const generator = new SigNetGenerator({
        mfgCode: 0x5379,
        k0: parseK0Hex(TEST_K0),
    })

    assert.equal(generator.tuid.length, 6)
    assert.equal(generator.tuid.readUInt16BE(0), 0x5379)
    assert.equal(generator.senderKey.toString('hex'), '78981fe02576b2e9e47d916853d5967f34f8ae8aaae46db0495b178a75620e89')
    assert.deepEqual(generator.getTuid(), generator.tuid)
    assert.deepEqual(generator.getSenderKey(), generator.senderKey)
})

test('generator accepts passphrases and machine-transfer K0 keys', () => {
    const passphraseGenerator = new SigNetGenerator({ mfgCode: 0x5379, key: TEST_PASSPHRASE })
    assert.equal(passphraseGenerator.keySource, 'passphrase')
    assert.equal(passphraseGenerator.getK0().toString('hex'), TEST_K0)

    const machineGenerator = new SigNetGenerator({ mfgCode: 0x5379, key: TEST_K0 })
    assert.equal(machineGenerator.keySource, 'machine-transfer')
    assert.equal(machineGenerator.senderKey.toString('hex'), passphraseGenerator.senderKey.toString('hex'))

    assert.throws(() => new SigNetGenerator({ mfgCode: 0x5379, key: 'weak' }), /invalid passphrase/)
})

test('generator creates a valid passphrase when key is blank', () => {
    const generator = new SigNetGenerator({ mfgCode: 0x5379, key: '' })
    assert.equal(generator.keySource, 'generated-passphrase')
    assert.equal(validatePassphrase(generator.passphrase ?? ''), 0)
    assert.equal(generator.senderKey.length, 32)
})

test('startup announce matches the current upstream TLV set', () => {
    const k0 = parseK0Hex(TEST_K0)
    const packet = buildAnnouncePacket({
        tuid: parseTuidHex(TEST_TUID),
        mfgCode: 0x5379,
        productVariantId: 0x0010,
        firmwareVersionId: 1,
        firmwareVersionString: 'ignored by v1.08 announce format',
        protocolVersion: 1,
        roleCapabilityBits: 0x00000003,
        changeCount: 7,
        sessionId: 1,
        seqNum: 1,
        citizenKey: deriveCitizenKey(k0),
        messageId: 2,
    })
    const tlvTypes = parsePacket(packet).tlvs.map((tlv) => tlv.typeId)
    assert.deepEqual(tlvTypes, [TID_POLL_REPLY, TID_RT_PROTOCOL_VERSION, TID_RT_ROLE_CAPABILITY, TID_RT_ENDPOINT_COUNT, TID_RT_MULT_OVERRIDE])
    assert.equal(parsePacket(packet).tlvs[2].length, 4)
})

test('lost-mode announcement uses the node_lost URI', () => {
    const k0 = parseK0Hex(TEST_K0)
    const packet = buildNodeLostPacket({
        tuid: parseTuidHex(TEST_TUID),
        mfgCode: 0x5379,
        productVariantId: 0x0010,
        firmwareVersionId: 1,
        firmwareVersionString: '1.0.0',
        protocolVersion: 1,
        roleCapabilityBits: 1,
        changeCount: 0,
        sessionId: 1,
        seqNum: 1,
        citizenKey: deriveCitizenKey(k0),
        messageId: 3,
    })
    assert.equal(parsePacket(packet).uri, `/sig-net/v1/local/node_lost/${TEST_TUID}/0`)
})

test('manager commands use the manager lane and local manager key', () => {
    const k0 = parseK0Hex(TEST_K0)
    const managerTuid = parseTuidHex(TEST_TUID)
    const targetTuid = parseTuidHex('537900000002')
    const packet = buildManagerPacket({
        managerTuid,
        targetTuid,
        targetEndpoint: 0,
        payload: buildGetPayload(TID_RT_PROTOCOL_VERSION),
        sessionId: 2,
        seqNum: 1,
        managerLocalKey: deriveManagerLocalKey(k0, targetTuid),
        messageId: 4,
    })
    const parsed = parsePacket(packet)
    assert.equal(parsed.uri, '/sig-net/v1/local/manager/537900000002/0')
    assert.equal(verifyPacketHmac(parsed.uri, parsed.options, parsed.payload, deriveManagerLocalKey(k0, targetTuid)), 0)
    assert.equal(parsed.tlvs[0].length, 0)
})

test('poll and set-reply TLVs decode their network-order fields', () => {
    const managerTuid = parseTuidHex(TEST_TUID)
    const poll = parseTidPoll(parsePacket(buildPollPacket({
        managerTuid,
        mfgCode: 0x5379,
        productVariantId: 0x0010,
        tuidLo: parseTuidHex('537900000001'),
        tuidHi: parseTuidHex('5379000000ff'),
        targetEndpoint: 0xffff,
        queryLevel: 2,
        sessionId: 1,
        seqNum: 1,
        managerGlobalKey: deriveManagerGlobalKey(parseK0Hex(TEST_K0)),
        messageId: 5,
    })).tlvs[0].value)
    assert.equal(poll.targetEndpoint, 0xffff)
    assert.equal(poll.queryLevel, 2)
    assert.equal(poll.mfgCode, 0x5379)
    assert.deepEqual(parseTidSetReply(Buffer.from([0, 0x12, 0x34])), { flags: 0, changeCount: 0x1234 })
})

test('open mode requires an empty HMAC option', () => {
    const options = parseSigNetOptions([
        { optionNumber: SIGNET_OPTION_SECURITY_MODE, value: Buffer.from([SECURITY_MODE_OPEN]) },
        { optionNumber: SIGNET_OPTION_SENDER_ID, value: Buffer.alloc(8) },
        { optionNumber: SIGNET_OPTION_MFG_CODE, value: Buffer.alloc(2) },
        { optionNumber: SIGNET_OPTION_SESSION_ID, value: Buffer.alloc(4) },
        { optionNumber: SIGNET_OPTION_SEQ_NUM, value: Buffer.alloc(4) },
        { optionNumber: SIGNET_OPTION_HMAC, value: Buffer.alloc(0) },
    ])
    assert.equal(options.hmac.length, 0)
})

test('SNOW SNRP packets use the universal local scope and unprovisioned mode', () => {
    const managerTuid = parseTuidHex(TEST_TUID)
    const payload = Buffer.concat([
        buildComeHomeTlv(managerTuid, Buffer.from([192, 168, 1, 20]), Buffer.from([255, 255, 255, 0]), Buffer.from([192, 168, 1, 1])),
        buildIdentifyTlv(Buffer.alloc(32, 0x42)),
    ])
    const packet = parsePacket(buildSnowSNRPPacket({ managerTuid, mfgCode: 0x5379, tlvs: payload }))
    assert.equal(packet.uri, '/sig-net/v1/local/snrp')
    assert.equal(packet.options.securityMode, 0xff)
    assert.equal(packet.options.hmac.length, 0)
    assert.deepEqual(parseTlvs(packet.payload).map((tlv) => tlv.typeId), [TOTW_RT_COME_HOME, TOTW_RT_IDENTIFY])
})
