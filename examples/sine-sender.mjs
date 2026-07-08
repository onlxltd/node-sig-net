import dgram from 'dgram'
import {
    SIGNET_UDP_PORT,
    TEST_K0,
    TEST_TUID,
    buildDMXPacket,
    calculateMulticastAddress,
    deriveSenderKey,
    incrementSequence,
    parseK0Hex,
    parseTuidHex,
} from '../dist/index.js'

const universe = 1
const channelCount = 50
const endpoint = 1
const mfgCode = 0x0000
const sessionId = 1
const intervalMs = 100
const multicastIp = calculateMulticastAddress(universe)
const senderKey = deriveSenderKey(parseK0Hex(TEST_K0))
const tuid = parseTuidHex(TEST_TUID)
const socket = dgram.createSocket('udp4')

let seqNum = 1
let messageId = 1
let phase = 0

socket.bind(() => {
    socket.setMulticastTTL(32)
    socket.setMulticastLoopback(true)
    console.log(`Sending universe ${universe} sine wave to ${multicastIp}:${SIGNET_UDP_PORT}`)

    setInterval(() => {
        const dmxData = buildSineWaveFrame(phase)
        const packet = buildDMXPacket({
            universe,
            dmxData,
            tuid,
            endpoint,
            mfgCode,
            sessionId,
            seqNum,
            senderKey,
            messageId,
        })

        socket.send(packet, SIGNET_UDP_PORT, multicastIp, (error) => {
            if (error) {
                console.error(error.message)
            }
        })

        process.stdout.write(`\rseq=${seqNum.toString().padStart(8, ' ')} msg=${messageId.toString().padStart(5, ' ')} ch1=${dmxData[0]}`)
        seqNum = incrementSequence(seqNum)
        messageId = messageId >= 0xffff ? 1 : messageId + 1
        phase += 0.18
    }, intervalMs)
})

process.on('SIGINT', () => {
    console.log('\nStopping sender')
    socket.close()
    process.exit(0)
})

function buildSineWaveFrame(framePhase) {
    const data = Buffer.alloc(channelCount)

    for (let channel = 0; channel < channelCount; channel++) {
        const channelPhase = framePhase + channel * 0.35
        data[channel] = Math.round((Math.sin(channelPhase) + 1) * 127.5)
    }

    return data
}
