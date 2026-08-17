import { TEST_K0, TEST_TUID, SigNetSender, deriveSenderKey, parseK0Hex, parseTuidHex } from '../dist/index.js'

const universe = 1
const channelCount = 50
const intervalMs = 100

const sender = new SigNetSender({
    tuid: parseTuidHex(TEST_TUID),
    senderKey: deriveSenderKey(parseK0Hex(TEST_K0)),
    endpoint: 1,
    mfgCode: 0x0000,
    sessionId: 1,
})

sender.on('error', (error) => console.error(`Sender error: ${error.message}`))

await sender.start()
console.log(`Sending universe ${universe} sine wave (session ${sender.getSessionId()})`)

let phase = 0
const timer = setInterval(async () => {
    const dmxData = buildSineWaveFrame(phase)

    try {
        await sender.sendDmx(dmxData, universe)
        process.stdout.write(`\rch1=${dmxData[0]}`)
        phase += 0.18
    } catch (error) {
        console.error(`\nSend failed: ${error instanceof Error ? error.message : String(error)}`)
    }
}, intervalMs)

process.on('SIGINT', () => {
    clearInterval(timer)
    sender.close()
    console.log('\nStopping sender')
})

function buildSineWaveFrame(framePhase) {
    const data = Buffer.alloc(channelCount)

    for (let channel = 0; channel < channelCount; channel++) {
        const channelPhase = framePhase + channel * 0.35
        data[channel] = Math.round((Math.sin(channelPhase) + 1) * 127.5)
    }

    return data
}
