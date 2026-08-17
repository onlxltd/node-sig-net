import { TEST_K0, SigNetReceiver, deriveSenderKey, parseK0Hex } from '../dist/index.js'

const universe = 1
const channelCount = 50
const iface = process.env.SIGNET_IFACE

const receiver = new SigNetReceiver({
    senderKey: deriveSenderKey(parseK0Hex(TEST_K0)),
    interfaceAddress: iface,
    universes: [universe],
})

receiver.on('level', ({ sequence, dmx }) => {
    const values = [...dmx.subarray(0, channelCount)]
    process.stdout.write(`\rseq=${sequence.toString().padStart(8, ' ')} ${renderValues(values)}`)
})

receiver.on('error', (error) => console.error(`Receiver error: ${error.message}`))

await receiver.start()
console.log(`Listening for universe ${universe}${iface ? ` via ${iface}` : ''}`)

process.on('SIGINT', () => {
    receiver.close()
    console.log('\nStopping receiver')
})

function renderValues(values) {
    const spark = ' ▁▂▃▄▅▆▇█'
    return values
        .map((value) => {
            const index = Math.min(spark.length - 1, Math.floor((value / 256) * spark.length))
            return spark[index]
        })
        .join('')
}
