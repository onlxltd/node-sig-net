import dgram from 'dgram'
import {
    SIGNET_SUCCESS,
    SIGNET_UDP_PORT,
    TEST_K0,
    TID_LEVEL,
    calculateMulticastAddress,
    deriveSenderKey,
    parseK0Hex,
    parsePacket,
    verifyPacketHmac,
} from '../../dist/imports.js'

const universe = 1
const channelCount = 50
const multicastIp = calculateMulticastAddress(universe)
const senderKey = deriveSenderKey(parseK0Hex(TEST_K0))
const iface = process.env.SIGNET_IFACE
const socket = dgram.createSocket({ type: 'udp4', reuseAddr: true })

socket.on('error', (error) => {
    console.error(error.message)
})

socket.on('message', (message, remote) => {
    try {
        const packet = parsePacket(message)

        if (packet.uri !== `/sig-net/v1/local/level/${universe}`) {
            return
        }

        const hmacResult = verifyPacketHmac(packet.uri, packet.options, packet.payload, senderKey)
        if (hmacResult !== SIGNET_SUCCESS) {
            console.warn(`Rejected packet from ${remote.address}:${remote.port}; HMAC failed`)
            return
        }

        const level = packet.tlvs.find((tlv) => tlv.typeId === TID_LEVEL)
        if (!level) {
            return
        }

        const values = [...level.value.subarray(0, channelCount)]
        process.stdout.write(`\rseq=${packet.options.seqNum.toString().padStart(8, ' ')} ${renderValues(values)}`)
    } catch (error) {
        const messageText = error instanceof Error ? error.message : String(error)
        console.warn(`Ignored packet from ${remote.address}:${remote.port}; ${messageText}`)
    }
})

socket.bind(SIGNET_UDP_PORT, () => {
    socket.addMembership(multicastIp, iface)
    console.log(`Listening for universe ${universe} on ${multicastIp}:${SIGNET_UDP_PORT}${iface ? ` via ${iface}` : ''}`)
})

process.on('SIGINT', () => {
    console.log('\nStopping receiver')
    socket.close()
    process.exit(0)
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
