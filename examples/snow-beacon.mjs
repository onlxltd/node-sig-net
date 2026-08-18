import { buildSnowBeaconPacket, parseTuidHex, sendMulticast } from '../dist/index.js'

const tuid = parseTuidHex(process.env.SNOW_TUID ?? '537900000010')
const port = Number(process.env.SNOW_OTW_PORT ?? 40000)
const interval = Number(process.env.SNOW_BEACON_INTERVAL ?? 3000)
const target = process.env.SNOW_BEACON_IP ?? '239.254.255.255'

const packet = buildSnowBeaconPacket({ deviceTuid: tuid, mfgCode: 0x5379, otwPort: port })
const send = async () => {
    const result = await sendMulticast(packet, target, Number(process.env.SNOW_PORT ?? 5683))
    if (result !== 0) console.error(`beacon send failed: ${result}`)
    else console.log(`beacon sent for ${tuid.toString('hex').toUpperCase()} -> ${target}:${process.env.SNOW_PORT ?? 5683}`)
}

await send()
const timer = setInterval(send, interval)
process.once('SIGINT', () => clearInterval(timer))
