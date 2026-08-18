import { SnowController, parseTuidHex } from '../dist/index.js'

const instance = process.env.SNOW_INSTANCE ?? '1'
const tuid = process.env.SNOW_TUID ?? `5379${instance.padStart(8, '0')}`
const controller = new SnowController({
    managerTuid: parseTuidHex(tuid),
    mfgCode: 0x5379,
    port: Number(process.env.SNOW_PORT ?? 5683),
    interfaceAddress: process.env.SIGNET_IFACE,
})

controller.on('deviceDiscovered', device => {
    console.log(`[controller ${instance}] discovered ${device.tuid.toString('hex').toUpperCase()} at ${device.ip}:${device.port} SNOW=${device.supportsSnow}`)
})
controller.on('error', error => console.error(`[controller ${instance}]`, error))

await controller.start()
console.log(`[controller ${instance}] listening on UDP ${process.env.SNOW_PORT ?? 5683}; press Ctrl-C to stop`)
process.once('SIGINT', () => controller.close())
