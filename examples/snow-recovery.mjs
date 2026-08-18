import { randomBytes } from 'node:crypto'
import { SnowController, parseTuidHex } from '../dist/index.js'

const controller = new SnowController({ managerTuid: parseTuidHex(process.env.SNOW_MANAGER_TUID ?? '537900000001'), mfgCode: 0x5379, port: Number(process.env.SNOW_PORT ?? 5683), interfaceAddress: process.env.SIGNET_IFACE })
controller.on('error', error => console.error(error))
await controller.start()

const targetTuid = parseTuidHex(process.env.SNOW_TUID ?? '537900000010')
await controller.comeHome({
    targetTuid,
    address: Buffer.from([192, 168, 1, 50]),
    netmask: Buffer.from([255, 255, 255, 0]),
    gateway: Buffer.from([192, 168, 1, 1]),
})
console.log(`sent unauthenticated COME_HOME for ${targetTuid.toString('hex').toUpperCase()}`)
console.log('POM wipe and OTW reopen require signatures; use controller.pomWipe() or controller.otwReopen() with protocol-valid signatures.')
setInterval(() => randomBytes(1), 60_000)
