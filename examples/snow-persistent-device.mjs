import fs from 'node:fs'
import { SnowDevice, SnowDeviceStore } from '../dist/index.js'

const device = new SnowDevice({
    tuid: Buffer.from(process.env.SNOW_TUID ?? '537900000010', 'hex'),
    mfgCode: 0x5379,
    store: new SnowDeviceStore(process.env.SNOW_STATE ?? './snow-device-state.json'),
    tlsKey: fs.readFileSync(process.env.SNOW_TLS_KEY ?? './snow-device-key.pem'),
    tlsCertificate: fs.readFileSync(process.env.SNOW_TLS_CERT ?? './snow-device-cert.pem'),
    tlsPort: Number(process.env.SNOW_TLS_PORT ?? 40000),
    autoStartOperational: process.env.SNOW_AUTO_START === '1',
})
device.on('provisioned', state => console.log(`persisted SNOW provisioning state for ${state.tuid}`))
device.on('identify', () => console.log('SNOW identify requested'))
device.on('error', error => console.error(error))
await device.start()
console.log(`persistent SNOW device listening on TLS ${device.getTlsPort()}`)
process.once('SIGINT', () => device.close())
