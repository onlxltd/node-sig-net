import fs from 'node:fs'
import tls from 'node:tls'
import { buildPublicKeyTlv, buildSnowNodePacket, decodeCoapTcpFrame, encodeCoapTcpFrame, parsePacket } from '../dist/index.js'
import { X509Certificate } from 'node:crypto'

const keyPath = process.env.SNOW_TLS_KEY ?? './snow-device-key.pem'
const certPath = process.env.SNOW_TLS_CERT ?? './snow-device-cert.pem'
const deviceTuid = Buffer.from(process.env.SNOW_TUID ?? '537900000010', 'hex')
if (!fs.existsSync(keyPath) || !fs.existsSync(certPath)) {
    throw new Error(`TLS certificate files not found. Set SNOW_TLS_KEY and SNOW_TLS_CERT, or create them with openssl.`)
}

const server = tls.createServer({ key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath), minVersion: 'TLSv1.3' }, socket => {
    const certificate = new X509Certificate(fs.readFileSync(certPath))
    const jwk = certificate.publicKey.export({ format: 'jwk' })
    const decode = value => Buffer.from(value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - (value.length % 4)) % 4), 'base64')
    const publicKey = Buffer.concat([Buffer.from([4]), decode(jwk.x), decode(jwk.y)])
    socket.write(encodeCoapTcpFrame(buildSnowNodePacket({ deviceTuid, mfgCode: 0x5379, tlvs: buildPublicKeyTlv(publicKey) })))
    let buffer = Buffer.alloc(0)
    socket.on('data', chunk => {
        buffer = Buffer.concat([buffer, chunk])
        while (true) {
            const frame = decodeCoapTcpFrame(buffer)
            if (!frame) break
            buffer = buffer.subarray(frame.bytesConsumed)
            const packet = parsePacket(frame.packet)
            console.log(`received ${packet.uri}: ${packet.tlvs.map(tlv => `0x${tlv.typeId.toString(16)}`).join(', ')}`)
        }
    })
})

server.listen(Number(process.env.SNOW_TLS_PORT ?? 40000), process.env.SNOW_TLS_HOST ?? '0.0.0.0', () => {
    console.log(`SNOW TLS device listening on ${process.env.SNOW_TLS_PORT ?? 40000}`)
})
process.once('SIGINT', () => server.close())
