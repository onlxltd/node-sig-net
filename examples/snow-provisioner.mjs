import { SnowIdentity, SnowProvisioner, parseK0Hex, parseTuidHex } from '../dist/index.js'

const targetTuid = parseTuidHex(process.env.SNOW_TUID ?? '537900000010')
const provisioner = new SnowProvisioner({
    managerTuid: parseTuidHex(process.env.SNOW_MANAGER_TUID ?? '537900000001'),
    mfgCode: 0x5379,
    k0: parseK0Hex(process.env.SNOW_K0 ?? '52fcc2e7749f40358ba00b1d557dc11861e89868e139f23014f6a0cfe59cf173'),
    identity: new SnowIdentity(),
})

const result = await provisioner.provision(process.env.SNOW_TLS_HOST ?? '127.0.0.1', Number(process.env.SNOW_TLS_PORT ?? 40000), targetTuid, {
    role: process.env.SNOW_ROLE ?? 'sender',
    authentication: 'tofu',
    confirm: ({ pin, publicKey }) => {
        console.log(`peer key: ${publicKey.toString('hex')}`)
        if (pin) console.log(`PIN: ${pin}`)
        return true
    },
}, { rejectUnauthorized: false })
console.log(`provisioned ${result.tuid.toString('hex').toUpperCase()}`)
