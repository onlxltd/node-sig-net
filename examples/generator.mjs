import { SigNetGenerator } from '../dist/index.js'

const key = process.argv[2] ?? ''
const generator = new SigNetGenerator({
    mfgCode: 0x5379,
    key,
})

console.log(`Key source: ${generator.keySource}`)
if (generator.passphrase !== undefined) console.log(`Passphrase: ${generator.passphrase}`)
console.log(`K0:         ${generator.k0.toString('hex')}`)
console.log(`TUID:       ${generator.tuid.toString('hex')}`)
console.log(`Sender key: ${generator.senderKey.toString('hex')}`)
