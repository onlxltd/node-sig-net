import { execFileSync } from 'node:child_process'
import { generateKeyPairSync } from 'node:crypto'
import { mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

const outputDir = process.env.SNOW_CERT_DIR ?? '.'
const commonName = process.env.SNOW_CERT_CN ?? 'snow-device'
const days = process.env.SNOW_CERT_DAYS ?? '365'
mkdirSync(outputDir, { recursive: true })

const deviceKey = join(outputDir, 'snow-device-key.pem')
const deviceCert = join(outputDir, 'snow-device-cert.pem')
execFileSync('openssl', ['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', deviceKey], { stdio: 'inherit' })
execFileSync('openssl', ['req', '-new', '-x509', '-key', deviceKey, '-out', deviceCert, '-days', days, '-subj', `/CN=${commonName}`], { stdio: 'inherit' })

const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
writeFileSync(join(outputDir, 'snow-manager-pom-key.pem'), privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 })
writeFileSync(join(outputDir, 'snow-manager-pom-public.pem'), publicKey.export({ type: 'spki', format: 'pem' }))

console.log(`Generated SNOW credentials in ${outputDir}`)
console.log(`  TLS private key: ${deviceKey}`)
console.log(`  TLS certificate: ${deviceCert}`)
console.log(`  POM private key: ${join(outputDir, 'snow-manager-pom-key.pem')}`)
console.log(`  POM public key:  ${join(outputDir, 'snow-manager-pom-public.pem')}`)
