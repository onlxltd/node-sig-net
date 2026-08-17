import fs from 'fs'
import path from 'path'
import { execFileSync } from 'child_process'

const explicitUpstream = process.argv[2]
const defaultCheckout = path.join('.upstream', 'public-sig-net-sdk')
const upstream = explicitUpstream ?? defaultCheckout

if (!explicitUpstream) {
    if (!fs.existsSync(upstream)) {
        fs.mkdirSync(path.dirname(upstream), { recursive: true })
        execFileSync('git', ['clone', '--depth', '1', 'https://github.com/WayneHowell/public-sig-net-sdk.git', upstream], { stdio: 'inherit' })
    } else {
        execFileSync('git', ['-C', upstream, 'pull', '--ff-only'], { stdio: 'inherit' })
    }
}

const headerPath = path.join(upstream, 'sig-net-constants.hpp')
const header = fs.readFileSync(headerPath, 'utf8')
const lines = []
const apostrophe = String.fromCharCode(39)
let exportedCount = 0

for (const rawLine of header.split(/\r?\n/)) {
    const trimmed = rawLine.trim()

    if (trimmed.startsWith('//')) {
        lines.push(trimmed)
        continue
    }

    if (trimmed === '') {
        if (lines.at(-1) !== '') lines.push('')
        continue
    }

    const numeric = trimmed.match(/^static const (?:uint(?:8|16|32)_t|int32_t)\s+([A-Za-z0-9_]+)\s*=\s*([^;]+);\s*(\/\/.*)?$/)
    if (numeric) {
        const [, name, rawValue, comment = ''] = numeric
        let value = rawValue
            .trim()
            .replace(/u$/i, '')
            .replace(/\(\(uint32_t\)\s*([A-Za-z_][A-Za-z0-9_]*)\s*<<\s*16\)\s*\|/g, '($1 << 16) |')
            .replace(/\bstatic_cast<[^>]+>\(([^()]*)\)/g, '($1)')
        if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)) continue
        lines.push(`export const ${name} = ${value}${comment ? ` ${comment}` : ''}`)
        exportedCount++
        continue
    }

    const string = trimmed.match(/^static const char\*\s+([A-Za-z0-9_]+)\s*=\s*"([^"]*)";\s*(\/\/.*)?$/)
    if (string) {
        const [, name, value, comment = ''] = string
        if (value.includes(apostrophe)) {
            lines.push('// prettier-ignore')
        }
        lines.push(`export const ${name} = ${toSingleQuotedString(value)}${comment ? ` ${comment}` : ''}`)
        exportedCount++
    }
}

const out = lines.join('\n').replace(/\n{3,}/g, '\n\n')
fs.writeFileSync(path.join('src', 'generated-constants.ts'), out)
console.log(`Wrote src/generated-constants.ts with ${exportedCount} constants.`)

function toSingleQuotedString(value) {
    const escapedApostrophe = '\\' + apostrophe
    return `'${value.replace(/\\/g, '\\\\').replace(/'/g, escapedApostrophe)}'`
}
