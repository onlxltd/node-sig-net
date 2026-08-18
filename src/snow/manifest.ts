import { readFile } from 'node:fs/promises'

export interface SnowManifestDevice {
    tuid: string
    publicKey: string
}

export interface SnowManifest {
    'sig - net_snow_manifest': {
        pom_public_key: string
        devices: SnowManifestDevice[]
    }
}

export function parseSnowManifest(value: string | SnowManifest): SnowManifest {
    const manifest = typeof value === 'string' ? JSON.parse(value) as unknown : value
    if (!isManifest(manifest)) throw new RangeError('invalid SNOW manifest')
    return manifest
}

export async function loadSnowManifest(path: string): Promise<SnowManifest> {
    return parseSnowManifest(await readFile(path, 'utf8'))
}

export function isManifest(value: unknown): value is SnowManifest {
    if (!value || typeof value !== 'object') return false
    const root = (value as Record<string, unknown>)['sig - net_snow_manifest']
    if (!root || typeof root !== 'object') return false
    const record = root as Record<string, unknown>
    if (typeof record.pom_public_key !== 'string' || !Array.isArray(record.devices)) return false
    return record.devices.every((device) => {
        if (!device || typeof device !== 'object') return false
        const item = device as Record<string, unknown>
        return typeof item.tuid === 'string' && /^[0-9a-fA-F]{12}$/.test(item.tuid) && typeof item.public_key === 'string' && item.public_key.length > 0
    })
}
