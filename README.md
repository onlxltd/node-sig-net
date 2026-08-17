> [!WARNING]  
> This library is early access and subject to frequent change.

# node-sig-net

A native TypeScript/Node implementation of the Sig-Net® protocol SDK, ported from [`WayneHowell/public-sig-net-sdk`](https://github.com/WayneHowell/public-sig-net-sdk).

Sig-Net® Designed by and Copyright Singularity (UK) Ltd

```ts
import { buildDMXPacket, calculateMulticastAddress, deriveSenderKey, parseK0Hex, parseTuidHex, sendMulticast } from 'node-sig-net'

const k0 = parseK0Hex('52fcc2e7749f40358ba00b1d557dc11861e89868e139f23014f6a0cfe59cf173')
const senderKey = deriveSenderKey(k0)
const dmxData = Buffer.alloc(512)
const tuid = parseTuidHex('537900000001')

const packet = buildDMXPacket({
    universe: 517,
    dmxData,
    tuid,
    endpoint: 1,
    mfgCode: 0,
    sessionId: 1,
    seqNum: 1,
    senderKey,
    messageId: 1,
})

await sendMulticast(packet, calculateMulticastAddress(517))
```

## Sine Wave Sender/Receiver

Run the receiver in one terminal:

```sh
yarn example:receiver
```

Run the sender in another terminal:

```sh
yarn example:sender
```

Both examples use universe `1`, the test K0/TUID constants, and the folded
multicast address for that universe. If your OS needs an explicit multicast
interface for receive, set `SIGNET_IFACE`, for example:

```sh
SIGNET_IFACE=192.168.1.20 yarn example:receiver
```
