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

## Sender and Receiver wrappers

For application code, the `SigNetSender` and `SigNetReceiver` wrappers manage
the UDP socket, controller session, sequence numbers, multicast routing, and
packet verification while using the existing low-level Sig-Net implementation:

```ts
import { SigNetReceiver, SigNetSender, deriveSenderKey, parseK0Hex, parseTuidHex, TEST_K0, TEST_TUID } from 'node-sig-net'

const sender = new SigNetSender({
    tuid: parseTuidHex(TEST_TUID),
    senderKey: deriveSenderKey(parseK0Hex(TEST_K0)),
})
await sender.start()
await sender.sendDmx(Buffer.alloc(512), 1)

const receiver = new SigNetReceiver({
    senderKey: deriveSenderKey(parseK0Hex(TEST_K0)),
    universes: [1],
})
receiver.on('level', ({ universe, dmx }) => console.log(universe, dmx))
await receiver.start()
```

`SigNetGenerator` can create the controller credentials from a passphrase,
from a machine-transfer K0, or from blank input (which generates a valid
random passphrase):

```ts
import { SigNetGenerator } from 'node-sig-net'

const credentials = new SigNetGenerator({
    mfgCode: 0x5379,
    key: '', // or a validated passphrase, or a 64-character machine-transfer K0
})

const sender = new SigNetSender({
    tuid: credentials.tuid,
    senderKey: credentials.senderKey,
})
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
