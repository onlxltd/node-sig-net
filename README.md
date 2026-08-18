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

## Optional SNOW discovery

SNOW support is exposed separately from the real-time sender and receiver
wrappers. A `SnowController` can listen for unprovisioned device beacons
without changing how `SigNetSender` or `SigNetReceiver` are initialised:

```ts
import { SnowController, parseTuidHex } from 'node-sig-net'

const snow = new SnowController({
    managerTuid: parseTuidHex('537900000001'),
    mfgCode: 0x5379,
})
snow.on('deviceDiscovered', device => console.log(device.tuid, device.ip))
await snow.start()
```

The SNOW layer provides local-scope SNRP/TOTW packet primitives, discovery,
CoAP-over-TCP framing, TLS sessions, and a provisioning orchestrator. SNOW
remains optional and is not required for core Sig-Net use.

For local testing, run a beacon publisher and one or more controllers in
separate terminals:

```sh
yarn example:snow-beacon
SNOW_INSTANCE=1 yarn example:snow-controller
SNOW_INSTANCE=2 yarn example:snow-controller
```

Controllers use `reuseAddr`, so multiple instances can listen on the same UDP
port. Set `SNOW_TUID`, `SNOW_PORT`, `SNOW_OTW_PORT`, or `SIGNET_IFACE` to
customise the test network.

### Local TLS provisioning test

Create a local certificate and run the TLS device and provisioner in separate
terminals:

```sh
yarn example:snow-cert-generator
yarn example:snow-persistent-device
SNOW_ROLE=sender yarn example:snow-provisioner
```

Set `SNOW_CERT_DIR=./.snow-test` to place generated credentials in a
dedicated directory. The generator creates the device TLS credentials and a
secp256r1 manager POM keypair for recovery examples.

The persistent device atomically writes `snow-device-state.json`, closes the
TLS session only after the key bundle is stored, and can transition to the
core UDP sender/node with `SNOW_AUTO_START=1`. The lower-level
`example:snow-device` remains available as a raw framing harness.

SNRP recovery helpers are available through `SnowController`:

```sh
yarn example:snow-recovery
```

`comeHome()` is intentionally unauthenticated as specified by SNOW. POM wipe
and OTW reopen require a caller-provided protocol signature and are exposed as
`pomWipe()` and `otwReopen()`.

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
