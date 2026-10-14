# DNS Message Codec

A zero-dependency JavaScript library for encoding and decoding DNS wire-format messages (RFC 1035, with EDNS(0) OPT support). ESM only, runs on Node.js.

## Usage

```js
import {
  encodeMessage,
  decodeMessage,
  Type,
  Class,
  Opcode,
} from "dns-message-codec";

const buf = encodeMessage({
  header: { id: 0x1234, opcode: Opcode.QUERY, rd: true },
  questions: [
    {
      name: [new TextEncoder().encode("example"), new TextEncoder().encode("org")],
      type: Type.A,
      class: Class.IN,
    },
  ],
  answers: [],
  authorities: [],
  additionals: [],
});

const msg = decodeMessage(buf);
console.log(msg.questions[0].type); // 1
```

## Why this exists

Parsing DNS by hand is fiddly because of name compression pointers, the variable RDATA formats per RR type, and the EDNS(0) OPT pseudo-record that smuggles extra fields into the additional section. This library exists to do exactly that work, once, with no dependencies — so callers building a stub resolver, a DNS firewall, or a test harness can stop copy-pasting RFC 1035 §4.1.4 into every project.

The trade-off: names are represented as arrays of `Uint8Array` labels, never as dotted strings. A label can legally contain a literal dot, which a dotted string cannot round-trip. This is slightly more annoying for the common case but correct for the general case. Callers who want dotted strings must build them themselves; the library does not lie about lossiness.

## Awkward edges you will hit

- **Counts are derived from the section arrays on encode.** If you set `qdcount` in the header, `encodeMessage` ignores it and writes the actual `questions.length`. This prevents the classic bug where the count field disagrees with the section. If you need to lie about counts, post-process the bytes yourself.
- **OPT lives in `additionals`.** The EDNS(0) OPT pseudo-record is not hoisted onto a separate `Message.edns` field; it is a normal `ResourceRecord` with `type === 41` in the additional section, exactly as on the wire. The OPT `class` field carries the requestor UDP payload size and `ttl` carries the extended RCODE/version/flags — set them directly.
- **Compression is decoded but not emitted.** Encoded names are always uncompressed. Decoding follows compression pointers anywhere in the message, including across sections.
- **Unknown RR types are passed as raw `Uint8Array`.** `data` is structured for `A`, `AAAA`, `NS`, `CNAME`, `SOA`, `PTR`, `MX`, `TXT`, `SRV`, and `OPT`; every other type yields a raw byte array under `data`.

## Exported names

`Opcode`, `Rcode`, `Type`, `Class`, `readU16`, `readU32`, `writeU16`, `writeU32`, `decodeName`, `encodeName`, `decodeHeader`, `encodeHeader`, `decodeQuestion`, `encodeQuestion`, `decodeRR`, `encodeRR`, `decodeRdata`, `encodeRdata`, `decodeMessage`, `encodeMessage`.

## Running the tests

```sh
node --test test/
```

## Design notes

The window stores values eagerly rather than keeping running aggregates. Running
sums drift with floating point over long streams, and recomputing from a small
buffer is cheap enough that the drift is not worth the speed.

## Limitations

Values are coerced to floats, so very large integers lose precision. If you need
exact integer aggregates over a window, this is the wrong tool.

## Contributing

Issues and pull requests are welcome. Please keep the dependency list empty —
that constraint is the point of the project, not an oversight.

