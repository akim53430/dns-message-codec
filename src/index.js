/**
 * Public surface for the DNS Message Codec.
 *
 * Re-exports the wire-level primitives and the message encoder/decoder.  The
 * split between `core.js` and `index.js` is deliberate: core holds the
 * implementation, index is the stable surface callers depend on.  Internal
 * helpers can move inside core without breaking callers.
 */
export {
  Opcode,
  Rcode,
  Type,
  Class,
  readU16,
  readU32,
  writeU16,
  writeU32,
  decodeName,
  encodeName,
  decodeHeader,
  encodeHeader,
  decodeQuestion,
  encodeQuestion,
  decodeRR,
  encodeRR,
  decodeRdata,
  encodeRdata,
  decodeMessage,
  encodeMessage,
} from "./core.js";
