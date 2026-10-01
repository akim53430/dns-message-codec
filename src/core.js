/**
 * DNS wire-format codec.
 *
 * Design choices, stated plainly so the tests and users share one mind:
 *
 * - This is a pure encoder/decoder for RFC 1035 (with EDNS(0) OPT support).
 *   No network I/O. No caching. No retries. Just bytes <-> structured object.
 *
 * - Names are stored as arrays of labels, never as dotted strings.  Dotted
 *   strings are lossy: a label that contains a literal dot is a perfectly
 *   legal DNS name that a dotted string cannot represent.  Encoding and
 *   decoding therefore operate on Uint8Array label buffers.  Tests assert on
 *   label arrays.  Callers who want dotted strings must build them themselves.
 *
 * - RDATA is decoded for the most common Internet class types (A, AAAA, NS,
 *   CNAME, SOA, PTR, MX, TXT, SRV, and the EDNS OPT pseudo-record).  Every
 *   other type is returned as a raw Uint8Array copy under the key `rdata`.
 *   This keeps the decoder total: it never throws on an unknown type.
 *
 * - EDNS(0) OPT pseudo-records are represented as regular ResourceRecord
 *   objects whose `type` is 41 and whose `rdata` contains the option list
 *   (decoded from the wire as an array of {code, data} when present).  We do
 *   NOT hide OPT behind a separate field on the Message; it lives in the
 *   additional section exactly as it does on the wire.  This is one
 *   interpretation and we stick to it.
 *
 * - Compression is fully supported on decode (following pointers as in RFC
 *   1035 section 4.1.4) but is NOT used on encode.  Encoded names are always
 *   uncompressed.  This trades wire size for simplicity and for the ability
 *   to slice any record's bytes back out without re-running the resolver.
 *   A 12-byte header + a few hundred records is still well inside a 512-byte
 *   UDP payload for ordinary queries; callers who need EDNS payload sizes can
 *   set them via the OPT record.
 */

// --- Constants ---------------------------------------------------------------

/** DNS opcodes (section 4.1.1). */
export const Opcode = Object.freeze({
  QUERY: 0,
  IQUERY: 1,
  STATUS: 2,
  // 3 is reserved.
  NOTIFY: 4,
  UPDATE: 5,
  DSO: 6,
});

/** DNS response codes (section 4.1.1, plus RFC 6895). */
export const Rcode = Object.freeze({
  NOERROR: 0,
  FORMERR: 1,
  SERVFAIL: 2,
  NXDOMAIN: 3,
  NOTIMP: 4,
  REFUSED: 5,
  YXDOMAIN: 6,
  YXRRSET: 7,
  NXRRSET: 8,
  NOTAUTH: 9,
  NOTZONE: 10,
});

/** RR types we know how to parse RDATA for. */
export const Type = Object.freeze({
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  OPT: 41,
  // 257 = CAA is left as raw rdata intentionally; the brief does not require
  // its structured form and partial handling invites bugs.
});

/**
 * The Internet class.  We only handle IN (1) at the type level.  CS (2), CH
 * (3), and HS (4) are historical; RR class is still carried verbatim.
 */
export const Class = Object.freeze({
  IN: 1,
  CS: 2,
  CH: 3,
  HS: 4,
  NONE: 254,
  ANY: 255,
});

// --- Bit helpers -----------------------------------------------------------

/**
 * Read an unsigned 16-bit big-endian integer at offset `o`.
 * Keeping these inline avoids repeated DataView allocation in hot loops.
 */
export function readU16(buf, o) {
  return (buf[o] << 8) | buf[o + 1];
}

/** Read an unsigned 32-bit big-endian integer at offset `o`. */
export function readU32(buf, o) {
  return (
    (buf[o] << 24) |
    (buf[o + 1] << 16) |
    (buf[o + 2] << 8) |
    buf[o + 3]
  ) >>> 0;
}

/** Write an unsigned 16-bit big-endian integer to offset `o`. */
export function writeU16(arr, v) {
  arr.push((v >>> 8) & 0xff, v & 0xff);
}

/** Write an unsigned 32-bit big-endian integer to offset `o`. */
export function writeU32(arr, v) {
  arr.push(
    (v >>> 24) & 0xff,
    (v >>> 16) & 0xff,
    (v >>> 8) & 0xff,
    v & 0xff,
  );
}

// --- Names ------------------------------------------------------------------

/**
 * Decode a single <domain-name> starting at byte offset `o`.
 *
 * Returns `{ name: Uint8Array[], end: number }` where `end` is the offset
 * immediately after the name's bytes on the wire (after following pointers;
 * that is, the offset to continue parsing subsequent fields).
 *
 * `name` is an array of labels, each label a fresh Uint8Array copy.  The root
 * (".") is the empty array `[]`.  We return copies, not slices of `buf`, so
 * callers can retain names safely after `buf` is reused.
 *
 * Pointer loops raise.  RFC 1035 section 4.1.4 mandates compression pointers
 * must always point backwards; a forward or self pointer is malformed input.
 */
export function decodeName(buf, o) {
  const labels = [];
  let i = o;
  let jumped = false;
  let afterPointer = 0; // the offset to return as `end` once we jump
  let safety = 0; // pointer-following iteration cap
  const seen = new Set(); // set of offsets at which we followed a pointer

  for (;;) {
    if (i >= buf.length) {
      throw new RangeError("truncated name");
    }
    const len = buf[i];
    if (len === 0) {
      i += 1;
      break;
    }
    // High two bits set => compression pointer (RFC 1035 §4.1.4).
    if ((len & 0xc0) === 0xc0) {
      if (i + 1 >= buf.length) {
        throw new RangeError("truncated compression pointer");
      }
      const ptr = ((len & 0x3f) << 8) | buf[i + 1];
      if (!jumped) {
        afterPointer = i + 2;
      }
      if (seen.has(ptr)) {
        throw new Error("compression pointer loop");
      }
      seen.add(ptr);
      i = ptr;
      jumped = true;
      if (++safety > 256) {
        throw new Error("too many compression jumps");
      }
      continue;
    }
    // The two high bits being 0b01 or 0b10 is reserved and malformed.
    if ((len & 0xc0) !== 0) {
      throw new Error("reserved label length bits");
    }
    if (i + 1 + len > buf.length) {
      throw new RangeError("truncated label");
    }
    // Copy so callers can hold the label beyond the life of `buf`.
    labels.push(buf.subarray(i + 1, i + 1 + len));
    i += 1 + len;
  }

  // Make each label an independently-owned copy with a clean byteOffset.
  const out = labels.map((l) => Uint16Array.from(l.length ? [l.length] : []));
  // The above is a no-op guard against empty; the real copy is below.
  const owned = labels.map((l) => {
    const c = new Uint8Array(l.length);
    c.set(l);
    return c;
  });
  void out; // silence the unused intermediate in a way the linter can follow

  return {
    name: owned,
    end: jumped ? afterPointer : i,
  };
}

/**
 * Encode a name (array of Uint8Array labels) into `arr` (a push target).
 * No compression is performed.  The root name `[]` encodes as a single 0x00.
 */
export function encodeName(arr, name) {
  if (!Array.isArray(name)) {
    throw new TypeError("name must be an array of labels");
  }
  for (const label of name) {
    if (!(label instanceof Uint8Array)) {
      throw new TypeError("each label must be a Uint8Array");
    }
    if (label.length === 0) {
      // Empty labels are not legal in the middle of a name; a zero-length
      // label IS the root terminator, which we emit explicitly at the end.
      throw new Error("empty label in name");
    }
    if (label.length > 63) {
      throw new Error("label too long");
    }
    arr.push(label.length);
    for (let k = 0; k < label.length; k++) arr.push(label[k]);
  }
  arr.push(0);
}

// --- Header -----------------------------------------------------------------

/**
 * Encode a 12-byte DNS header into `arr`.
 *
 * The header object shape is documented on `decodeHeader`.  Booleans default
 * to false; numbers default to 0.  We never read fields we did not define.
 */
export function encodeHeader(arr, h) {
  const id = h.id >>> 0;
  writeU16(arr, id & 0xffff);

  const qr = h.qr ? 1 : 0;
  const opcode = (h.opcode ?? 0) & 0x0f;
  const aa = h.aa ? 1 : 0;
  const tc = h.tc ? 1 : 0;
  const rd = h.rd ? 1 : 0;
  const ra = h.ra ? 1 : 0;
  const z = 0; // reserved, must be zero on encode
  const rcode = (h.rcode ?? 0) & 0x0f;
  const flags =
    (qr << 15) |
    (opcode << 11) |
    (aa << 10) |
    (tc << 9) |
    (rd << 8) |
    (ra << 7) |
    (z << 4) |
    rcode;
  writeU16(arr, flags);

  writeU16(arr, h.qdcount ?? 0);
  writeU16(arr, h.ancount ?? 0);
  writeU16(arr, h.nscount ?? 0);
  writeU16(arr, h.arcount ?? 0);
}

/**
 * Decode the 12-byte DNS header at offset `o`.  Returns the header and the
 * offset after the header (always o+12, but returning it keeps calls uniform).
 */
export function decodeHeader(buf, o) {
  if (o + 12 > buf.length) {
    throw new RangeError("truncated header");
  }
  const id = readU16(buf, o);
  const flags = readU16(buf, o + 2);
  return {
    id,
    qr: ((flags >>> 15) & 0x1) === 1,
    opcode: (flags >>> 11) & 0x0f,
    aa: ((flags >>> 10) & 0x1) === 1,
    tc: ((flags >>> 9) & 0x1) === 1,
    rd: ((flags >>> 8) & 0x1) === 1,
    ra: ((flags >>> 7) & 0x1) === 1,
    z: (flags >>> 4) & 0x7,
    rcode: flags & 0x0f,
    qdcount: readU16(buf, o + 4),
    ancount: readU16(buf, o + 6),
    nscount: readU16(buf, o + 8),
    arcount: readU16(buf, o + 10),
    end: o + 12,
  };
}

// --- Questions --------------------------------------------------------------

/**
 * Encode a question into `arr`.  A question is:
 *   { name: Uint8Array[], type: number, class: number }
 */
export function encodeQuestion(arr, q) {
  encodeName(arr, q.name);
  writeU16(arr, q.type & 0xffff);
  writeU16(arr, q.class & 0xffff);
}

/** Decode a single question at offset `o`. */
export function decodeQuestion(buf, o) {
  const { name, end } = decodeName(buf, o);
  if (end + 4 > buf.length) {
    throw new RangeError("truncated question");
  }
  return {
    name,
    type: readU16(buf, end),
    class: readU16(buf, end + 2),
    end: end + 4,
  };
}

// --- Resource Records -------------------------------------------------------

/**
 * Encode an RR into `arr`.  An RR is:
 *   {
 *     name: Uint8Array[],
 *     type: number,
 *     class: number,
 *     ttl: number,
 *     data: object | Uint8Array  // structured form for known types,
 *                                 // raw bytes otherwise
 *   }
 *
 * For the OPT pseudo-RR, `class` carries the requestor's UDP payload size
 * (per RFC 6891) and `ttl` carries extended-rcode/flags/version fields; we do
 * not try to be clever about that here — callers set them directly.
 */
export function encodeRR(arr, rr) {
  encodeName(arr, rr.name);
  writeU16(arr, rr.type & 0xffff);
  writeU16(arr, rr.class & 0xffff);
  writeU32(arr, rr.ttl >>> 0);

  const rdata = encodeRdata(rr.type, rr.data);
  writeU16(arr, rdata.length);
  for (let k = 0; k < rdata.length; k++) arr.push(rdata[k]);
}

/**
 * Decode a single RR at offset `o`.  Returns the structured RR.  For known
 * types, `data` is the parsed object; for all other types, `data` is a fresh
 * Uint8Array copy of the RDATA.
 */
export function decodeRR(buf, o) {
  const { name, end } = decodeName(buf, o);
  if (end + 10 > buf.length) {
    throw new RangeError("truncated RR fixed fields");
  }
  const type = readU16(buf, end);
  const cls = readU16(buf, end + 2);
  const ttl = readU32(buf, end + 4);
  const rdlen = readU16(buf, end + 8);
  const rdataStart = end + 10;
  if (rdataStart + rdlen > buf.length) {
    throw new RangeError("truncated RDATA");
  }
  const data = decodeRdata(buf, rdataStart, rdlen, type);
  return {
    name,
    type,
    class: cls,
    ttl,
    data,
    end: rdataStart + rdlen,
  };
}

// --- RDATA encoders ---------------------------------------------------------

/**
 * Encode structured `data` for `type` to a fresh Uint8Array.  Unknown types
 * accept a Uint8Array directly.  This totality is important: callers building
 * arbitrary RRs never branch on type.
 */
export function encodeRdata(type, data) {
  const out = [];
  switch (type) {
    case Type.A:
      return encodeA(data);
    case Type.AAAA:
      return encodeAAAA(data);
    case Type.NS:
    case Type.CNAME:
    case Type.PTR:
      return encodeNameRR(data);
    case Type.SOA:
      return encodeSOA(data);
    case Type.MX:
      return encodeMX(data);
    case Type.TXT:
      return encodeTXT(data);
    case Type.SRV:
      return encodeSRV(data);
    case Type.OPT:
      return encodeOPT(data);
    default:
      if (!(data instanceof Uint8Array)) {
        throw new TypeError("unknown RR type requires Uint8Array rdata");
      }
      const c = new Uint8Array(data.length);
      c.set(data);
      return c;
  }
}

/** A record: data is [a,b,c,d]. */
function encodeA(d) {
  if (!Array.isArray(d) || d.length !== 4) {
    throw new TypeError("A data must be a 4-byte array");
  }
  return new Uint8Array(d.map((b) => b & 0xff));
}

/** AAAA record: data is a 16-byte array. */
function encodeAAAA(d) {
  if (!Array.isArray(d) || d.length !== 16) {
    throw new TypeError("AAAA data must be a 16-byte array");
  }
  return new Uint8Array(d.map((b) => b & 0xff));
}

/** NS/CNAME/PTR: data is a name (array of labels). */
function encodeNameRR(d) {
  const arr = [];
  encodeName(arr, d);
  return new Uint8Array(arr);
}

/** SOA record. */
function encodeSOA(d) {
  const arr = [];
  encodeName(arr, d.mname);
  encodeName(arr, d.rname);
  writeU32(arr, d.serial >>> 0);
  writeU32(arr, d.refresh >>> 0);
  writeU32(arr, d.retry >>> 0);
  writeU32(arr, d.expire >>> 0);
  writeU32(arr, d.minimum >>> 0);
  return new Uint8Array(arr);
}

/** MX record. */
function encodeMX(d) {
  const arr = [];
  writeU16(arr, d.preference & 0xffff);
  encodeName(arr, d.exchange);
  return new Uint8Array(arr);
}

/** TXT record: data is an array of string -> Uint8Array character strings. */
function encodeTXT(d) {
  if (!Array.isArray(d)) {
    throw new TypeError("TXT data must be an array of Uint8Array");
  }
  const arr = [];
  for (const cs of d) {
    let bytes;
    if (cs instanceof Uint8Array) {
      bytes = cs;
    } else if (typeof cs === "string") {
      bytes = new TextEncoder().encode(cs);
    } else {
      throw new TypeError("TXT character-string must be string or Uint8Array");
    }
    if (bytes.length > 255) {
      throw new Error("TXT character-string too long");
    }
    arr.push(bytes.length);
    for (let k = 0; k < bytes.length; k++) arr.push(bytes[k]);
  }
  return new Uint8Array(arr);
}

/** SRV record. */
function encodeSRV(d) {
  const arr = [];
  writeU16(arr, d.priority & 0xffff);
  writeU16(arr, d.weight & 0xffff);
  writeU16(arr, d.port & 0xffff);
  encodeName(arr, d.target);
  return new Uint8Array(arr);
}

/**
 * OPT pseudo-RR.  `data` is an array of { code, data: Uint8Array }.  We copy
 * option data so callers can reuse buffers.
 */
function encodeOPT(d) {
  const arr = [];
  const opts = Array.isArray(d) ? d : [];
  for (const opt of opts) {
    writeU16(arr, opt.code & 0xffff);
    const optData =
      opt.data instanceof Uint8Array ? opt.data : new Uint8Array(opt.data ?? []);
    writeU16(arr, optData.length);
    for (let k = 0; k < optData.length; k++) arr.push(optData[k]);
  }
  return new Uint8Array(arr);
}

// --- RDATA decoders ---------------------------------------------------------

/**
 * Decode RDATA of length `rdlen` starting at `start` in `buf` for RR `type`.
 * Returns structured data for known types, or a Uint8Array copy otherwise.
 *
 * Names inside RDATA may use compression that points back into the *full*
 * message, so decodeName is given the whole `buf`, not a sub-slice.
 */
export function decodeRdata(buf, start, rdlen, type) {
  const end = start + rdlen;
  switch (type) {
    case Type.A:
      return decodeA(buf, start, rdlen);
    case Type.AAAA:
      return decodeAAAA(buf, start, rdlen);
    case Type.NS:
    case Type.CNAME:
    case Type.PTR:
      return decodeName(buf, start).name;
    case Type.SOA:
      return decodeSOA(buf, start, rdlen);
    case Type.MX:
      return decodeMX(buf, start, rdlen);
    case Type.TXT:
      return decodeTXT(buf, start, rdlen);
    case Type.SRV:
      return decodeSRV(buf, start, rdlen);
    case Type.OPT:
      return decodeOPT(buf, start, rdlen);
    default: {
      const c = new Uint8Array(rdlen);
      c.set(buf.subarray(start, end));
      return c;
    }
  }
}

function decodeA(buf, start, rdlen) {
  if (rdlen !== 4) throw new Error("bad A rdlen");
  return [buf[start], buf[start + 1], buf[start + 2], buf[start + 3]];
}

function decodeAAAA(buf, start, rdlen) {
  if (rdlen !== 16) throw new Error("bad AAAA rdlen");
  const out = new Array(16);
  for (let i = 0; i < 16; i++) out[i] = buf[start + i];
  return out;
}

function decodeSOA(buf, start, rdlen) {
  const mname = decodeName(buf, start);
  const rname = decodeName(buf, mname.end);
  if (rname.end + 20 > start + rdlen) {
    throw new RangeError("truncated SOA");
  }
  const o = rname.end;
  return {
    mname: mname.name,
    rname: rname.name,
    serial: readU32(buf, o),
    refresh: readU32(buf, o + 4),
    retry: readU32(buf, o + 8),
    expire: readU32(buf, o + 12),
    minimum: readU32(buf, o + 16),
  };
}

function decodeMX(buf, start, rdlen) {
  if (rdlen < 3) throw new RangeError("truncated MX");
  const preference = readU16(buf, start);
  const exchange = decodeName(buf, start + 2);
  return { preference, exchange: exchange.name };
}

function decodeTXT(buf, start, rdlen) {
  const out = [];
  let i = start;
  const end = start + rdlen;
  while (i < end) {
    const len = buf[i];
    i += 1;
    if (i + len > end) throw new RangeError("truncated TXT string");
    const c = new Uint8Array(len);
    c.set(buf.subarray(i, i + len));
    out.push(c);
    i += len;
  }
  return out;
}

function decodeSRV(buf, start, rdlen) {
  if (rdlen < 7) throw new RangeError("truncated SRV");
  const priority = readU16(buf, start);
  const weight = readU16(buf, start + 2);
  const port = readU16(buf, start + 4);
  const target = decodeName(buf, start + 6);
  return { priority, weight, port, target: target.name };
}

function decodeOPT(buf, start, rdlen) {
  const out = [];
  let i = start;
  const end = start + rdlen;
  while (i + 4 <= end) {
    const code = readU16(buf, i);
    const len = readU16(buf, i + 2);
    i += 4;
    if (i + len > end) throw new RangeError("truncated OPT option");
    const c = new Uint8Array(len);
    c.set(buf.subarray(i, i + len));
    out.push({ code, data: c });
    i += len;
  }
  if (i !== end) throw new RangeError("OPT options misaligned");
  return out;
}

// --- Whole messages ---------------------------------------------------------

/**
 * Encode a Message to a fresh Uint8Array.
 *
 * Message shape:
 *   {
 *     header: Header,
 *     questions: Question[],
 *     answers: RR[],
 *     authorities: RR[],
 *     additionals: RR[],
 *   }
 *
 * The header's qd/anc/ns/ar counts are taken FROM the arrays, not from the
 * header fields — the header counts are ignored on encode.  This prevents a
 * mismatch between the count field and the actual section lengths, which is a
 * real bug source.  If a caller wants to lie about counts they must do it by
 * post-processing the bytes.
 */
export function encodeMessage(msg) {
  const arr = [];
  const h = { ...msg.header };
  h.qdcount = msg.questions ? msg.questions.length : 0;
  h.ancount = msg.answers ? msg.answers.length : 0;
  h.nscount = msg.authorities ? msg.authorities.length : 0;
  h.arcount = msg.additionals ? msg.additionals.length : 0;
  encodeHeader(arr, h);
  if (msg.questions) for (const q of msg.questions) encodeQuestion(arr, q);
  if (msg.answers) for (const rr of msg.answers) encodeRR(arr, rr);
  if (msg.authorities) for (const rr of msg.authorities) encodeRR(arr, rr);
  if (msg.additionals) for (const rr of msg.additionals) encodeRR(arr, rr);
  return new Uint8Array(arr);
}

/**
 * Decode a full DNS message from `buf`.  Decodes exactly the counts advertised
 * in the header.  If the buffer has trailing bytes, they are ignored (a real
 * DNS server may pad; we do not require the buffer to be exactly trimmed).
 * If the buffer is too short, a RangeError is thrown.
 */
export function decodeMessage(buf) {
  if (!(buf instanceof Uint8Array)) {
    throw new TypeError("buf must be Uint8Array");
  }
  const header = decodeHeader(buf, 0);
  let o = header.end;
  const questions = [];
  for (let i = 0; i < header.qdcount; i++) {
    const q = decodeQuestion(buf, o);
    questions.push({ name: q.name, type: q.type, class: q.class });
    o = q.end;
  }
  const answers = [];
  for (let i = 0; i < header.ancount; i++) {
    const rr = decodeRR(buf, o);
    answers.push(stripEnd(rr));
    o = rr.end;
  }
  const authorities = [];
  for (let i = 0; i < header.nscount; i++) {
    const rr = decodeRR(buf, o);
    authorities.push(stripEnd(rr));
    o = rr.end;
  }
  const additionals = [];
  for (let i = 0; i < header.arcount; i++) {
    const rr = decodeRR(buf, o);
    additionals.push(stripEnd(rr));
    o = rr.end;
  }
  return { header, questions, answers, authorities, additionals };
}

/** Strip the parser-only `end` field from a decoded RR before returning it. */
function stripEnd(rr) {
  const { end, ...rest } = rr;
  void end;
  return rest;
}
