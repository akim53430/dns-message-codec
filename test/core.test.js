import { test } from "node:test";
import * as assert from "node:assert/strict";

import {
  Opcode,
  Rcode,
  Type,
  Class,
  encodeMessage,
  decodeMessage,
  encodeName,
  decodeName,
  encodeRR,
  decodeRR,
  encodeHeader,
  decodeHeader,
} from "../src/index.js";

// Helpers -------------------------------------------------------------------

/** Build a name from an array of strings, one per label. */
function n(...labels) {
  return labels.map((s) => new TextEncoder().encode(s));
}

/** Compare two Uint8Arrays for value equality. */
function bytesEqual(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// Header --------------------------------------------------------------------

test("header round-trips with all flags set", () => {
  const h = {
    id: 0x1234,
    qr: true,
    opcode: Opcode.STATUS,
    aa: true,
    tc: true,
    rd: true,
    ra: true,
    rcode: Rcode.REFUSED,
  };
  const arr = [];
  encodeHeader(arr, h);
  const buf = new Uint8Array(arr);
  const got = decodeHeader(buf, 0);
  assert.equal(got.id, 0x1234);
  assert.equal(got.qr, true);
  assert.equal(got.opcode, Opcode.STATUS);
  assert.equal(got.aa, true);
  assert.equal(got.tc, true);
  assert.equal(got.rd, true);
  assert.equal(got.ra, true);
  assert.equal(got.rcode, Rcode.REFUSED);
  assert.equal(got.qdcount, 0);
});

test("header defaults: no flags, zero counts", () => {
  const arr = [];
  encodeHeader(arr, { id: 1 });
  const got = decodeHeader(new Uint8Array(arr), 0);
  assert.equal(got.qr, false);
  assert.equal(got.opcode, 0);
  assert.equal(got.rcode, 0);
  assert.equal(got.qdcount, 0);
});

test("header rejects truncated input", () => {
  assert.throws(() => decodeHeader(new Uint8Array(11), 0), RangeError);
});

// Names ---------------------------------------------------------------------

test("root name encodes as 0x00 and decodes as empty label array", () => {
  const arr = [];
  encodeName(arr, []);
  assert.deepEqual(arr, [0]);
  const { name, end } = decodeName(new Uint8Array(arr), 0);
  assert.equal(name.length, 0);
  assert.equal(end, 1);
});

test("name with labels round-trips", () => {
  const arr = [];
  const name = n("example", "test");
  encodeName(arr, name);
  const { name: got, end } = decodeName(new Uint8Array(arr), 0);
  assert.equal(got.length, 2);
  assert.ok(bytesEqual(got[0], new TextEncoder().encode("example")));
  assert.ok(bytesEqual(got[1], new TextEncoder().encode("test")));
  assert.equal(end, arr.length);
});

test("decodeName follows a compression pointer", () => {
  // Build a buffer with a name at offset 12, then a second name that is a
  // pointer to offset 12.
  const arr = [];
  // padding so the real name sits at 12
  for (let i = 0; i < 12; i++) arr.push(0);
  // name at 12: "foo" "bar" 0
  arr.push(3, 102, 111, 111, 3, 98, 97, 114, 0);
  // name at 21: pointer to 12 = 0xC00C
  arr.push(0xc0, 0x0c);
  const buf = new Uint8Array(arr);
  const { name, end } = decodeName(buf, 21);
  assert.equal(name.length, 2);
  assert.ok(bytesEqual(name[0], new TextEncoder().encode("foo")));
  assert.ok(bytesEqual(name[1], new TextEncoder().encode("bar")));
  assert.equal(end, 23); // pointer consumed exactly 2 bytes at offset 21
});

test("decodeName rejects compression pointer loop", () => {
  // A pointer that points to itself.
  const buf = new Uint8Array([0xc0, 0x00]);
  assert.throws(() => decodeName(buf, 0), /pointer loop/);
});

test("decodeName rejects reserved label length bits", () => {
  // 0x40 has the 0b01 high bits — reserved per RFC 1035 §4.1.4.
  const buf = new Uint8Array([0x40, 0x00]);
  assert.throws(() => decodeName(buf, 0), /reserved/);
});

test("encodeName rejects a label longer than 63 bytes", () => {
  const long = new Uint8Array(64);
  assert.throws(() => encodeName([], [long]), /too long/);
});

test("encodeName rejects an empty label in the middle of a name", () => {
  assert.throws(() => encodeName([], [new Uint8Array(0)]), /empty label/);
});

// Whole message round-trips -------------------------------------------------

test("a minimal query round-trips", () => {
  const msg = {
    header: { id: 0xabcd, opcode: Opcode.QUERY, rd: true },
    questions: [{ name: n("example", "test"), type: Type.A, class: Class.IN }],
    answers: [],
    authorities: [],
    additionals: [],
  };
  const buf = encodeMessage(msg);
  const got = decodeMessage(buf);
  assert.equal(got.header.id, 0xabcd);
  assert.equal(got.header.qr, false);
  assert.equal(got.header.opcode, Opcode.QUERY);
  assert.equal(got.header.rd, true);
  assert.equal(got.header.qdcount, 1);
  assert.equal(got.questions.length, 1);
  assert.equal(got.questions[0].type, Type.A);
  assert.equal(got.questions[0].class, Class.IN);
  assert.equal(got.questions[0].name.length, 2);
});

test("encodeMessage derives counts from section arrays, ignoring header counts", () => {
  const msg = {
    header: { id: 1, qdcount: 9, ancount: 9, nscount: 9, arcount: 9 },
    questions: [{ name: [], type: Type.A, class: Class.IN }],
    answers: [],
    authorities: [],
    additionals: [],
  };
  const buf = encodeMessage(msg);
  const got = decodeMessage(buf);
  assert.equal(got.header.qdcount, 1);
  assert.equal(got.header.ancount, 0);
  assert.equal(got.header.nscount, 0);
  assert.equal(got.header.arcount, 0);
});

test("decodeMessage tolerates trailing bytes", () => {
  const msg = {
    header: { id: 1 },
    questions: [{ name: [], type: Type.A, class: Class.IN }],
    answers: [],
    authorities: [],
    additionals: [],
  };
  const buf = encodeMessage(msg);
  const padded = new Uint8Array(buf.length + 5);
  padded.set(buf, 0);
  const got = decodeMessage(padded);
  assert.equal(got.questions.length, 1);
});

test("decodeMessage throws on truncated question section", () => {
  const msg = {
    header: { id: 1 },
    questions: [{ name: [], type: Type.A, class: Class.IN }],
    answers: [],
    authorities: [],
    additionals: [],
  };
  const buf = encodeMessage(msg).slice(0, 13); // drop one byte of the question
  assert.throws(() => decodeMessage(buf), RangeError);
});

// Known RR types ------------------------------------------------------------

test("A record round-trips", () => {
  const rr = {
    name: n("host", "test"),
    type: Type.A,
    class: Class.IN,
    ttl: 300,
    data: [192, 0, 2, 1],
  };
  const arr = [];
  encodeRR(arr, rr);
  const got = decodeRR(new Uint8Array(arr), 0);
  assert.deepEqual(got.data, [192, 0, 2, 1]);
  assert.equal(got.ttl, 300);
  assert.equal(got.type, Type.A);
});

test("AAAA record round-trips", () => {
  const addr = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
  ];
  const rr = {
    name: [],
    type: Type.AAAA,
    class: Class.IN,
    ttl: 60,
    data: addr,
  };
  const arr = [];
  encodeRR(arr, rr);
  const got = decodeRR(new Uint8Array(arr), 0);
  assert.deepEqual(got.data, addr);
});

test("CNAME record round-trips with a name in RDATA", () => {
  const rr = {
    name: n("alias", "test"),
    type: Type.CNAME,
    class: Class.IN,
    ttl: 100,
    data: n("target", "test"),
  };
  const arr = [];
  encodeRR(arr, rr);
  const got = decodeRR(new Uint8Array(arr), 0);
  assert.equal(got.data.length, 2);
  assert.ok(bytesEqual(got.data[0], new TextEncoder().encode("target")));
});

test("MX record round-trips", () => {
  const rr = {
    name: n("test"),
    type: Type.MX,
    class: Class.IN,
    ttl: 100,
    data: { preference: 10, exchange: n("mail", "test") },
  };
  const arr = [];
  encodeRR(arr, rr);
  const got = decodeRR(new Uint8Array(arr), 0);
  assert.equal(got.data.preference, 10);
  assert.equal(got.data.exchange.length, 2);
});

test("SOA record round-trips", () => {
  const rr = {
    name: n("test"),
    type: Type.SOA,
    class: Class.IN,
    ttl: 100,
    data: {
      mname: n("ns", "test"),
      rname: n("admin", "test"),
      serial: 2024010101,
      refresh: 7200,
      retry: 3600,
      expire: 1209600,
      minimum: 3600,
    },
  };
  const arr = [];
  encodeRR(arr, rr);
  const got = decodeRR(new Uint8Array(arr), 0);
  assert.equal(got.data.serial, 2024010101);
  assert.equal(got.data.refresh, 7200);
  assert.equal(got.data.expire, 1209600);
  assert.equal(got.data.minimum, 3600);
  assert.equal(got.data.mname.length, 2);
});

test("TXT record with multiple character-strings round-trips", () => {
  const rr = {
    name: n("txt", "test"),
    type: Type.TXT,
    class: Class.IN,
    ttl: 100,
    data: [
      new TextEncoder().encode("hello"),
      new TextEncoder().encode("world"),
    ],
  };
  const arr = [];
  encodeRR(arr, rr);
  const got = decodeRR(new Uint8Array(arr), 0);
  assert.equal(got.data.length, 2);
  assert.ok(bytesEqual(got.data[0], new TextEncoder().encode("hello")));
  assert.ok(bytesEqual(got.data[1], new TextEncoder().encode("world")));
});

test("TXT record accepts string character-strings on encode", () => {
  const rr = {
    name: [],
    type: Type.TXT,
    class: Class.IN,
    ttl: 0,
    data: ["ok"],
  };
  const arr = [];
  encodeRR(arr, rr);
  const got = decodeRR(new Uint8Array(arr), 0);
  assert.ok(bytesEqual(got.data[0], new TextEncoder().encode("ok")));
});

test("SRV record round-trips", () => {
  const rr = {
    name: n("_sip._tcp", "test"),
    type: Type.SRV,
    class: Class.IN,
    ttl: 100,
    data: { priority: 1, weight: 2, port: 5060, target: n("sip", "test") },
  };
  const arr = [];
  encodeRR(arr, rr);
  const got = decodeRR(new Uint8Array(arr), 0);
  assert.equal(got.data.priority, 1);
  assert.equal(got.data.weight, 2);
  assert.equal(got.data.port, 5060);
  assert.equal(got.data.target.length, 2);
});

// Unknown RR type -----------------------------------------------------------

test("unknown RR type is carried as raw rdata bytes", () => {
  const raw = new Uint8Array([1, 2, 3, 4, 5]);
  const rr = {
    name: n("x", "test"),
    type: 999, // made-up type, but legal on the wire
    class: Class.IN,
    ttl: 10,
    data: raw,
  };
  const arr = [];
  encodeRR(arr, rr);
  const got = decodeRR(new Uint8Array(arr), 0);
  assert.equal(got.type, 999);
  assert.ok(bytesEqual(got.data, raw));
});

test("encodeRdata rejects unknown type without Uint8Array data", () => {
  assert.throws(
    () => encodeRR([], { name: [], type: 999, class: 1, ttl: 0, data: "no" }),
    TypeError,
  );
});

// EDNS OPT ------------------------------------------------------------------

test("OPT pseudo-RR round-trips in the additional section", () => {
  const msg = {
    header: { id: 1 },
    questions: [{ name: n("example", "test"), type: Type.A, class: Class.IN }],
    answers: [],
    authorities: [],
    additionals: [
      {
        name: [], // OPT root name per RFC 6891
        type: Type.OPT,
        class: 4096, // requestor UDP payload size
        ttl: 0, // extended RCODE 0, version 0, no flags
        data: [{ code: 10, data: new Uint8Array([1, 2, 3]) }],
      },
    ],
  };
  const buf = encodeMessage(msg);
  const got = decodeMessage(buf);
  assert.equal(got.additionals.length, 1);
  const opt = got.additionals[0];
  assert.equal(opt.type, Type.OPT);
  assert.equal(opt.class, 4096);
  assert.equal(opt.data.length, 1);
  assert.equal(opt.data[0].code, 10);
  assert.ok(bytesEqual(opt.data[0].data, new Uint8Array([1, 2, 3])));
});

test("OPT with zero options round-trips", () => {
  const rr = {
    name: [],
    type: Type.OPT,
    class: 1232,
    ttl: 0,
    data: [],
  };
  const arr = [];
  encodeRR(arr, rr);
  const got = decodeRR(new Uint8Array(arr), 0);
  assert.deepEqual(got.data, []);
});

// Compression across message ------------------------------------------------

test("answer name compression pointer into question is followed", () => {
  // Hand-build a message where the answer name is a pointer to the question.
  const arr = [];
  // header
  encodeHeader(arr, { id: 1, qdcount: 1, ancount: 1 });
  // question at offset 12
  const qNameOff = arr.length;
  encodeName(arr, n("example", "test"));
  arr.push(0, 1, 0, 1); // type A, class IN
  // answer: name = pointer to 12
  arr.push(0xc0, 0x0c);
  arr.push(0, 1, 0, 1); // type A, class IN
  arr.push(0, 0, 0, 60); // ttl 60
  arr.push(0, 4); // rdlen 4
  arr.push(10, 0, 0, 1); // rdata
  const buf = new Uint8Array(arr);
  void qNameOff;
  const got = decodeMessage(buf);
  assert.equal(got.answers.length, 1);
  assert.equal(got.answers[0].name.length, 2);
  assert.ok(bytesEqual(got.answers[0].name[0], new TextEncoder().encode("example")));
  assert.deepEqual(got.answers[0].data, [10, 0, 0, 1]);
});

// Truncation guards ---------------------------------------------------------

test("decodeRR throws on truncated RDATA", () => {
  const rr = {
    name: [],
    type: Type.A,
    class: Class.IN,
    ttl: 0,
    data: [1, 2, 3, 4],
  };
  const arr = [];
  encodeRR(arr, rr);
  const buf = new Uint8Array(arr).slice(0, arr.length - 1);
  assert.throws(() => decodeRR(buf, 0), RangeError);
});

test("decodeTXT throws on a truncated character-string", () => {
  // TXT rdlen=1 but the length byte says 5.
  const buf = new Uint8Array([5, 1, 2]);
  // We need to go through decodeRR so rdlen is honored.
  const rr = {
    name: [],
    type: Type.TXT,
    class: 1,
    ttl: 0,
    data: [new TextEncoder().encode("x")],
  };
  const arr = [];
  encodeRR(arr, rr);
  // Rewrite rdlen to 3 and truncate the actual bytes to match.
  const fixed = new Uint8Array(arr);
  // Find rdlen position: name(1) + type(2) + class(2) + ttl(4) = 9, rdlen at 9-10
  fixed[9] = 0; fixed[10] = 3;
  const buf2 = new Uint8Array(13);
  buf2.set(fixed.subarray(0, 11), 0);
  buf2[11] = 5; buf2[12] = 1; // length 5, only 1 byte follows
  assert.throws(() => decodeRR(buf2, 0), RangeError);
});
