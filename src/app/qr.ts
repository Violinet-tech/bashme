// qr.ts — a QR encoder, because pairing by typing is the part that fails.
//
// Enrolment needs the phone to reach https://<ip>:<port>/?code=NNNNNN. Typing
// that is four chances to get it wrong -- the address, the port, the code, and
// accepting the certificate warning at the end of it. A camera does all four in
// one motion, and the code is short-lived and one-use, so putting it in a QR on
// screen gives away nothing that the screen was not already showing.
//
// It is written here rather than installed because this package has no runtime
// dependencies and that is deliberate (see package.json): bashme is the thing
// that approves what other software does, so its own supply chain is the one
// place a dependency is least welcome. A QR encoder is a few hundred lines of
// finite-field arithmetic that never changes; that is a better trade than a
// transitive tree.
//
// Byte mode, error correction level M (~15% recovery), versions 1-10. Ten is
// 213 bytes, several times the longest pairing URL, and stopping there keeps
// the capacity tables short enough to check by eye.

// The non-null assertions throughout are on array reads whose index is bounded
// by the loop that produced it -- tsconfig has noUncheckedIndexedAccess, which
// is right for data that came from outside and noise for finite-field tables
// walked by their own length. The bounds are the algorithm, not an assumption.

/** [ec codewords per block, group 1 blocks, group 1 data cw, group 2 blocks, group 2 data cw] */
const SPEC_M: ReadonlyArray<readonly [number, number, number, number, number]> = [
  [10, 1, 16, 0, 0], // 1
  [16, 1, 28, 0, 0], // 2
  [26, 1, 44, 0, 0], // 3
  [18, 2, 32, 0, 0], // 4
  [24, 2, 43, 0, 0], // 5
  [16, 4, 27, 0, 0], // 6
  [18, 4, 31, 0, 0], // 7
  [22, 2, 38, 2, 39], // 8
  [22, 3, 36, 2, 37], // 9
  [26, 4, 43, 1, 44], // 10
];

const ALIGNMENT: ReadonlyArray<readonly number[]> = [
  [],
  [],
  [6, 18],
  [6, 22],
  [6, 26],
  [6, 30],
  [6, 34],
  [6, 22, 38],
  [6, 24, 42],
  [6, 26, 46],
  [6, 28, 50],
];

// Bits left over after the codewords, which are placed as zeros.
const REMAINDER = [0, 0, 7, 7, 7, 7, 7, 0, 0, 0, 0];

// --- GF(256), the field QR's Reed-Solomon runs in ---------------------------

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d; // the QR primitive polynomial
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255]!;
}

const mul = (a: number, b: number): number => (a === 0 || b === 0 ? 0 : EXP[LOG[a]! + LOG[b]!]!);

/** The generator polynomial for `degree` error-correction codewords. */
function generator(degree: number): Uint8Array {
  let poly = Uint8Array.from([1]);
  for (let i = 0; i < degree; i++) {
    const next = new Uint8Array(poly.length + 1);
    for (let j = 0; j < poly.length; j++) {
      next[j]! ^= poly[j]!;
      next[j + 1]! ^= mul(poly[j]!, EXP[i]!);
    }
    poly = next;
  }
  return poly;
}

function ecCodewords(data: Uint8Array, count: number): Uint8Array {
  const gen = generator(count);
  const rem = new Uint8Array(count);
  for (const byte of data) {
    const factor = byte ^ rem[0]!;
    rem.copyWithin(0, 1);
    rem[count - 1] = 0;
    for (let i = 0; i < count; i++) rem[i]! ^= mul(gen[i + 1]!, factor);
  }
  return rem;
}

// --- BCH, for the format and version strips ---------------------------------

function bch(value: number, generatorPoly: number, bits: number): number {
  let rem = value << bits;
  const genBits = 32 - Math.clz32(generatorPoly);
  for (let i = 32 - Math.clz32(rem); i >= genBits; i--) {
    if (rem & (1 << (i - 1))) rem ^= generatorPoly << (i - genBits);
  }
  return rem;
}

/** 15 bits: level M (0b00) and the mask, BCH-protected and masked with 0x5412. */
const formatBits = (mask: number): number => {
  const value = (0b00 << 3) | mask;
  return ((value << 10) | bch(value, 0x537, 10)) ^ 0x5412;
};

/** 18 bits, versions 7 and up only. */
const versionBits = (version: number): number => (version << 12) | bch(version, 0x1f25, 12);

// --- bit stream -------------------------------------------------------------

class Bits {
  readonly bytes: number[] = [];
  #length = 0;

  get length(): number {
    return this.#length;
  }

  push(value: number, width: number): void {
    for (let i = width - 1; i >= 0; i--) {
      const bit = (value >> i) & 1;
      if (this.#length % 8 === 0) this.bytes.push(0);
      this.bytes[this.bytes.length - 1]! |= bit << (7 - (this.#length % 8));
      this.#length++;
    }
  }
}

// --- the matrix -------------------------------------------------------------

interface Grid {
  size: number;
  modules: Uint8Array;
  reserved: Uint8Array;
}

const at = (g: Grid, x: number, y: number): number => g.modules[y * g.size + x]!;

const set = (g: Grid, x: number, y: number, dark: boolean, reserve = true): void => {
  g.modules[y * g.size + x] = dark ? 1 : 0;
  if (reserve) g.reserved[y * g.size + x] = 1;
};

function placeFunctionPatterns(g: Grid, version: number): void {
  const n = g.size;

  const finder = (ox: number, oy: number): void => {
    // The separator ring is included by walking one module outside the 7x7.
    for (let dy = -1; dy <= 7; dy++) {
      for (let dx = -1; dx <= 7; dx++) {
        const x = ox + dx;
        const y = oy + dy;
        if (x < 0 || y < 0 || x >= n || y >= n) continue;
        const inside = dx >= 0 && dx <= 6 && dy >= 0 && dy <= 6;
        const outer = dx === 0 || dx === 6 || dy === 0 || dy === 6;
        const core = dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4;
        set(g, x, y, inside && (outer || core));
      }
    }
  };
  finder(0, 0);
  finder(n - 7, 0);
  finder(0, n - 7);

  for (let i = 8; i < n - 8; i++) {
    set(g, i, 6, i % 2 === 0);
    set(g, 6, i, i % 2 === 0);
  }

  const centres = ALIGNMENT[version] ?? [];
  for (const cy of centres) {
    for (const cx of centres) {
      // Alignment patterns are omitted where a finder already sits.
      if ((cx <= 8 && cy <= 8) || (cx <= 8 && cy >= n - 9) || (cx >= n - 9 && cy <= 8)) continue;
      for (let dy = -2; dy <= 2; dy++) {
        for (let dx = -2; dx <= 2; dx++) {
          const edge = Math.max(Math.abs(dx), Math.abs(dy));
          set(g, cx + dx, cy + dy, edge !== 1);
        }
      }
    }
  }

  // The dark module. Fixed position, always dark, part of no pattern.
  set(g, 8, n - 8, true);

  // Format areas are reserved now and written after masking.
  for (let i = 0; i < 9; i++) {
    if (i !== 6) {
      set(g, i, 8, false);
      set(g, 8, i, false);
    }
  }
  for (let i = 0; i < 8; i++) {
    set(g, n - 1 - i, 8, false);
    if (n - 1 - i !== n - 8) set(g, 8, n - 1 - i, false);
  }

  if (version >= 7) {
    const value = versionBits(version);
    for (let i = 0; i < 18; i++) {
      const dark = ((value >> i) & 1) === 1;
      const a = Math.floor(i / 3);
      const b = (i % 3) + n - 11;
      set(g, a, b, dark);
      set(g, b, a, dark);
    }
  }
}

function placeData(g: Grid, codewords: Uint8Array, remainder: number): void {
  const n = g.size;
  const total = codewords.length * 8 + remainder;
  let bit = 0;
  let upward = true;

  for (let right = n - 1; right >= 1; right -= 2) {
    // Column 6 is the vertical timing pattern; the zigzag steps over it.
    if (right === 6) right = 5;
    for (let step = 0; step < n; step++) {
      const y = upward ? n - 1 - step : step;
      for (const x of [right, right - 1]) {
        if (g.reserved[y * n + x]) continue;
        if (bit >= total) continue;
        const dark = bit < codewords.length * 8 && ((codewords[bit >> 3]! >> (7 - (bit & 7))) & 1) === 1;
        set(g, x, y, dark, false);
        bit++;
      }
    }
    upward = !upward;
  }
}

const maskAt = (mask: number, x: number, y: number): boolean => {
  switch (mask) {
    case 0:
      return (x + y) % 2 === 0;
    case 1:
      return y % 2 === 0;
    case 2:
      return x % 3 === 0;
    case 3:
      return (x + y) % 3 === 0;
    case 4:
      return (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0;
    case 5:
      return ((x * y) % 2) + ((x * y) % 3) === 0;
    case 6:
      return (((x * y) % 2) + ((x * y) % 3)) % 2 === 0;
    default:
      return (((x + y) % 2) + ((x * y) % 3)) % 2 === 0;
  }
};

/**
 * The four standard penalties. These pick the mask, and their only job is to
 * avoid patterns a scanner would misread -- long runs, solid blocks, and
 * anything that resembles a finder.
 */
function penalty(g: Grid): number {
  const n = g.size;
  let score = 0;

  for (let a = 0; a < n; a++) {
    for (const horizontal of [true, false]) {
      let run = 1;
      for (let b = 1; b < n; b++) {
        const prev = horizontal ? at(g, b - 1, a) : at(g, a, b - 1);
        const cur = horizontal ? at(g, b, a) : at(g, a, b);
        if (cur === prev) {
          run++;
        } else {
          if (run >= 5) score += 3 + (run - 5);
          run = 1;
        }
      }
      if (run >= 5) score += 3 + (run - 5);
    }
  }

  for (let y = 0; y < n - 1; y++) {
    for (let x = 0; x < n - 1; x++) {
      const v = at(g, x, y);
      if (v === at(g, x + 1, y) && v === at(g, x, y + 1) && v === at(g, x + 1, y + 1)) score += 3;
    }
  }

  const finderLike = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0];
  const reversed = [...finderLike].reverse();
  for (let a = 0; a < n; a++) {
    for (let b = 0; b + 11 <= n; b++) {
      for (const horizontal of [true, false]) {
        const window = Array.from({ length: 11 }, (_, i) => (horizontal ? at(g, b + i, a) : at(g, a, b + i)));
        if (window.every((v, i) => v === finderLike[i]) || window.every((v, i) => v === reversed[i])) {
          score += 40;
        }
      }
    }
  }

  const dark = g.modules.reduce<number>((sum, v) => sum + v, 0);
  const percent = (dark * 100) / (n * n);
  score += Math.floor(Math.abs(percent - 50) / 5) * 10;

  return score;
}

function writeFormat(g: Grid, mask: number): void {
  const n = g.size;
  const value = formatBits(mask);
  for (let i = 0; i < 15; i++) {
    const dark = ((value >> i) & 1) === 1;
    // Copy one: up the left column and along the top row, stepping over timing.
    if (i < 6) set(g, 8, i, dark);
    else if (i < 8) set(g, 8, i + 1, dark);
    else if (i === 8) set(g, 7, 8, dark);
    else set(g, 14 - i, 8, dark);
    // Copy two: along the top-right and down the bottom-left.
    if (i < 8) set(g, n - 1 - i, 8, dark);
    else set(g, 8, n - 15 + i, dark);
  }
}

export interface QrMatrix {
  version: number;
  size: number;
  /** One string per row, '1' dark and '0' light. Cheap to send over IPC. */
  rows: string[];
}

/**
 * Encode `text` as a QR matrix.
 *
 * Throws rather than truncating if the text will not fit in version 10 --
 * silently dropping the tail of a pairing URL would produce a code that scans
 * cleanly and goes somewhere wrong, which is worse than an error.
 */
export function encodeQr(text: string, forceMask?: number): QrMatrix {
  const data = new TextEncoder().encode(text);

  let version = 0;
  for (let v = 1; v <= 10; v++) {
    const [, g1, d1, g2, d2] = SPEC_M[v - 1]!;
    const dataCw = g1 * d1 + g2 * d2;
    const countBits = v < 10 ? 8 : 16;
    if (data.length * 8 + 4 + countBits <= dataCw * 8) {
      version = v;
      break;
    }
  }
  if (!version) throw new Error(`${data.length} bytes is too long for a version 10 QR code`);

  const [ecPerBlock, g1Blocks, g1Data, g2Blocks, g2Data] = SPEC_M[version - 1]!;
  const dataCw = g1Blocks * g1Data + g2Blocks * g2Data;

  const bits = new Bits();
  bits.push(0b0100, 4); // byte mode
  bits.push(data.length, version < 10 ? 8 : 16);
  for (const byte of data) bits.push(byte, 8);
  // Terminator, then to a byte boundary, then the standard alternating pad.
  bits.push(0, Math.min(4, dataCw * 8 - bits.length));
  if (bits.length % 8) bits.push(0, 8 - (bits.length % 8));
  const payload = Uint8Array.from(bits.bytes);
  const full = new Uint8Array(dataCw);
  full.set(payload);
  for (let i = payload.length; i < dataCw; i++) {
    full[i] = (i - payload.length) % 2 === 0 ? 0xec : 0x11;
  }

  const blocks: Uint8Array[] = [];
  const ecBlocks: Uint8Array[] = [];
  let offset = 0;
  for (const [count, size] of [
    [g1Blocks, g1Data],
    [g2Blocks, g2Data],
  ] as const) {
    for (let i = 0; i < count; i++) {
      const block = full.subarray(offset, offset + size);
      offset += size;
      blocks.push(block);
      ecBlocks.push(ecCodewords(block, ecPerBlock));
    }
  }

  // Interleaved: column-wise across the blocks, data first then correction.
  const interleaved: number[] = [];
  const widest = Math.max(...blocks.map((b) => b.length));
  for (let i = 0; i < widest; i++) {
    for (const block of blocks) if (i < block.length) interleaved.push(block[i]!);
  }
  for (let i = 0; i < ecPerBlock; i++) {
    for (const block of ecBlocks) interleaved.push(block[i]!);
  }

  const size = version * 4 + 17;
  const base: Grid = {
    size,
    modules: new Uint8Array(size * size),
    reserved: new Uint8Array(size * size),
  };
  placeFunctionPatterns(base, version);
  placeData(base, Uint8Array.from(interleaved), REMAINDER[version]!);

  // `forceMask` exists so the encoder can be compared module-for-module
  // against a reference implementation one mask at a time; production always
  // lets the penalty scores choose.
  let best: Grid | null = null;
  let bestScore = Infinity;
  for (let mask = forceMask ?? 0; mask < (forceMask !== undefined ? forceMask + 1 : 8); mask++) {
    const g: Grid = { size, modules: Uint8Array.from(base.modules), reserved: base.reserved };
    for (let y = 0; y < size; y++) {
      for (let x = 0; x < size; x++) {
        if (!g.reserved[y * size + x] && maskAt(mask, x, y)) g.modules[y * size + x]! ^= 1;
      }
    }
    writeFormat(g, mask);
    const score = penalty(g);
    if (score < bestScore) {
      bestScore = score;
      best = g;
    }
  }

  const grid = best as Grid;
  const rows: string[] = [];
  for (let y = 0; y < size; y++) {
    let row = '';
    for (let x = 0; x < size; x++) row += grid.modules[y * size + x] ? '1' : '0';
    rows.push(row);
  }
  return { version, size, rows };
}
