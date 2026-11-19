// qr.test.ts — the encoder is hand-written, so it is checked against fixed
// output rather than against itself.
//
// The two matrices below were verified by decoding them with zxing-cpp, an
// independent reader, which returned the original strings. That matters more
// than matching some other encoder module-for-module: two encoders can differ
// legitimately (segno pads with an extra zero codeword before the EC/11 run,
// which is spec-legal slack) and both still scan. What must never change
// silently is whether a phone camera can read these.

import test from 'node:test';
import assert from 'node:assert/strict';
import { encodeQr } from './qr.ts';

const A_V1 = [
  '111111101001001111111',
  '100000101111101000001',
  '101110100010101011101',
  '101110101101101011101',
  '101110100111001011101',
  '100000100101101000001',
  '111111101010101111111',
  '000000001101100000000',
  '101101110011101001011',
  '010110010101111001000',
  '110011101101000001101',
  '101101000001001111100',
  '100111100100100100100',
  '000000001011001001001',
  '111111101001100101000',
  '100000101100000110110',
  '101110100110111110001',
  '101110101111001111110',
  '101110101010101100000',
  '100000100010010100101',
  '111111101000010010000',
];

const PAIRING_V3 = [
  '11111110001010100001001111111',
  '10000010001100110100001000001',
  '10111010100000111000001011101',
  '10111010111101011111101011101',
  '10111010101010100101001011101',
  '10000010110001111010001000001',
  '11111110101010101010101111111',
  '00000000111000000011000000000',
  '10111110010000011111101111100',
  '10100100000011000001001010001',
  '00000011111111110100010000000',
  '00101000000111000000000101010',
  '10001110100000111110110001100',
  '01010001111100000111001010001',
  '00000010010000011100100001100',
  '10100001100100110000111010010',
  '01111110110000011110110101100',
  '10101101110101100101001010101',
  '10001010101011111100011110100',
  '10101001001011011001110000010',
  '10111110011010101101111110111',
  '00000000101000000010100011111',
  '11111110001010011111101011100',
  '10000010101000111000100010011',
  '10111010111000010100111110100',
  '10111010111111101111010101111',
  '10111010111001010100011011110',
  '10000010011001011001101110010',
  '11111110100000110100011011100',
];

test('a one-byte payload encodes to the known version 1 matrix', () => {
  const m = encodeQr('A');
  assert.equal(m.version, 1);
  assert.equal(m.size, 21);
  assert.deepEqual(m.rows, A_V1);
});

test('a pairing URL encodes to the known version 3 matrix', () => {
  const m = encodeQr('https://192.168.1.50:8787/?code=123456');
  assert.equal(m.version, 3);
  assert.equal(m.size, 29);
  assert.deepEqual(m.rows, PAIRING_V3);
});

test('the version grows with the payload, and each size is square', () => {
  // Byte-mode capacities at level M. A version that silently came out too
  // small would mean a truncated URL, so the boundaries are pinned.
  for (const [length, version] of [
    [14, 1],
    [15, 2],
    [26, 2],
    [27, 3],
    [42, 3],
    [43, 4],
    [213, 10],
  ] as const) {
    const m = encodeQr('x'.repeat(length));
    assert.equal(m.version, version, `${length} bytes should be version ${version}`);
    assert.equal(m.size, version * 4 + 17);
    assert.equal(m.rows.length, m.size);
    for (const row of m.rows) assert.equal(row.length, m.size);
  }
});

test('too long is an error, not a truncation', () => {
  // A truncated pairing URL would scan cleanly and go somewhere else.
  assert.throws(() => encodeQr('x'.repeat(214)), /too long/);
});

test('the finder patterns and timing rows are where a scanner looks for them', () => {
  const m = encodeQr('https://192.168.1.50:8787/?code=123456');
  const dark = (x: number, y: number) => m.rows[y]![x] === '1';

  for (const [ox, oy] of [
    [0, 0],
    [m.size - 7, 0],
    [0, m.size - 7],
  ] as const) {
    for (let dy = 0; dy < 7; dy++) {
      for (let dx = 0; dx < 7; dx++) {
        const outer = dx === 0 || dx === 6 || dy === 0 || dy === 6;
        const core = dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4;
        assert.equal(dark(ox + dx, oy + dy), outer || core, `finder at ${ox},${oy} module ${dx},${dy}`);
      }
    }
  }

  for (let i = 8; i < m.size - 8; i++) {
    assert.equal(dark(i, 6), i % 2 === 0, `horizontal timing at ${i}`);
    assert.equal(dark(6, i), i % 2 === 0, `vertical timing at ${i}`);
  }

  // The dark module is fixed and always set.
  assert.equal(dark(8, m.size - 8), true);
});
