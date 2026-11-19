// check-contrast.mjs — the standalone app's text must be readable.
//
// This exists because it already failed once: --ink-faint was #8d82a8 on the
// panel, which is 4.91:1. That passes WCAG AA for normal text, and it was still
// too dim to read at 11px, which is what most of this UI is made of. So the bar
// The bar was 7:1 for a while. That turned out to be its own failure: with a
// background plate behind translucent panels, 7:1 admits no surface lighter
// than #322a52, and the result was repeatedly reported as too dark to use. A
// rule that forces an unusable UI is not protecting anyone.
//
// So the floor is 5.5:1 — comfortably above the 4.5:1 WCAG AA requirement for
// body text, and short of the 7:1 AAA bar that was costing all the light. The
// original failure it guarded against (11px text at 4.91:1) is separately
// covered by the 11px font-size floor below.
//
// Colours are read from app.css rather than duplicated, so editing the palette
// is what this checks.
//
//   node scripts/check-contrast.mjs

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const rendererDir = join(here, '..', 'src', 'app', 'renderer');
const css = readFileSync(join(rendererDir, 'app.css'), 'utf8');

function vars(source) {
  const out = {};
  for (const [, name, value] of source.matchAll(/--([\w-]+):\s*(#[0-9a-fA-F]{3,8})\s*;/g)) {
    out[name] = value;
  }
  return out;
}

function toRgb(hex) {
  const h = hex.replace('#', '');
  const full = h.length === 3 ? [...h].map((c) => c + c).join('') : h;
  return [0, 2, 4].map((i) => parseInt(full.slice(i, i + 2), 16));
}

function luminance(hex) {
  const [r, g, b] = toRgb(hex).map((v) => {
    const c = v / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function ratio(fg, bg) {
  const a = luminance(fg);
  const b = luminance(bg);
  const [hi, lo] = a > b ? [a, b] : [b, a];
  return (hi + 0.05) / (lo + 0.05);
}

const v = vars(css);
const required = ['bg', 'panel', 'ink', 'ink-dim', 'ink-faint', 'accent', 'steel', 'purple', 'danger', 'warn'];
const missing = required.filter((k) => !v[k]);
if (missing.length) {
  console.error(`FAIL: app.css is missing ${missing.join(', ')}`);
  process.exit(1);
}

// Text colours are used on both the page background and inside panels; the
// panel is the lighter of the two, so it is the harder case.
const SURFACES = [
  ['page', v.bg],
  ['panel', v.panel],
];

const TEXT = [
  ['ink', v.ink, 5.5],
  ['ink-dim', v['ink-dim'], 5.5],
  ['ink-faint', v['ink-faint'], 5.5],
  ['accent', v.accent, 5.5],
  ['steel', v.steel, 5.5],
  ['purple', v.purple, 5.5],
  ['danger', v.danger, 4.5],
  ['warn', v.warn, 4.5],
];

let failed = 0;
for (const [surfaceName, surface] of SURFACES) {
  const parts = [];
  for (const [name, colour, min] of TEXT) {
    const r = ratio(colour, surface);
    parts.push(`${name} ${r.toFixed(2)}:1 (need ${min})`);
    if (r < min) failed++;
  }
  console.log(`${surfaceName.padEnd(6)} ${parts.join('    ')}`);
}

// The case a token-on-token check cannot see.
//
// Panels are translucent over a background plate, so the real background under
// body text is the PANEL COMPOSITED OVER THE ARTWORK -- and the worst case is
// the artwork's brightest pixel, which in assets/bg.webp is pure white. A
// panel at 0.90 still lets 10% of that through, which lifts the surface and
// costs contrast. Checking only against the flat panel colour would pass a
// palette that is unreadable exactly where the picture is brightest.
// The artwork is checked at BOTH extremes, because which one is the worst case
// depends on which way the palette runs. Light ink on a dark panel loses
// contrast where the picture is brightest; dark ink on a light panel loses it
// where the picture is DARKEST, since a dark pixel bleeding through drags the
// surface down toward the ink. This file previously checked #ffffff only, which
// was correct for the dark palette it was written for and became the wrong
// extreme the moment the palette was inverted -- i.e. it would have passed the
// exact failure it exists to catch. Checking both is direction-agnostic.
const ARTWORK_EXTREMES = [
  ['brightest', '#ffffff'],
  ['darkest', '#000000'],
];
const SCRIM_UNDER_PANEL = 0.4;
const panelAlpha = Number(/--panel-alpha:\s*([\d.]+)/.exec(css)?.[1] ?? 1);

// The .panel rule has to state its alpha as a LITERAL percentage. It was
// written as calc(var(--panel-alpha) * 100%) inside color-mix(), which does not
// resolve -- the whole declaration was dropped, panels rendered transparent,
// and the artwork showed straight through what should have been a solid
// surface. It looked like the palette had not been applied at all. So the
// literal is checked against the token rather than trusted to match.
// The .panel rule states its colour as a LITERAL rgba(), checked against the
// tokens here. Two earlier forms both computed correctly and PAINTED NOTHING:
// calc() inside color-mix() was dropped outright, and backdrop-filter renders
// as nothing under software compositing. Both left panels fully transparent
// with the artwork showing through, which reads as 'the palette never applied'
// -- and getComputedStyle reports the intended value in both cases, so only a
// pixel or this check catches it.
const declaredRgba = /\.panel\s*{[^}]*background:\s*rgba\((\d+),\s*(\d+),\s*(\d+),\s*([\d.]+)\)/.exec(css);
if (!declaredRgba) {
  console.log(`
FAIL: .panel must set background as a literal rgba(...)`);
  failed++;
} else {
  const [, r, g, b, a] = declaredRgba;
  const want = toRgb(v.panel);
  if (Number(r) !== want[0] || Number(g) !== want[1] || Number(b) !== want[2]) {
    console.log(`
FAIL: .panel rgba(${r}, ${g}, ${b}) does not match --panel ${v.panel}`);
    failed++;
  }
  if (Number(a) !== panelAlpha) {
    console.log(`
FAIL: .panel alpha ${a} does not match --panel-alpha ${panelAlpha}`);
    failed++;
  }
}

const composite = (fg, alpha, bg) => {
  const [a, b] = [toRgb(fg), toRgb(bg)];
  return `#${a.map((x, i) => Math.round(alpha * x + (1 - alpha) * b[i]).toString(16).padStart(2, '0')).join('')}`;
};


for (const [extremeName, extreme] of ARTWORK_EXTREMES) {
  const artUnderScrim = composite(extreme, 1 - SCRIM_UNDER_PANEL, v.bg);
  const panelWorst = composite(v.panel, panelAlpha, artUnderScrim);

  const worstParts = [];
  for (const [name, colour, min] of TEXT) {
    const r = ratio(colour, panelWorst);
    worstParts.push(`${name} ${r.toFixed(2)}:1 (need ${min})`);
    if (r < min) failed++;
  }
  console.log(`
panel over the ${extremeName} artwork pixel = ${panelWorst} (alpha ${panelAlpha})`);
  console.log(`worst  ${worstParts.join('    ')}`);
}

// The one inverted case: an active chip is dark text on the accent fill.
const onAccent = /button\.on\s*{[^}]*color:\s*(#[0-9a-fA-F]{3,8})/.exec(css)?.[1];
if (onAccent) {
  const r = ratio(onAccent, v.accent);
  console.log(`\nactive chip: ${onAccent} on accent ${r.toFixed(2)}:1 (need 4.5)`);
  if (r < 4.5) failed++;
}

// Small text is where a marginal ratio actually bites, so the floor is checked
// too -- raising contrast does not help if the type is 9px.
const tooSmall = [...css.matchAll(/font-size:\s*(\d+)px/g)]
  .map((m) => Number(m[1]))
  .filter((px) => px < 11);
if (tooSmall.length) {
  console.log(`\nFAIL: ${tooSmall.length} rule(s) below 11px: ${tooSmall.join(', ')}`);
  failed++;
}

// preview.html carries its own copy of the palette, because it has to render
// standalone. A copy that silently falls behind is worse than no preview at
// all: it is looked at to decide whether the colours are readable, so showing
// the previous palette would answer that question about the wrong UI.
const preview = readFileSync(join(rendererDir, 'preview.html'), 'utf8');
const palette = (source) =>
  [...source.matchAll(/--((?:bg|panel|line|ink|ink-dim|ink-faint|accent|danger|warn)):\s*([^;]+);/g)]
    .map(([, name, value]) => `${name}: ${value.trim()}`);

const inApp = palette(css);
const inPreview = palette(preview);
const drifted = inApp.filter((line) => !inPreview.includes(line));
if (drifted.length) {
  console.log(`\nFAIL: preview.html's palette is behind app.css: ${drifted.join(', ')}`);
  failed++;
}

if (failed) {
  console.error(`\ncontrast FAILED (${failed})`);
  process.exit(1);
}
console.log('\ncontrast OK');
