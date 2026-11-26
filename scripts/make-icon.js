'use strict';
// Generates icon.png (128x128) and images/screenshot.png (1400x900) for Pulumi Stack & Policy Viewer.
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const crcT = new Int32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c;
});
const crc = (b) => { let c = -1; for (const v of b) c = crcT[(c ^ v) & 255] ^ (c >>> 8); return (c ^ -1) >>> 0; };
const chunk = (t, d) => {
  const l = Buffer.alloc(4); l.writeUInt32BE(d.length);
  const td = Buffer.concat([Buffer.from(t), d]);
  const c = Buffer.alloc(4); c.writeUInt32BE(crc(td));
  return Buffer.concat([l, td, c]);
};
const hex = (h) => [parseInt(h.slice(1, 3), 16), parseInt(h.slice(3, 5), 16), parseInt(h.slice(5, 7), 16)];
const mix = (a, b, t) => a.map((v, i) => Math.round(v + (b[i] - v) * t));

function writePng(filePath, W, H, px) {
  const raw = Buffer.alloc((W * 4 + 1) * H);
  for (let y = 0; y < H; y += 1) {
    raw[y * (W * 4 + 1)] = 0;
    px.copy(raw, y * (W * 4 + 1) + 1, y * W * 4, (y + 1) * W * 4);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(W, 0); ihdr.writeUInt32BE(H, 4); ihdr[8] = 8; ihdr[9] = 6;
  fs.writeFileSync(filePath, Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw)),
    chunk('IEND', Buffer.alloc(0)),
  ]));
}

function makeCanvas(W, H) {
  const px = Buffer.alloc(W * H * 4);
  const set = (x, y, [r, g, b], a = 255) => {
    x = Math.round(x); y = Math.round(y);
    if (x < 0 || y < 0 || x >= W || y >= H) return;
    const i = (y * W + x) * 4;
    const k = a / 255;
    px[i] = Math.round(px[i] * (1 - k) + r * k);
    px[i + 1] = Math.round(px[i + 1] * (1 - k) + g * k);
    px[i + 2] = Math.round(px[i + 2] * (1 - k) + b * k);
    px[i + 3] = Math.max(px[i + 3], a);
  };
  const rect = (x0, y0, w, h, col, r = 3, a = 255) => {
    for (let y = y0; y < y0 + h; y += 1) for (let x = x0; x < x0 + w; x += 1) {
      const dx = Math.max(x0 + r - x, 0, x - (x0 + w - 1 - r));
      const dy = Math.max(y0 + r - y, 0, y - (y0 + h - 1 - r));
      const d = Math.sqrt(dx * dx + dy * dy);
      if (d <= r) set(x, y, col, d > r - 1 ? Math.round(a * (r - d)) : a);
    }
  };
  return { px, set, rect };
}

// 1. Icon (128x128): Violet/Indigo stack layers & secret shield card
{
  const W = 128, H = 128, R = 22;
  const { px, set, rect } = makeCanvas(W, H);
  for (let y = 0; y < H; y += 1) for (let x = 0; x < W; x += 1) {
    const dx = Math.max(R - x, 0, x - (W - 1 - R)), dy = Math.max(R - y, 0, y - (H - 1 - R));
    const d = Math.sqrt(dx * dx + dy * dy);
    if (d <= R) set(x, y, mix(hex('#6D28D9'), hex('#312E81'), y / H), d > R - 1 ? Math.round(255 * (R - d)) : 255);
  }
  rect(14, 15, 100, 16, hex('#8B5CF6'), 4);
  rect(20, 20, 48, 6, hex('#F5F3FF'), 2);
  rect(80, 20, 28, 6, hex('#DDD6FE'), 2);

  rect(18, 40, 92, 64, hex('#0F172A'), 5);
  rect(26, 48, 76, 12, hex('#A78BFA'), 3);
  rect(26, 66, 52, 12, hex('#34D399'), 3);
  rect(84, 66, 18, 12, hex('#10B981'), 3);
  rect(26, 84, 52, 12, hex('#F87171'), 3);
  rect(84, 84, 18, 12, hex('#FBBF24'), 3);

  rect(14, 110, 100, 8, hex('#4C1D95'), 3);
  rect(22, 112, 52, 4, hex('#EDE9FE'), 2);
  rect(84, 112, 24, 4, hex('#A78BFA'), 2);
  writePng(path.join(__dirname, '..', 'icon.png'), W, H, px);
}

// 2. Screenshot preview (1400x900)
{
  const W = 1400, H = 900;
  const { px, rect } = makeCanvas(W, H);
  rect(0, 0, W, H, hex('#1E1E1E'), 0);
  rect(0, 0, W, 44, hex('#252526'), 0);
  rect(16, 12, 340, 20, hex('#6D28D9'), 4);
  rect(370, 14, 340, 16, hex('#475569'), 3);
  for (let i = 0; i < 6; i += 1) {
    const col = i === 4 ? hex('#991B1B') : (i === 5 ? hex('#B45309') : (i === 1 ? hex('#065F46') : hex('#334155')));
    rect(16 + i * 155, 58, 142, 24, col, 10);
  }
  rect(16, 94, 300, 28, hex('#2D2D30'), 3);
  rect(328, 94, 150, 28, hex('#2D2D30'), 3);
  rect(490, 94, 90, 28, hex('#7C3AED'), 3);
  rect(600, 94, 175, 28, hex('#4C1D95'), 3);
  rect(788, 94, 175, 28, hex('#4C1D95'), 3);
  rect(976, 94, 175, 28, hex('#4C1D95'), 3);

  rect(16, 140, 840, 720, hex('#0F172A'), 4);
  rect(16, 140, 840, 34, hex('#1E293B'), 2);
  for (let r = 0; r < 10; r += 1) {
    const y = 184 + r * 58;
    const isErr = r === 3 || r === 6;
    const isSec = r === 1 || r === 4 || r === 7;
    rect(24, y, 824, 48, r === 3 ? hex('#3B0764') : (r % 2 === 0 ? hex('#1E293B') : hex('#0F172A')), 2);
    rect(34, y + 18, 28, 12, hex('#94A3B8'), 2);
    rect(74, y + 18, 110, 12, hex('#A78BFA'), 2);
    rect(200, y + 18, 220, 12, hex('#F8FAFC'), 2);
    rect(440, y + 18, 240, 12, hex('#CBD5E1'), 2);
    rect(700, y + 18, 120, 12, isErr ? hex('#F87171') : (isSec ? hex('#34D399') : hex('#94A3B8')), 2);
  }

  rect(872, 140, 512, 720, hex('#0F172A'), 4);
  rect(872, 140, 512, 34, hex('#1E293B'), 2);
  for (let r = 0; r < 6; r += 1) {
    const y = 188 + r * 36;
    rect(888, y, 130, 14, hex('#A78BFA'), 2);
    rect(1032, y, 330, 14, r === 2 ? hex('#F87171') : hex('#F8FAFC'), 2);
  }
  rect(888, 430, 480, 405, hex('#020617'), 4);
  for (let r = 0; r < 8; r += 1) {
    const y = 452 + r * 34;
    rect(904, y, 420 - (r % 3) * 40, 12, r === 0 ? hex('#A78BFA') : hex('#94A3B8'), 2);
  }
  fs.mkdirSync(path.join(__dirname, '..', 'images'), { recursive: true });
  writePng(path.join(__dirname, '..', 'images', 'screenshot.png'), W, H, px);
}
console.log('Generated icon.png and images/screenshot.png');
