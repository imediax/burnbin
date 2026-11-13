/**
 * Self-contained zero-dependency QR Code generator (ISO/IEC 18004, Byte mode, EC Level L, Versions 1-14).
 * Compatible with strict CSP (no external scripts, no inline styles required for SVG rendering).
 */
(function (root) {
  "use strict";

  // [ecPerBlock, g1Blocks, g1DataCw, g2Blocks, g2DataCw] for EC Level L (Versions 1..14)
  const EC_L_TABLE = [
    null,
    [7, 1, 19, 0, 0],
    [10, 1, 34, 0, 0],
    [15, 1, 55, 0, 0],
    [20, 1, 80, 0, 0],
    [26, 1, 108, 0, 0],
    [18, 2, 68, 0, 0],
    [20, 2, 78, 0, 0],
    [24, 2, 97, 0, 0],
    [30, 2, 116, 0, 0],
    [18, 2, 68, 2, 69],
    [20, 4, 81, 0, 0],
    [24, 2, 92, 2, 93],
    [26, 4, 107, 0, 0],
    [30, 3, 115, 1, 116],
  ];

  const ALIGN_POS = [
    null,
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
    [6, 30, 54],
    [6, 32, 58],
    [6, 34, 62],
    [6, 26, 46, 66],
  ];

  const GF_EXP = new Uint8Array(512);
  const GF_LOG = new Uint8Array(256);
  (() => {
    let x = 1;
    for (let i = 0; i < 255; i++) {
      GF_EXP[i] = x;
      GF_LOG[x] = i;
      x <<= 1;
      if (x & 0x100) x ^= 0x11d;
    }
    for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
  })();

  function gfMul(a, b) {
    if (a === 0 || b === 0) return 0;
    return GF_EXP[GF_LOG[a] + GF_LOG[b]];
  }

  function rsGeneratorPoly(ecCount) {
    let poly = [1];
    for (let i = 0; i < ecCount; i++) {
      const next = new Array(poly.length + 1).fill(0);
      const factor = GF_EXP[i];
      for (let j = 0; j < poly.length; j++) {
        next[j] ^= poly[j];
        next[j + 1] ^= gfMul(poly[j], factor);
      }
      poly = next;
    }
    return poly;
  }

  function rsComputeEc(data, ecCount) {
    const gen = rsGeneratorPoly(ecCount);
    const res = new Array(data.length + ecCount).fill(0);
    for (let i = 0; i < data.length; i++) res[i] = data[i];
    for (let i = 0; i < data.length; i++) {
      const coef = res[i];
      if (coef !== 0) {
        for (let j = 1; j < gen.length; j++) {
          res[i + j] ^= gfMul(gen[j], coef);
        }
      }
    }
    return res.slice(data.length);
  }

  function bchFormatBits(mask) {
    // EC level L = 01
    const data = (1 << 3) | mask;
    let rem = data << 10;
    for (let i = 14; i >= 10; i--) {
      if ((rem >>> i) & 1) rem ^= 0x537 << (i - 10);
    }
    return ((data << 10) | rem) ^ 0x5412;
  }

  function bchVersionBits(version) {
    let rem = version << 12;
    for (let i = 17; i >= 12; i--) {
      if ((rem >>> i) & 1) rem ^= 0x1f25 << (i - 12);
    }
    return (version << 12) | rem;
  }

  function encodeByteData(bytes) {
    let version = -1;
    for (let v = 1; v < EC_L_TABLE.length; v++) {
      const [, g1b, g1c, g2b, g2c] = EC_L_TABLE[v];
      const totalDataCw = g1b * g1c + g2b * g2c;
      const charCountBits = v < 10 ? 8 : 16;
      const neededBits = 4 + charCountBits + bytes.length * 8;
      if (neededBits <= totalDataCw * 8) {
        version = v;
        break;
      }
    }
    if (version === -1) {
      throw new Error("URL exceeds maximum QR capacity (Version 14).");
    }

    const [ecPerBlock, g1b, g1c, g2b, g2c] = EC_L_TABLE[version];
    const totalDataCw = g1b * g1c + g2b * g2c;
    const charCountBits = version < 10 ? 8 : 16;

    const bits = [];
    const pushBits = (val, count) => {
      for (let i = count - 1; i >= 0; i--) bits.push((val >>> i) & 1);
    };

    pushBits(0b0100, 4); // Byte mode
    pushBits(bytes.length, charCountBits);
    for (const b of bytes) pushBits(b, 8);

    const maxBits = totalDataCw * 8;
    const terminator = Math.min(4, maxBits - bits.length);
    for (let i = 0; i < terminator; i++) bits.push(0);
    while (bits.length % 8 !== 0) bits.push(0);

    const dataCw = [];
    for (let i = 0; i < bits.length; i += 8) {
      let byte = 0;
      for (let j = 0; j < 8; j++) byte = (byte << 1) | bits[i + j];
      dataCw.push(byte);
    }
    const padBytes = [0xec, 0x11];
    let padIdx = 0;
    while (dataCw.length < totalDataCw) {
      dataCw.push(padBytes[padIdx % 2]);
      padIdx++;
    }

    // Split blocks & compute RS EC
    const blocks = [];
    const ecBlocks = [];
    let offset = 0;
    for (let b = 0; b < g1b; b++) {
      const slice = dataCw.slice(offset, offset + g1c);
      blocks.push(slice);
      ecBlocks.push(rsComputeEc(slice, ecPerBlock));
      offset += g1c;
    }
    for (let b = 0; b < g2b; b++) {
      const slice = dataCw.slice(offset, offset + g2c);
      blocks.push(slice);
      ecBlocks.push(rsComputeEc(slice, ecPerBlock));
      offset += g2c;
    }

    const interleaved = [];
    const maxDataLen = Math.max(g1c, g2c);
    for (let i = 0; i < maxDataLen; i++) {
      for (let b = 0; b < blocks.length; b++) {
        if (i < blocks[b].length) interleaved.push(blocks[b][i]);
      }
    }
    for (let i = 0; i < ecPerBlock; i++) {
      for (let b = 0; b < ecBlocks.length; b++) {
        interleaved.push(ecBlocks[b][i]);
      }
    }

    const finalBits = [];
    for (const cw of interleaved) {
      for (let i = 7; i >= 0; i--) finalBits.push((cw >>> i) & 1);
    }
    return { version, bits: finalBits };
  }

  function buildMatrix(version, bitStream) {
    const size = version * 4 + 17;
    const mod = Array.from({ length: size }, () => new Int8Array(size)); // 0=unset, 1=light, 2=dark
    const isFunc = Array.from({ length: size }, () => new Uint8Array(size));

    const setFunc = (r, c, dark) => {
      if (r < 0 || r >= size || c < 0 || c >= size) return;
      mod[r][c] = dark ? 2 : 1;
      isFunc[r][c] = 1;
    };

    const drawFinder = (r0, c0) => {
      for (let dr = -1; dr <= 7; dr++) {
        for (let dc = -1; dc <= 7; dc++) {
          const inBox = dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6;
          const border = dr === 0 || dr === 6 || dc === 0 || dc === 6;
          const inner = dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4;
          setFunc(r0 + dr, c0 + dc, inBox && (border || inner));
        }
      }
    };

    drawFinder(0, 0);
    drawFinder(0, size - 7);
    drawFinder(size - 7, 0);

    // Timing patterns
    for (let i = 8; i < size - 8; i++) {
      const dark = i % 2 === 0;
      setFunc(6, i, dark);
      setFunc(i, 6, dark);
    }

    // Alignment patterns
    const pos = ALIGN_POS[version];
    for (const ar of pos) {
      for (const ac of pos) {
        const overlapsFinder =
          (ar <= 8 && ac <= 8) ||
          (ar <= 8 && ac >= size - 9) ||
          (ar >= size - 9 && ac <= 8);
        if (overlapsFinder) continue;
        for (let dr = -2; dr <= 2; dr++) {
          for (let dc = -2; dc <= 2; dc++) {
            const dark = Math.max(Math.abs(dr), Math.abs(dc)) !== 1;
            setFunc(ar + dr, ac + dc, dark);
          }
        }
      }
    }

    // Dark module + reserve format info
    setFunc(size - 8, 8, true);
    for (let i = 0; i < 9; i++) {
      if (i !== 6) {
        setFunc(8, i, false);
        setFunc(i, 8, false);
      }
    }
    for (let i = 0; i < 8; i++) {
      setFunc(8, size - 1 - i, false);
      setFunc(size - 1 - i, 8, false);
    }

    // Version info (>= 7)
    if (version >= 7) {
      const vBits = bchVersionBits(version);
      for (let i = 0; i < 18; i++) {
        const dark = ((vBits >>> i) & 1) === 1;
        const r = Math.floor(i / 3);
        const c = size - 11 + (i % 3);
        setFunc(r, c, dark);
        setFunc(c, r, dark);
      }
    }

    // Place data bits zig-zag
    let bitIdx = 0;
    let upward = true;
    for (let right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (let step = 0; step < size; step++) {
        const r = upward ? size - 1 - step : step;
        for (let dx = 0; dx < 2; dx++) {
          const c = right - dx;
          if (!isFunc[r][c]) {
            const bit = bitIdx < bitStream.length ? bitStream[bitIdx++] : 0;
            mod[r][c] = bit ? 2 : 1;
          }
        }
      }
      upward = !upward;
    }

    const maskFn = [
      (r, c) => (r + c) % 2 === 0,
      (r, c) => r % 2 === 0,
      (r, c) => c % 3 === 0,
      (r, c) => (r + c) % 3 === 0,
      (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
      (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
      (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
      (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0,
    ];

    let bestMask = 0;
    let bestScore = Infinity;
    let bestGrid = null;

    for (let m = 0; m < 8; m++) {
      const g = mod.map((row) => new Uint8Array(row.length));
      for (let r = 0; r < size; r++) {
        for (let c = 0; c < size; c++) {
          let dark = mod[r][c] === 2;
          if (!isFunc[r][c] && maskFn[m](r, c)) dark = !dark;
          g[r][c] = dark ? 1 : 0;
        }
      }
      // Write 15-bit format info (ISO/IEC 18004 Figure 19, MSB bit 14 down to LSB bit 0)
      const fmt = bchFormatBits(m);
      for (let k = 0; k < 15; k++) {
        const bit = (fmt >>> (14 - k)) & 1;

        // Horizontal strip along row 8: k=0..5 -> c=0..5, k=6 -> c=7, k=7..14 -> c=size-8..size-1 (plus (8,8)=k7)
        if (k < 6) g[8][k] = bit;
        else if (k === 6) g[8][7] = bit;
        else if (k === 7) {
          g[8][8] = bit;
          g[8][size - 8] = bit;
        } else {
          g[8][size - 15 + k] = bit;
        }

        // Vertical strip along col 8: k=0..6 -> r=size-1..size-7, k=7 -> r=8, k=8 -> r=7, k=9..14 -> r=5..0
        if (k < 7) g[size - 1 - k][8] = bit;
        else if (k === 7) g[8][8] = bit;
        else if (k === 8) g[7][8] = bit;
        else g[14 - k][8] = bit;
      }
      g[size - 8][8] = 1; // Always-dark module next to bottom-left finder

      const score = penaltyScore(g);
      if (score < bestScore) {
        bestScore = score;
        bestMask = m;
        bestGrid = g;
      }
    }

    return { size, grid: bestGrid, version, mask: bestMask };
  }

  function penaltyScore(g) {
    const n = g.length;
    let score = 0;
    let darkCount = 0;

    for (let r = 0; r < n; r++) {
      let runLen = 1;
      darkCount += g[r][0];
      for (let c = 1; c < n; c++) {
        darkCount += g[r][c];
        if (g[r][c] === g[r][c - 1]) {
          runLen++;
          if (runLen === 5) score += 3;
          else if (runLen > 5) score += 1;
        } else {
          runLen = 1;
        }
      }
    }
    for (let c = 0; c < n; c++) {
      let runLen = 1;
      for (let r = 1; r < n; r++) {
        if (g[r][c] === g[r - 1][c]) {
          runLen++;
          if (runLen === 5) score += 3;
          else if (runLen > 5) score += 1;
        } else {
          runLen = 1;
        }
      }
    }
    for (let r = 0; r < n - 1; r++) {
      for (let c = 0; c < n - 1; c++) {
        const sum = g[r][c] + g[r][c + 1] + g[r + 1][c] + g[r + 1][c + 1];
        if (sum === 0 || sum === 4) score += 3;
      }
    }
    const p1 = "10111010000";
    const p2 = "00001011101";
    for (let r = 0; r < n; r++) {
      const rowStr = g[r].join("");
      for (let i = 0; i <= n - 11; i++) {
        const sub = rowStr.substring(i, i + 11);
        if (sub === p1 || sub === p2) score += 40;
      }
    }
    for (let c = 0; c < n; c++) {
      let colStr = "";
      for (let r = 0; r < n; r++) colStr += g[r][c];
      for (let i = 0; i <= n - 11; i++) {
        const sub = colStr.substring(i, i + 11);
        if (sub === p1 || sub === p2) score += 40;
      }
    }
    const pct = (darkCount * 100) / (n * n);
    const k = Math.min(
      Math.floor(Math.abs(Math.floor(pct / 5) * 5 - 50) / 5),
      Math.floor(Math.abs(Math.ceil(pct / 5) * 5 - 50) / 5)
    );
    score += k * 10;
    return score;
  }

  function createMatrix(text) {
    const bytes = new TextEncoder().encode(text);
    const { version, bits } = encodeByteData(bytes);
    return buildMatrix(version, bits);
  }

  function toSvgElement(text, pixelSize = 200) {
    const { size, grid } = createMatrix(text);
    const quiet = 4;
    const full = size + quiet * 2;
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", `0 0 ${full} ${full}`);
    svg.setAttribute("width", String(pixelSize));
    svg.setAttribute("height", String(pixelSize));
    svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", "QR code for BurnBin secret link");
    svg.setAttribute("shape-rendering", "crispEdges");

    const bg = document.createElementNS(ns, "rect");
    bg.setAttribute("width", String(full));
    bg.setAttribute("height", String(full));
    bg.setAttribute("fill", "#ffffff");
    svg.appendChild(bg);

    let d = "";
    for (let r = 0; r < size; r++) {
      for (let c = 0; c < size; c++) {
        if (grid[r][c]) {
          d += `M${c + quiet},${r + quiet}h1v1h-1z`;
        }
      }
    }
    const path = document.createElementNS(ns, "path");
    path.setAttribute("d", d);
    path.setAttribute("fill", "#000000");
    svg.appendChild(path);
    return svg;
  }

  function toPngDataUrl(text, scale = 8) {
    const { size, grid } = createMatrix(text);
    const quiet = 4;
    const full = (size + quiet * 2) * scale;
    const canvas = document.createElement("canvas");
    canvas.width = full;
    canvas.height = full;
    const ctx = canvas.getContext("2d");
    ctx.fillStyle = "#ffffff";
    ctx.fillRect(0, 0, full, full);
    ctx.fillStyle = "#000000";
    for (let r = 0; r < size; r++) {
      for (let c = 0; c < size; c++) {
        if (grid[r][c]) {
          ctx.fillRect((c + quiet) * scale, (r + quiet) * scale, scale, scale);
        }
      }
    }
    return canvas.toDataURL("image/png");
  }

  root.BurnBinQR = {
    createMatrix,
    toSvgElement,
    toPngDataUrl,
  };
})(window);
