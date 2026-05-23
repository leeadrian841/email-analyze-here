// parser.js — pure-browser RFC 822 / MIME email parser.
// Handles full .eml files, raw pasted email (headers + body), or headers-only input.
// No data ever leaves the browser.

const STANDARD_CTE = new Set([
  '7bit', '8bit', 'binary', 'quoted-printable', 'base64',
]);

// ---- Low-level byte/charset helpers -------------------------------------

function binaryStringToBytes(bin) {
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i) & 0xff;
  return bytes;
}

function decodeBytes(bytes, charset) {
  const cs = (charset || 'utf-8').toLowerCase().trim();
  try {
    return new TextDecoder(cs).decode(bytes);
  } catch (_) {
    try {
      return new TextDecoder('utf-8').decode(bytes);
    } catch (_2) {
      // Last resort: latin1-ish
      let out = '';
      for (let i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]);
      return out;
    }
  }
}

function base64ToBytes(b64) {
  const clean = b64.replace(/[^A-Za-z0-9+/=]/g, '');
  try {
    return binaryStringToBytes(atob(clean));
  } catch (_) {
    return new Uint8Array(0);
  }
}

function quotedPrintableToBytes(input) {
  // Remove soft line breaks, then decode =XX sequences.
  const text = input.replace(/=\r?\n/g, '');
  const out = [];
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '=' && i + 2 < text.length) {
      const hex = text.substr(i + 1, 2);
      if (/^[0-9A-Fa-f]{2}$/.test(hex)) {
        out.push(parseInt(hex, 16));
        i += 2;
        continue;
      }
    }
    out.push(ch.charCodeAt(0) & 0xff);
  }
  return Uint8Array.from(out);
}

// ---- RFC 2047 encoded-word decoding (for header display) ----------------

function decodeEncodedWords(str) {
  if (!str || str.indexOf('=?') === -1) return str;
  // Join adjacent encoded words separated only by whitespace (RFC 2047 rule).
  const joined = str.replace(/\?=\s+=\?/g, '?==?');
  return joined.replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, (m, charset, enc, data) => {
    try {
      if (enc.toUpperCase() === 'B') {
        return decodeBytes(base64ToBytes(data), charset);
      }
      // Q encoding: _ => space, =XX => byte
      const qp = data.replace(/_/g, ' ');
      return decodeBytes(quotedPrintableToBytes(qp), charset);
    } catch (_) {
      return m;
    }
  });
}

// ---- Header parsing ------------------------------------------------------

function splitHeadersAndBody(raw) {
  // Normalize to detect the first blank line (header/body separator).
  const m = raw.match(/\r?\n\r?\n/);
  if (!m) return { headerBlock: raw, body: '' };
  const idx = m.index;
  const sepLen = m[0].length;
  return {
    headerBlock: raw.slice(0, idx),
    body: raw.slice(idx + sepLen),
  };
}

function parseHeaderBlock(headerBlock) {
  const lines = headerBlock.split(/\r?\n/);
  const headers = [];
  let current = null;
  for (const line of lines) {
    if (/^[ \t]/.test(line) && current) {
      // Folded continuation line.
      current.rawValue += '\n' + line.replace(/^[ \t]+/, ' ').replace(/^ /, '');
      current.rawValue = current.rawValue; // keep as-is
    } else {
      const ci = line.indexOf(':');
      if (ci === -1) {
        // Malformed line — attach to previous value if any, else skip.
        if (current) current.rawValue += '\n' + line;
        continue;
      }
      current = {
        key: line.slice(0, ci).trim(),
        rawValue: line.slice(ci + 1).replace(/^ /, ''),
      };
      headers.push(current);
    }
  }
  // Build display value (unfolded + encoded-word decoded).
  for (const h of headers) {
    const unfolded = h.rawValue.replace(/\n[ \t]*/g, ' ').replace(/\n/g, ' ').trim();
    h.value = decodeEncodedWords(unfolded);
    h.rawValue = h.rawValue.replace(/\n[ \t]*/g, ' ').trim();
  }
  return headers;
}

// ---- Content-Type / parameter parsing -----------------------------------

function parseContentType(value) {
  if (!value) return { type: 'text/plain', params: {} };
  const parts = value.split(';');
  const type = parts[0].trim().toLowerCase();
  const params = {};
  for (let i = 1; i < parts.length; i++) {
    const eq = parts[i].indexOf('=');
    if (eq === -1) continue;
    const k = parts[i].slice(0, eq).trim().toLowerCase();
    let v = parts[i].slice(eq + 1).trim();
    v = v.replace(/^"(.*)"$/, '$1');
    params[k] = v;
  }
  return { type, params };
}

// ---- MIME body walking ---------------------------------------------------

function decodePartBody(bodyText, cte, charset) {
  const enc = (cte || '7bit').toLowerCase().trim();
  if (enc === 'base64') return decodeBytes(base64ToBytes(bodyText), charset);
  if (enc === 'quoted-printable') return decodeBytes(quotedPrintableToBytes(bodyText), charset);
  // 7bit / 8bit / binary / unknown — treat as already text.
  return bodyText;
}

function walkPart(headers, body, acc) {
  const ctHeader = findHeaderValue(headers, 'content-type');
  const { type, params } = parseContentType(ctHeader);
  const cte = findHeaderValue(headers, 'content-transfer-encoding') || '7bit';
  const disposition = (findHeaderValue(headers, 'content-disposition') || '').toLowerCase();
  const filename = extractFilename(params, findHeaderValue(headers, 'content-disposition'));

  if (type.startsWith('multipart/') && params.boundary) {
    const segments = splitMultipart(body, params.boundary);
    for (const seg of segments) {
      const { headerBlock, body: segBody } = splitHeadersAndBody(seg);
      const segHeaders = parseHeaderBlock(headerBlock);
      walkPart(segHeaders, segBody, acc);
    }
    return;
  }

  const isAttachment = disposition.startsWith('attachment') || (filename && !type.startsWith('text/'));

  if (isAttachment) {
    let size = body.length;
    if (cte.toLowerCase().trim() === 'base64') size = Math.floor(body.replace(/\s/g, '').length * 3 / 4);
    acc.attachments.push({
      filename: filename || '(unnamed)',
      contentType: type,
      encoding: cte.trim(),
      size,
    });
    return;
  }

  const decoded = decodePartBody(body, cte, params.charset);
  if (type === 'text/html') {
    acc.html += decoded;
  } else if (type === 'text/plain') {
    acc.text += decoded;
  } else if (type.startsWith('text/')) {
    acc.text += decoded;
  } else if (!acc.html && !acc.text) {
    // Single-part non-text fallback.
    acc.text += decoded;
  }
}

function splitMultipart(body, boundary) {
  const delim = '--' + boundary;
  const parts = [];
  const lines = body.split(/\r?\n/);
  let buf = [];
  let started = false;
  for (const line of lines) {
    if (line === delim || line === delim + '--') {
      if (started) parts.push(buf.join('\n'));
      buf = [];
      started = true;
      if (line === delim + '--') break;
    } else if (started) {
      buf.push(line);
    }
  }
  return parts;
}

function extractFilename(params, dispositionRaw) {
  if (params && params.name) return decodeEncodedWords(params.name);
  if (dispositionRaw) {
    const m = dispositionRaw.match(/filename\*?=("?)([^";]+)\1/i);
    if (m) return decodeEncodedWords(m[2].trim());
  }
  return null;
}

function findHeaderValue(headers, name) {
  const lower = name.toLowerCase();
  for (const h of headers) {
    if (h.key.toLowerCase() === lower) return h.rawValue;
  }
  return null;
}

// ---- Public API ----------------------------------------------------------

export function parseEmail(raw) {
  raw = (raw || '').replace(/^﻿/, ''); // strip BOM
  const { headerBlock, body } = splitHeadersAndBody(raw);
  const headers = parseHeaderBlock(headerBlock);

  // Build a case-insensitive multimap.
  const map = new Map();
  for (const h of headers) {
    const k = h.key.toLowerCase();
    if (!map.has(k)) map.set(k, []);
    map.get(k).push(h.value);
  }

  const acc = { text: '', html: '', attachments: [] };
  const hasBody = body.trim().length > 0;
  if (hasBody) {
    try {
      walkPart(headers, body, acc);
    } catch (_) {
      acc.text = body;
    }
  }

  // Derive a plain-text view of the HTML for content scanning.
  let htmlText = '';
  if (acc.html) {
    htmlText = acc.html
      .replace(/<style[\s\S]*?<\/style>/gi, ' ')
      .replace(/<script[\s\S]*?<\/script>/gi, ' ')
      .replace(/<[^>]+>/g, ' ')
      .replace(/&nbsp;/gi, ' ')
      .replace(/&amp;/gi, '&')
      .replace(/&lt;/gi, '<')
      .replace(/&gt;/gi, '>')
      .replace(/\s+/g, ' ')
      .trim();
  }

  return {
    raw,
    headers,            // ordered, with duplicates preserved
    headerMap: map,
    bodyText: acc.text,
    bodyHtml: acc.html,
    bodyHtmlText: htmlText,
    combinedText: [acc.text, htmlText].filter(Boolean).join('\n'),
    attachments: acc.attachments,
    hasBody,

    get(name) {
      const v = map.get(name.toLowerCase());
      return v ? v[0] : null;
    },
    getAll(name) {
      return map.get(name.toLowerCase()) || [];
    },
    has(name) {
      return map.has(name.toLowerCase());
    },
  };
}

export { decodeEncodedWords, parseContentType, STANDARD_CTE };
