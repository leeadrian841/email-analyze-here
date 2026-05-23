// export.js — JSON / Markdown download and print-to-PDF.

import { redactRecipient } from './render.js';

function download(filename, text, mime) {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function maybeRedact(obj, redact, recipient) {
  if (!redact) return obj;
  const clone = JSON.parse(JSON.stringify(obj));
  const walk = (o) => {
    if (typeof o === 'string') return redactRecipient(o, recipient);
    if (Array.isArray(o)) return o.map(walk);
    if (o && typeof o === 'object') {
      for (const k of Object.keys(o)) o[k] = walk(o[k]);
      return o;
    }
    return o;
  };
  return walk(clone);
}

export function exportJson(analysis, opts = {}) {
  const obj = maybeRedact(analysis, opts.redact, opts.recipient);
  const { _meta, ...clean } = obj;
  download(`${analysis.id}.json`, JSON.stringify(clean, null, 2), 'application/json');
}

export function exportMarkdown(analysis, opts = {}) {
  const a = maybeRedact(analysis, opts.redact, opts.recipient);
  const L = [];
  L.push(`# ${a.title}`, '');
  L.push(`> **${a.verdict}** — ${a.tldr}`, '');
  L.push(`- **Severity:** ${a.severity}`);
  L.push(`- **Category:** ${a.category} (${a.subtitle})`);
  L.push(`- **Received:** ${a.date}`);
  L.push(`- **Tags:** ${a.tags.join(', ') || '—'}`, '');
  L.push('## Case Summary', '', a.summary, '');

  L.push('## Red Flags', '');
  if (a.redFlags.length) a.redFlags.forEach((f) => L.push(`- **[${f.severity}]** ${f.flag}`));
  else L.push('_None._');
  L.push('');

  L.push('## Attack Techniques', '');
  if (a.techniques.length) a.techniques.forEach((t) => L.push(`- ${t}`));
  else L.push('_None identified._');
  L.push('');

  L.push('## Indicators of Compromise', '');
  if (a.iocs.length) {
    L.push('| Type | Value |', '|---|---|');
    a.iocs.forEach((i) => L.push(`| ${i.type} | \`${i.value}\` |`));
  } else L.push('_None extracted._');
  L.push('');

  L.push('## Email Headers', '');
  L.push('| Flag | Header | Value |', '|---|---|---|');
  a.emailHeaders.forEach((h) => L.push(`| ${h.flagged ? '⚑' : ''} | ${h.key} | \`${(h.value || '').replace(/\|/g, '\\|')}\` |`));
  L.push('');

  L.push('## Forensic Analysis', '');
  a.analysis.forEach((s) => {
    L.push(`### ${s.step}`, '', s.content, '');
    if (s.codeBlock) {
      L.push(`**${s.codeBlock.title}**`, '', '```' + (s.codeBlock.language || ''), s.codeBlock.code, '```', '');
    }
  });

  L.push('## Recommendations', '');
  a.recommendations.forEach((rrec, i) => L.push(`${i + 1}. ${rrec}`));
  L.push('');
  L.push('---', `_Generated locally in-browser by the Email Threat Analysis Platform. No data left this machine._`);

  download(`${analysis.id}.md`, L.join('\n'), 'text/markdown');
}

export function exportPdf() {
  // Browser print dialog → "Save as PDF". A print stylesheet handles layout.
  window.print();
}
