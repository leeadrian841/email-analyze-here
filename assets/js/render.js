// render.js — turns an EmailAnalysis object into safe DOM.
// Every value derived from the (hostile) email is HTML-escaped. Raw HTML
// bodies are NEVER injected into the page.

import { SEVERITY_ORDER } from './patterns.js';

export function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

const sevClass = (s) => `sev-${String(s).toLowerCase()}`;

function sevBadge(s) {
  return `<span class="badge ${sevClass(s)}">${esc(s)}</span>`;
}

function section(title, id, bodyHtml, count) {
  return `
    <section class="card" id="${id}">
      <h2 class="card-title">${esc(title)}${count != null ? ` <span class="count">${count}</span>` : ''}</h2>
      ${bodyHtml}
    </section>`;
}

export function renderReport(a, opts = {}) {
  const redact = !!opts.redact;
  const r = (v) => (redact ? redactRecipient(v, opts.recipient) : v);

  const sortedFlags = [...a.redFlags].sort((x, y) => SEVERITY_ORDER[y.severity] - SEVERITY_ORDER[x.severity]);

  const verdict = `
    <div class="verdict ${sevClass(a.severity)}">
      <div class="verdict-main">
        <div class="verdict-sev">${sevBadge(a.severity)}<span class="verdict-cat">${esc(a.category)}</span></div>
        <p class="verdict-tldr">${esc(a.tldr)}</p>
      </div>
      <div class="verdict-meta">
        <div><span class="k">Verdict</span><span class="v">${esc(a.verdict)}</span></div>
        <div><span class="k">Received</span><span class="v">${esc(a.date)}</span></div>
        <div><span class="k">Indicators</span><span class="v">${a.redFlags.length}</span></div>
      </div>
    </div>`;

  // Case summary.
  const tags = a.tags.length ? `<div class="tags">${a.tags.map((t) => `<span class="tag">${esc(t)}</span>`).join('')}</div>` : '';
  const summary = section('Case Summary', 'sec-summary', `
    <h3 class="case-title">${esc(r(a.title))}</h3>
    <p class="subtitle">${esc(a.subtitle)}</p>
    ${tags}
    <p class="summary-text">${esc(r(a.summary))}</p>
  `);

  // Red flags.
  const flagsBody = sortedFlags.length
    ? `<ul class="flag-list">${sortedFlags.map((f) => `
        <li class="flag ${sevClass(f.severity)}">
          ${sevBadge(f.severity)}<span class="flag-text">${esc(r(f.flag))}</span>
        </li>`).join('')}</ul>`
    : '<p class="empty">No red flags raised.</p>';
  const flags = section('Red Flags (Attack Indicators)', 'sec-flags', flagsBody, sortedFlags.length);

  // Techniques.
  const techBody = a.techniques.length
    ? `<div class="chips">${a.techniques.map((t) => `<span class="chip">${esc(t)}</span>`).join('')}</div>`
    : '<p class="empty">No specific attack techniques identified.</p>';
  const techniques = section('Attack Techniques', 'sec-tech', techBody, a.techniques.length);

  // IOCs grouped by type.
  const grouped = {};
  for (const ioc of a.iocs) (grouped[ioc.type] = grouped[ioc.type] || []).push(ioc.value);
  const iocBody = Object.keys(grouped).length
    ? `<div class="ioc-grid">${Object.entries(grouped).map(([type, vals]) => `
        <div class="ioc-group">
          <div class="ioc-type">${esc(type)} <span class="count">${vals.length}</span></div>
          <ul>${[...new Set(vals)].map((v) => `<li><code>${esc(r(v))}</code></li>`).join('')}</ul>
        </div>`).join('')}</div>`
    : '<p class="empty">No indicators of compromise extracted.</p>';
  const iocs = section('Indicators of Compromise', 'sec-iocs', iocBody, a.iocs.length);

  // Headers table.
  const flaggedCount = a.emailHeaders.filter((h) => h.flagged).length;
  const headerRows = a.emailHeaders.map((h) => `
    <tr class="${h.flagged ? 'flagged' : ''}">
      <td class="h-key">${h.flagged ? '<span class="flag-dot" title="' + esc(h.reason || 'Flagged') + '"></span>' : ''}${esc(h.key)}</td>
      <td class="h-val"><code>${esc(r(h.value))}</code>${h.flagged && h.reason ? `<span class="h-reason">${esc(h.reason)}</span>` : ''}</td>
    </tr>`).join('');
  const headersBody = a.emailHeaders.length
    ? `<div class="table-wrap"><table class="headers"><tbody>${headerRows}</tbody></table></div>
       <p class="hint">${flaggedCount} of ${a.emailHeaders.length} headers flagged. Flagged rows are highlighted; hover the dot for the reason.</p>`
    : '<p class="empty">No headers parsed.</p>';
  const headers = section('Email Headers', 'sec-headers', headersBody, a.emailHeaders.length);

  // Forensic analysis steps.
  const stepsBody = a.analysis.map((s) => `
    <div class="step">
      <h3 class="step-title">${esc(s.step)}</h3>
      <p class="step-content">${esc(r(s.content)).replace(/\n\n/g, '</p><p class="step-content">').replace(/\n/g, '<br>')}</p>
      ${s.codeBlock ? `
        <div class="code-block">
          <div class="code-title">${esc(s.codeBlock.title)}</div>
          <pre><code>${esc(r(s.codeBlock.code))}</code></pre>
        </div>` : ''}
    </div>`).join('');
  const analysis = section('Forensic Analysis', 'sec-analysis', stepsBody);

  // Recommendations.
  const recsBody = a.recommendations.length
    ? `<ol class="recs">${a.recommendations.map((x) => `<li>${esc(x)}</li>`).join('')}</ol>`
    : '<p class="empty">No recommendations.</p>';
  const recs = section('Recommendations', 'sec-recs', recsBody);

  // Attachments.
  let attach = '';
  const at = (a._meta && a._meta.attachments) || [];
  if (at.length) {
    attach = section('Attachments', 'sec-attach', `
      <div class="table-wrap"><table class="headers"><thead><tr><th>Filename</th><th>Type</th><th>Encoding</th><th>~Size</th></tr></thead>
      <tbody>${at.map((x) => `<tr><td>${esc(x.filename)}</td><td><code>${esc(x.contentType)}</code></td><td>${esc(x.encoding)}</td><td>${fmtBytes(x.size)}</td></tr>`).join('')}</tbody></table></div>
      <p class="hint">Attachments are listed for evidence only — they are never opened, decoded to disk, or executed.</p>
    `, at.length);
  }

  return `
    ${verdict}
    <div class="report-grid">
      ${summary}
      ${flags}
      ${headers}
      ${techniques}
      ${iocs}
      ${attach}
      ${analysis}
      ${recs}
    </div>`;
}

function fmtBytes(n) {
  if (!n && n !== 0) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function redactRecipient(value, recipient) {
  if (!value) return value;
  let out = String(value);
  if (recipient) {
    out = out.split(recipient).join('[recipient]');
    const user = recipient.split('@')[0];
    if (user && user.length > 2) out = out.split(user).join('[recipient]');
  }
  return out;
}
