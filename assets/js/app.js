// app.js — UI wiring. All work happens in-browser.

import { parseEmail } from './parser.js';
import { analyze, parseAddress } from './analyzer.js';
import { renderReport } from './render.js';
import { exportJson, exportMarkdown, exportPdf } from './export.js';
import { SAMPLES } from './samples.js';

const $ = (sel) => document.querySelector(sel);

const els = {
  drop: $('#dropzone'),
  file: $('#fileInput'),
  textarea: $('#rawInput'),
  analyzeBtn: $('#analyzeBtn'),
  clearBtn: $('#clearBtn'),
  samples: $('#sampleButtons'),
  results: $('#results'),
  report: $('#report'),
  empty: $('#emptyState'),
  redact: $('#redactToggle'),
  exJson: $('#exportJson'),
  exMd: $('#exportMd'),
  exPdf: $('#exportPdf'),
  errorBox: $('#errorBox'),
};

let current = null;     // last analysis object
let recipient = '';     // parsed recipient for redaction

function showError(msg) {
  els.errorBox.textContent = msg;
  els.errorBox.hidden = !msg;
}

function runAnalysis(raw) {
  showError('');
  if (!raw || !raw.trim()) { showError('Paste an email, upload an .eml file, or load a sample first.'); return; }
  try {
    const parsed = parseEmail(raw);
    if (!parsed.headers.length && !parsed.hasBody) {
      showError('Could not parse any headers or body from that input. Make sure you pasted the full email including headers.');
      return;
    }
    recipient = parseAddress(parsed.get('to') || parsed.get('delivered-to') || '').email || '';
    current = analyze(parsed);
    render();
  } catch (e) {
    console.error(e);
    showError('Analysis failed: ' + (e && e.message ? e.message : 'unexpected error') + '. The input may be malformed.');
  }
}

function render() {
  if (!current) return;
  const opts = { redact: els.redact.checked, recipient };
  els.report.innerHTML = renderReport(current, opts);
  els.empty.hidden = true;
  els.results.hidden = false;
  els.results.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ---- input handlers ------------------------------------------------------

els.analyzeBtn.addEventListener('click', () => runAnalysis(els.textarea.value));

els.clearBtn.addEventListener('click', () => {
  els.textarea.value = '';
  current = null; recipient = '';
  els.results.hidden = true;
  els.empty.hidden = false;
  showError('');
  els.textarea.focus();
});

els.file.addEventListener('change', async (e) => {
  const f = e.target.files && e.target.files[0];
  if (!f) return;
  const text = await f.text();
  els.textarea.value = text;
  runAnalysis(text);
  els.file.value = '';
});

['dragover', 'dragenter'].forEach((evt) =>
  els.drop.addEventListener(evt, (e) => { e.preventDefault(); els.drop.classList.add('drag'); }));
['dragleave', 'drop'].forEach((evt) =>
  els.drop.addEventListener(evt, (e) => { e.preventDefault(); els.drop.classList.remove('drag'); }));
els.drop.addEventListener('drop', async (e) => {
  const f = e.dataTransfer.files && e.dataTransfer.files[0];
  if (!f) return;
  const text = await f.text();
  els.textarea.value = text;
  runAnalysis(text);
});
els.drop.addEventListener('click', () => els.file.click());
els.drop.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); els.file.click(); } });

// Sample buttons.
SAMPLES.forEach((s) => {
  const b = document.createElement('button');
  b.className = 'sample-btn';
  b.type = 'button';
  b.textContent = s.label;
  b.addEventListener('click', () => { els.textarea.value = s.raw; runAnalysis(s.raw); });
  els.samples.appendChild(b);
});

// Export + redact.
els.redact.addEventListener('change', render);
els.exJson.addEventListener('click', () => current && exportJson(current, { redact: els.redact.checked, recipient }));
els.exMd.addEventListener('click', () => current && exportMarkdown(current, { redact: els.redact.checked, recipient }));
els.exPdf.addEventListener('click', () => exportPdf());

// Ctrl/Cmd+Enter to analyze.
els.textarea.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); runAnalysis(els.textarea.value); }
});
