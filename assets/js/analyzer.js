// analyzer.js — turns a parsed email into the rigid EmailAnalysis object.
// All detection logic runs locally; nothing is sent anywhere.

import {
  SEVERITY_ORDER, SUSPICIOUS_TLDS, SUSPICIOUS_DOMAIN_SUFFIXES, TRACKING_INFRA,
  TRACKING_PARAMS, PERSONAL_ISP_DOMAINS, FREEMAIL_DOMAINS, BULK_ESPS, VALID_CTE,
  REGISTERED_AGENT_HINTS, KNOWN_IMPERSONATED, SEXTORTION_TERMS, ADVANCE_FEE_TERMS,
  BEC_PROBE_PHRASES, PHISHING_TERMS, PII_SOLICITATION, CAMPAIGN_FINGERPRINTS,
  RE, KNOWN_HTML_TAGS,
} from './patterns.js';

const MULTI_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'co.nz', 'com.au', 'net.au',
  'com.br', 'com.ar', 'biz.ua', 'co.za', 'co.jp', 'edu.ng', 'edu.tw',
  'com.ng', 'co.in',
]);

// ---- small utilities -----------------------------------------------------

function maxSeverity(severities) {
  let best = null;
  for (const s of severities) {
    if (!best || SEVERITY_ORDER[s] > SEVERITY_ORDER[best]) best = s;
  }
  return best || 'Low';
}

function uniq(arr) { return Array.from(new Set(arr)); }

function slugify(s) {
  return (s || 'analysis')
    .toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60) || 'analysis';
}

function parseAddress(raw) {
  if (!raw) return { display: '', email: '', domain: '' };
  raw = raw.trim();
  let display = '';
  let email = '';
  const angle = raw.match(/^(.*?)<([^>]+)>/);
  if (angle) {
    display = angle[1].trim().replace(/^"(.*)"$/, '$1').trim();
    email = angle[2].trim();
  } else {
    const m = raw.match(RE.email);
    email = m ? m[0] : raw;
  }
  const domain = email.includes('@') ? email.split('@').pop().toLowerCase() : '';
  return { display, email: email.toLowerCase(), domain };
}

function registrableDomain(domain) {
  if (!domain) return '';
  const labels = domain.toLowerCase().split('.');
  if (labels.length <= 2) return domain.toLowerCase();
  const lastTwo = labels.slice(-2).join('.');
  const lastThree = labels.slice(-3).join('.');
  if (MULTI_SUFFIXES.has(lastTwo)) return lastThree;
  return lastTwo;
}

function looksLikeDomain(v) {
  return /^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test((v || '').trim());
}

// ---- authentication analysis --------------------------------------------

function analyzeAuth(p) {
  const authResults = p.getAll('authentication-results').join(' ');
  const recvSpf = (p.get('received-spf') || '').toLowerCase();
  const dkimSigs = p.getAll('dkim-signature');
  const result = {
    spf: null, dkim: null, dmarc: null,
    spfDomain: null, dkimDomain: null, dkimAlg: null,
    notes: [], flags: [], scenario: '', raw: authResults || '(no Authentication-Results header)',
  };

  const grab = (re) => {
    const m = authResults.match(re);
    return m ? m[1].toLowerCase() : null;
  };
  result.spf = grab(/spf=(\w+)/i) || (recvSpf.match(/^\s*(pass|fail|softfail|neutral|none)/) || [])[1] || null;
  result.dkim = grab(/dkim=(\w+)/i);
  result.dmarc = grab(/dmarc=(\w+)/i);
  const domPart = (v) => (v.includes('@') ? v.split('@').pop() : v).replace(/^@/, '');
  const mf = authResults.match(/smtp\.mailfrom=([^\s;]+)/i);
  if (mf) result.spfDomain = domPart(mf[1].toLowerCase());
  const hd = authResults.match(/header\.(?:d|i)=([^\s;]+)/i);
  if (hd) result.dkimDomain = domPart(hd[1].toLowerCase());

  if (dkimSigs.length) {
    const sig = dkimSigs[0];
    const a = sig.match(/[;\s]a=([a-z0-9-]+)/i);
    const d = sig.match(/[;\s]d=([^;\s]+)/i);
    if (a) result.dkimAlg = a[1].toLowerCase();
    if (d && !result.dkimDomain) result.dkimDomain = d[1].toLowerCase();
  }

  const spfPass = result.spf === 'pass';
  const dkimPass = result.dkim === 'pass';
  const dmarcPass = result.dmarc === 'pass';

  // Scenario classification per the knowledge base.
  if (!spfPass && !dkimPass && !dmarcPass) {
    result.scenario = 'all-fail';
    result.notes.push('All authentication is failing or absent — the strongest possible negative signal. The sender cannot prove control of the From domain.');
    result.flags.push({ flag: 'Authentication entirely absent or failing (SPF/DKIM/DMARC)', severity: 'Critical' });
  } else if (spfPass && !dkimPass && !dmarcPass) {
    result.scenario = 'spf-only';
    result.notes.push('SPF passes but there is no DKIM and no DMARC. SPF only proves the sending IP is authorised for the envelope-sender (Return-Path) domain — NOT the visible From address. This is a misleading pass: check whether the SPF domain is the same as the From domain (it usually is not).');
  } else if (spfPass && dkimPass && dmarcPass) {
    result.scenario = 'all-pass';
    result.notes.push('All authentication passes. This proves the message was sent through infrastructure authorised for the signing domain — it does NOT prove the email is safe. Attackers who register their own domain, abuse a paid ESP, or send from a compromised legitimate account all pass authentication cleanly. Detection here must come from content, behaviour, and reply-channel analysis.');
  } else {
    result.scenario = 'mixed';
    result.notes.push('Mixed authentication results — interpret each signal on its own merits rather than as a single pass/fail verdict.');
  }

  // Per-signal contextual notes.
  if (spfPass) {
    if (result.spfDomain && p.get('from')) {
      const fromDom = registrableDomain(parseAddress(p.get('from')).domain);
      const spfDom = registrableDomain(result.spfDomain);
      if (fromDom && spfDom && fromDom !== spfDom) {
        result.notes.push(`SPF passed for "${result.spfDomain}", but the visible From domain is "${parseAddress(p.get('from')).domain}". The pass does not vouch for the address the recipient actually sees.`);
        result.flags.push({ flag: `SPF authorises a different domain (${result.spfDomain}) than the visible From (${parseAddress(p.get('from')).domain})`, severity: 'High' });
      }
    }
  } else if (result.spf === 'fail') {
    result.flags.push({ flag: 'SPF fail — sending IP is not authorised for the sender domain', severity: 'High' });
  }

  if (dkimPass && result.dkimDomain && p.get('from')) {
    const fromDom = registrableDomain(parseAddress(p.get('from')).domain);
    const dkimDom = registrableDomain(result.dkimDomain);
    const depth = (result.dkimDomain.match(/\./g) || []).length;
    if (fromDom && dkimDom && fromDom !== dkimDom) {
      result.notes.push(`DKIM is valid but signed by "${result.dkimDomain}", which does not align with the From domain. A valid signature on an unrelated (often junk) subdomain proves nothing about sender legitimacy.`);
      result.flags.push({ flag: `DKIM signed by non-aligned domain (${result.dkimDomain})`, severity: depth >= 3 ? 'High' : 'Medium' });
    }
    if (depth >= 3) {
      result.flags.push({ flag: `DKIM signed by a deeply-nested junk subdomain (${result.dkimDomain})`, severity: 'High' });
    }
  }
  if (result.dkimAlg === 'rsa-sha1') {
    result.notes.push('DKIM uses the deprecated rsa-sha1 algorithm. Modern legitimate senders use rsa-sha256; SHA-1 is a soft negative signal.');
    result.flags.push({ flag: 'DKIM uses deprecated rsa-sha1 algorithm', severity: 'Medium' });
  }
  if (!dkimSigs.length && result.dkim !== 'pass') {
    result.notes.push('No DKIM signature is present. Legitimate corporate senders almost always sign with DKIM; absence is a moderate negative signal.');
  }

  if (result.dmarc === 'none' || result.dmarc === null) {
    result.notes.push('No usable DMARC result. DMARC is the only signal that meaningfully ties authentication to the visible From domain; its absence means a forged From would not be caught by policy.');
  } else if (result.dmarc === 'fail') {
    result.flags.push({ flag: 'DMARC fail — authentication does not align with the visible From domain', severity: 'High' });
  }

  return result;
}

// ---- header inspection ---------------------------------------------------

function analyzeHeaders(p, auth, ctx) {
  const flags = [];
  const flaggedKeys = new Map(); // index -> reason
  const headers = p.headers;
  const from = parseAddress(p.get('from'));
  const replyTo = parseAddress(p.get('reply-to'));
  const fromReg = registrableDomain(from.domain);

  // Duplicate conflicting headers.
  const byKey = {};
  headers.forEach((h, i) => {
    const k = h.key.toLowerCase();
    (byKey[k] = byKey[k] || []).push({ i, v: h.value });
  });
  for (const k of ['delivered-to', 'content-length', 'message-id']) {
    if (byKey[k] && byKey[k].length > 1) {
      const vals = uniq(byKey[k].map((x) => x.v));
      if (vals.length > 1) {
        byKey[k].forEach((x) => flaggedKeys.set(x.i, 'Duplicate conflicting header'));
        flags.push({ flag: `Duplicate conflicting "${h_title(k)}" headers (${vals.join(' vs ')})`, severity: 'Medium' });
      }
    }
  }

  headers.forEach((h, i) => {
    const k = h.key.toLowerCase();
    const v = h.value || '';
    const setF = (reason) => flaggedKeys.set(i, reason);

    switch (k) {
      case 'from': {
        if (from.domain && FREEMAIL_DOMAINS.includes(from.domain) && from.display &&
            /\b(ceo|cfo|director|manager|bank|inc|llc|ltd|corp|office|department|support|team|admin)\b/i.test(from.display)) {
          setF('Corporate display name on a free webmail address');
          flags.push({ flag: `Display name "${from.display}" claims authority but sends from free webmail (${from.domain})`, severity: 'High' });
        }
        if (from.domain && PERSONAL_ISP_DOMAINS.includes(from.domain) && from.display) {
          setF('Corporate-sounding display name on a personal ISP account');
        }
        break;
      }
      case 'reply-to': {
        if (replyTo.domain && fromReg && registrableDomain(replyTo.domain) !== fromReg) {
          setF('Reply-To redirects to a different domain than the sender');
          flags.push({ flag: `Reply-channel misdirection: Reply-To (${replyTo.email}) differs from From domain (${from.domain})`, severity: 'High' });
          ctx.replyChannelMismatch = true;
        }
        break;
      }
      case 'x-google-sender-delegation': {
        if (v && !looksLikeDomain(v)) {
          setF('Fabricated header — real values are domain names');
          flags.push({ flag: `Fabricated X-Google-Sender-Delegation header (non-domain value "${v}")`, severity: 'High' });
        }
        break;
      }
      case 'content-transfer-encoding': {
        if (v && !VALID_CTE.has(v.toLowerCase().trim())) {
          setF('Invalid Content-Transfer-Encoding value');
          flags.push({ flag: `Invalid Content-Transfer-Encoding value ("${v}")`, severity: 'Low' });
        }
        break;
      }
      case 'domainkey-signature': {
        setF('Legacy DomainKey-Signature (deprecated since 2007)');
        flags.push({ flag: 'Legacy DomainKey-Signature present (deprecated 2007)', severity: 'Low' });
        break;
      }
      case 'disposition-notification-to':
      case 'return-receipt-to':
      case 'x-confirm-reading-to': {
        setF('Silent read-receipt request — used to confirm a live inbox');
        flags.push({ flag: 'Read-receipt request — used to confirm the inbox is monitored', severity: 'Medium' });
        break;
      }
      case 'precedence': {
        if (/bulk/i.test(v)) { setF('Self-identifies as bulk mail'); flags.push({ flag: 'Precedence: bulk — self-identified bulk mailing', severity: 'Medium' }); }
        break;
      }
      case 'require-recipient-valid-since': {
        setF('Reveals when the address was added to the campaign list');
        flags.push({ flag: 'Require-Recipient-Valid-Since header reveals campaign list membership', severity: 'Low' });
        break;
      }
      case 'message-id':
      case 'list-unsubscribe': {
        for (const tld of SUSPICIOUS_TLDS) {
          if (new RegExp(`\\.${tld}\\b`, 'i').test(v)) {
            setF(`Non-existent TLD .${tld}`);
            flags.push({ flag: `${h.key} references a non-existent TLD (.${tld})`, severity: 'Low' });
          }
        }
        break;
      }
      case 'x-ms-exchange-organization-authas': {
        if (/anonymous/i.test(v)) { setF('Anonymous submission to Exchange'); flags.push({ flag: 'X-MS-Exchange-Organization-AuthAs: Anonymous', severity: 'Medium' }); }
        break;
      }
      case 'x-sid-result': {
        if (/fail/i.test(v)) { setF('Microsoft Sender ID failure'); flags.push({ flag: 'X-SID-Result: FAIL (Microsoft Sender ID failure)', severity: 'Medium' }); }
        break;
      }
      case 'dkim-signature': {
        if (/a=rsa-sha1/i.test(v)) setF('Deprecated rsa-sha1 signature');
        break;
      }
      case 'authentication-results': {
        if (/(spf|dkim|dmarc)=fail/i.test(v)) setF('Reports an authentication failure');
        break;
      }
      case 'received': {
        for (const t of TRACKING_INFRA) {
          if (v.toLowerCase().includes(t.value)) { setF(t.note); flags.push({ flag: `Routing hop through ${t.value} — ${t.note}`, severity: 'Medium' }); }
        }
        break;
      }
      default:
        break;
    }
  });

  // From == To self-spoof (sextortion signature).
  const to = parseAddress(p.get('to'));
  if (from.email && to.email && from.email === to.email) {
    flags.push({ flag: 'From address is forged as the recipient’s own address (fake "your account is hacked" illusion)', severity: 'High' });
    ctx.selfSpoof = true;
  }

  // Missing / mass-BCC recipient.
  if (!p.has('to')) {
    flags.push({ flag: 'No To header — consistent with mass BCC distribution', severity: 'Low' });
  } else if (/undisclosed-recipients/i.test(p.get('to') || '')) {
    flags.push({ flag: 'To: undisclosed-recipients — mass BCC distribution', severity: 'Low' });
  }

  // X-Originating-IP vs last relay discrepancy.
  const xoip = (p.get('x-originating-ip') || '').replace(/[\[\]]/g, '').trim();
  if (xoip) {
    const recv = p.getAll('received').join(' ');
    const relayIps = recv.match(RE.ipv4) || [];
    if (relayIps.length && !relayIps.includes(xoip)) {
      flags.push({ flag: `X-Originating-IP (${xoip}) differs from the SMTP relay IP(s) — composed from a separate host`, severity: 'Medium' });
    }
  }

  // Zimbra shared-toolkit fingerprint.
  const ua = `${p.get('x-mailer') || ''} ${p.get('user-agent') || ''}`;
  if (/10\.1\.16_GA_4850/.test(ua) || /Zimbra 10\.1\.16/.test(ua)) {
    flags.push({ flag: 'Zimbra 10.1.16_GA_4850 web-client fingerprint (shared compromised-account tooling)', severity: 'Low' });
  }

  return { flags, flaggedKeys, from, replyTo, to };
}

function h_title(k) {
  return k.replace(/(^|-)([a-z])/g, (m, a, b) => a + b.toUpperCase());
}

// ---- content & identity analysis ----------------------------------------

function analyzeContent(p, ctx) {
  const flags = [];
  const techniques = [];
  const iocs = [];
  const text = p.combinedText || '';
  const html = p.bodyHtml || '';
  const subject = p.get('subject') || '';
  const lc = (text + ' ' + subject).toLowerCase();

  const addIoc = (type, value) => { if (value) iocs.push({ type, value }); };

  // URLs.
  const urls = uniq((text.match(RE.url) || []).concat(html.match(RE.url) || []));
  urls.forEach((u) => addIoc('URL', u.replace(/[).,]+$/, '')));

  // GCS bucket abuse.
  let m;
  const gcsRe = new RegExp(RE.gcsBucket.source, 'gi');
  const bucketNames = new Set();
  while ((m = gcsRe.exec(html + ' ' + text)) !== null) bucketNames.add(m[1]);
  if (bucketNames.size) {
    techniques.push('Google Cloud Storage bucket abuse for payload hosting');
    flags.push({ flag: `Credential-harvest payload hosted on storage.googleapis.com (bucket: ${Array.from(bucketNames).join(', ')}) — abuses Google’s domain reputation`, severity: 'Critical' });
    bucketNames.forEach((b) => addIoc('GCS Bucket', b));
  }

  // Tracking params.
  const foundParams = TRACKING_PARAMS.filter((pp) => new RegExp(`[?&#]${pp}=`, 'i').test(html + ' ' + text));
  if (foundParams.length >= 2) {
    techniques.push('Per-victim URL tracking parameters');
    flags.push({ flag: `Victim-tracking URL parameters present (${foundParams.join(', ')})`, severity: 'Medium' });
    const cid = (html + text).match(/[?&#]cid=([A-Za-z0-9]+)/i);
    if (cid) addIoc('Campaign ID', cid[1]);
  }

  // Crypto wallets.
  const wallets = [];
  for (const [type, re] of [['BTC', RE.btc], ['ETH', RE.eth], ['LTC', RE.ltc], ['XMR', RE.xmr]]) {
    const r = new RegExp(re.source, 'g');
    const found = uniq(text.match(r) || []);
    found.forEach((w) => { wallets.push({ type, w }); addIoc('Crypto Wallet', `${type}: ${w}`); });
  }
  if (wallets.length) {
    techniques.push('Cryptocurrency extortion / payment demand');
    flags.push({ flag: `Cryptocurrency wallet address embedded (${wallets.map((x) => x.type).join(', ')}) — direct financial-loss path`, severity: 'Critical' });
  }

  // Phone numbers.
  const phones = uniq((text.match(RE.phone) || []).map((x) => x.trim()));
  phones.slice(0, 12).forEach((ph) => addIoc('Phone', ph));

  // Body-embedded email reply channels.
  const fromAddr = parseAddress(p.get('from'));
  const bodyEmails = uniq((text.match(RE.email) || []).map((e) => e.toLowerCase()))
    .filter((e) => e !== fromAddr.email);
  bodyEmails.slice(0, 15).forEach((e) => addIoc('Email', e));
  const bodyFreemail = bodyEmails.filter((e) => FREEMAIL_DOMAINS.includes(e.split('@').pop()));
  if (bodyFreemail.length && (ctx.replyChannelMismatch || fromAddr.domain && !FREEMAIL_DOMAINS.includes(fromAddr.domain))) {
    flags.push({ flag: `Alternate contact channel buried in the body (${bodyFreemail.join(', ')}) — redirects the conversation off the original domain`, severity: 'High' });
    techniques.push('Reply-channel redirection to attacker-controlled webmail');
  }

  // Unicode look-alike substitution.
  if (/[Ѐ-ӿ]/.test(text + subject) && /[A-Za-z]/.test(text + subject)) {
    const cy = uniq(((text + subject).match(/[Ѐ-ӿ]/g) || [])).slice(0, 10);
    techniques.push('Cyrillic homoglyph substitution (filter evasion)');
    flags.push({ flag: `Cyrillic look-alike characters mixed into Latin text (${cy.join(' ')}) — content-filter evasion`, severity: 'High' });
  }

  // HTML evasion: hidden / invisible text.
  if (html) {
    const hidden = /(font-size\s*:\s*0|display\s*:\s*none|visibility\s*:\s*hidden|color\s*:\s*#fff(fff)?|color\s*:\s*white|color\s*:\s*rgb\(\s*255\s*,\s*255\s*,\s*255)/i.test(html);
    if (hidden) {
      techniques.push('Hidden / invisible HTML text (Bayesian poisoning)');
      flags.push({ flag: 'Hidden or invisible HTML text detected (white-on-white / size-0 / display:none)', severity: 'High' });
    }
    // Invalid custom tags.
    const tagRe = new RegExp(RE.customTag.source, 'gi');
    const tags = new Set();
    while ((m = tagRe.exec(html)) !== null) {
      const t = m[1].toLowerCase();
      if (!KNOWN_HTML_TAGS.has(t)) tags.add(t);
    }
    if (tags.size) {
      techniques.push('Invalid custom HTML tags for parser confusion');
      flags.push({ flag: `Invalid custom HTML tag names used for parser confusion (e.g. <${Array.from(tags).slice(0, 3).join('>, <')}>)`, severity: 'Low' });
    }
  }

  // Bayesian junk token blocks.
  const junk = (text + html).match(RE.bayesianJunk);
  if (junk && junk.length) {
    techniques.push('Bayesian poisoning via junk token blocks');
    flags.push({ flag: `Junk token blocks for Bayesian poisoning (e.g. ${uniq(junk).slice(0, 3).join(', ')})`, severity: 'Low' });
  }

  // Registered-agent / Delaware LLC footer.
  if (REGISTERED_AGENT_HINTS.some((h) => lc.includes(h)) && /\b(llc|inc|ltd|corp)\b/i.test(lc)) {
    flags.push({ flag: 'Shared registered-agent / Delaware LLC footer address — common fraud-operator pattern', severity: 'Low' });
  }

  // PII solicitation.
  const piiHits = PII_SOLICITATION.filter((t) => lc.includes(t));
  if (piiHits.length >= 2) {
    techniques.push('PII solicitation');
    flags.push({ flag: `Solicits personal information (${piiHits.slice(0, 5).join(', ')})`, severity: 'High' });
  }

  // Tracking infra in body too.
  for (const t of TRACKING_INFRA) {
    if ((text + html).toLowerCase().includes(t.value)) addIoc('Domain', t.value);
  }

  return { flags, techniques: uniq(techniques), iocs, urls, wallets, phones };
}

// ---- category & lexical classification ----------------------------------

function classify(p, auth, content, ctx) {
  const subject = (p.get('subject') || '').toLowerCase();
  const text = (p.combinedText || '').toLowerCase();
  const all = subject + ' ' + text;
  const bodyLen = (p.combinedText || '').trim().length;
  const linkCount = content.urls.length;
  const score = { Phishing: 0, BEC: 0, Sextortion: 0, 'Advance Fee Fraud': 0 };
  const tags = [];

  const count = (terms) => terms.reduce((n, t) => n + (all.includes(t) ? 1 : 0), 0);

  const sext = count(SEXTORTION_TERMS);
  if (sext) { score.Sextortion += sext * 2; tags.push('sextortion'); }
  if (content.wallets.length) score.Sextortion += 1;
  if (ctx.selfSpoof) score.Sextortion += 2;

  const adv = count(ADVANCE_FEE_TERMS);
  if (adv) { score['Advance Fee Fraud'] += adv; tags.push('advance-fee'); }

  const ph = count(PHISHING_TERMS);
  if (ph) { score.Phishing += ph; tags.push('phishing'); }
  if (content.techniques.some((t) => /Cloud Storage/.test(t))) score.Phishing += 3;

  const becHit = BEC_PROBE_PHRASES.some(( pp) => all.includes(pp));
  const isProbe = bodyLen > 0 && bodyLen < 280 && linkCount === 0 && content.wallets.length === 0;
  if (becHit && isProbe) { score.BEC += 4; tags.push('bec', 'probe'); }
  else if (becHit) score.BEC += 1;

  // Pick winner.
  let category = 'Suspicious Email';
  let best = 0;
  for (const [k, v] of Object.entries(score)) {
    if (v > best) { best = v; category = k; }
  }
  if (best === 0) {
    // No strong lexical hit — fall back on structural signals.
    if (auth.scenario === 'all-fail') { category = 'Suspicious Email'; }
  }

  // Sub-labels.
  let subtitle = '';
  if (category === 'Advance Fee Fraud') {
    if (/sblc|standby letter|investment|funding|non-recourse/.test(all)) subtitle = 'Investment / SBLC advance-fee fraud';
    else subtitle = '419 / compensation / inheritance advance-fee fraud';
  } else if (category === 'Phishing') {
    subtitle = content.techniques.some((t) => /Cloud Storage/.test(t)) ? 'Cloud-storage credential phishing' : 'Credential / payment phishing';
  } else if (category === 'BEC') {
    subtitle = 'Business email compromise reconnaissance probe';
  } else if (category === 'Sextortion') {
    subtitle = 'Mass-template sextortion / extortion scam';
  } else {
    subtitle = 'Unclassified suspicious email';
  }

  // Impersonation detection.
  const fromDisplay = parseAddress(p.get('from')).display.toLowerCase();
  const impersonated = KNOWN_IMPERSONATED.filter((n) => all.includes(n) || fromDisplay.includes(n));

  return { category, subtitle, tags: uniq(tags), score, impersonated, isProbe };
}

// ---- campaign correlation ------------------------------------------------

function correlate(p) {
  const hay = p.raw.toLowerCase();
  const matches = [];
  for (const fp of CAMPAIGN_FINGERPRINTS) {
    let hits = 0;
    const matched = [];
    for (const ind of fp.indicators) {
      if (ind.kind === 'text' && hay.includes(ind.value.toLowerCase())) { hits++; matched.push(ind.value); }
      if (ind.kind === 'header') {
        const hv = (p.get(ind.name) || '').toLowerCase();
        if (hv.includes(ind.value.toLowerCase())) { hits++; matched.push(`${ind.name}: ${ind.value}`); }
      }
    }
    if (hits >= fp.minMatches) matches.push({ ...fp, hits, matched });
  }
  return matches;
}

// ---- recommendations -----------------------------------------------------

function buildRecommendations(category, auth, content, ctx, impersonated) {
  const recs = [];
  recs.push('Do not reply, click any link, open any attachment, or call any phone number contained in this email.');
  if (category === 'Sextortion') {
    recs.push('No actual compromise has occurred — this is a mass-distributed template scam. The "From: yourself" trick is header spoofing, not evidence your account was hacked.');
    recs.push('Do not pay the cryptocurrency demand. Delete and report the message.');
    recs.push('If a real password was quoted, change it everywhere it was reused and enable multi-factor authentication.');
  }
  if (category === 'BEC') {
    recs.push('Treat as a BEC reconnaissance probe. Do not respond — a reply confirms a live, monitored inbox and invites a follow-up payment-redirect request.');
    recs.push('Verify any payment or banking-change request through a separately-known phone number, never by replying to the email.');
  }
  if (category === 'Advance Fee Fraud') {
    recs.push('There is no fund, inheritance, compensation, or facility. The upfront fee is the entire scam; no money will ever be released to you.');
    recs.push('Do not send any personal information, identity documents, or payment.');
  }
  if (category === 'Phishing') {
    recs.push('Do not enter credentials on any linked page. The high-reputation host (e.g. Google Cloud Storage) is abuse, not legitimacy.');
    recs.push('If credentials were entered, change the affected password immediately and enable MFA.');
  }
  if (ctx.replyChannelMismatch) {
    recs.push('Reply-To points to a different domain than the sender — any reply would go to the attacker, not the apparent sender.');
  }
  if (impersonated.length) {
    recs.push(`This email impersonates a real person or institution (${impersonated.slice(0, 3).join(', ')}). Verify independently; the named party is not the actual sender.`);
  }
  if (auth.scenario === 'all-pass') {
    recs.push('Authentication passing does NOT make this safe — the sender controls the signing domain, abuses a legitimate ESP, or is sending from a compromised account.');
  }
  recs.push('Report the message to your email provider / security team and then delete it. Preserve the original headers if a formal report is needed.');
  return uniq(recs);
}

// ---- public: analyze -----------------------------------------------------

export function analyze(p) {
  const ctx = {};
  const auth = analyzeAuth(p);
  const headerRes = analyzeHeaders(p, auth, ctx);
  const content = analyzeContent(p, ctx);
  const cls = classify(p, auth, content, ctx);
  const campaigns = correlate(p);

  // Aggregate red flags.
  let redFlags = [...auth.flags, ...headerRes.flags, ...content.flags];
  if (cls.impersonated.length) {
    redFlags.push({ flag: `Impersonation of a real person/institution: ${cls.impersonated.slice(0, 3).join(', ')}`, severity: 'Critical' });
  }
  campaigns.forEach((c) => {
    redFlags.push({ flag: `Campaign correlation: shares indicators with ${c.label} (${c.matched.join(', ')})`, severity: 'High' });
  });
  // Dedup red flags by text.
  const seen = new Set();
  redFlags = redFlags.filter((f) => (seen.has(f.flag) ? false : seen.add(f.flag)));

  // Severity.
  let severity = redFlags.length ? maxSeverity(redFlags.map((f) => f.severity)) : 'Low';
  let elevationNote = '';
  const fraudCategory = ['Advance Fee Fraud', 'BEC', 'Phishing', 'Sextortion'].includes(cls.category);
  if (fraudCategory && SEVERITY_ORDER[severity] < SEVERITY_ORDER.High) {
    elevationNote = ` Although individual flags are only ${severity.toLowerCase()}-level, the combined pattern clearly indicates ${cls.category.toLowerCase()}, so overall severity is elevated to High.`;
    severity = 'High';
  }

  // Techniques.
  const techniques = uniq([
    ...content.techniques,
    auth.scenario === 'all-pass' ? 'Authentication-passing delivery (registered domain / ESP / compromised account)' : null,
    auth.scenario === 'spf-only' ? 'Misleading SPF pass on attacker-controlled domain' : null,
    cls.impersonated.length ? 'Real-person / brand impersonation' : null,
    ctx.replyChannelMismatch ? 'Reply-channel misdirection' : null,
    ctx.selfSpoof ? 'Self-addressed From spoofing' : null,
  ].filter(Boolean));

  // IOCs — add structural ones.
  const iocs = [...content.iocs];
  const from = headerRes.from;
  if (from.email) iocs.push({ type: 'Email', value: from.email });
  if (from.domain) iocs.push({ type: 'Domain', value: from.domain });
  if (headerRes.replyTo.email) iocs.push({ type: 'Email', value: headerRes.replyTo.email });
  const recvIps = uniq(p.getAll('received').join(' ').match(RE.ipv4) || []);
  recvIps.slice(0, 10).forEach((ip) => iocs.push({ type: 'IP', value: ip }));
  const xoip = (p.get('x-originating-ip') || '').replace(/[\[\]]/g, '').trim();
  if (xoip) iocs.push({ type: 'IP', value: xoip });
  cls.impersonated.forEach((n) => iocs.push({ type: 'Person', value: n }));
  // Dedup IOCs.
  const iocSeen = new Set();
  const iocsFinal = iocs.filter((x) => {
    const key = `${x.type}|${x.value}`;
    return iocSeen.has(key) ? false : iocSeen.add(key);
  });

  // emailHeaders[]
  const emailHeaders = p.headers.map((h, i) => ({
    key: h.key,
    value: h.value,
    flagged: headerRes.flaggedKeys.has(i),
    reason: headerRes.flaggedKeys.get(i) || '',
  }));

  // Forensic analysis steps.
  const analysisSteps = buildAnalysisSteps(p, auth, headerRes, content, cls, campaigns);

  // Narrative summary.
  const subject = p.get('subject') || '(no subject)';
  const dateRaw = p.get('date');
  let dateIso = new Date().toISOString().slice(0, 10);
  if (dateRaw) { const d = new Date(dateRaw); if (!isNaN(d)) dateIso = d.toISOString().slice(0, 10); }

  const critCount = redFlags.filter((f) => f.severity === 'Critical').length;
  const highCount = redFlags.filter((f) => f.severity === 'High').length;
  const verdict = `${severity} — ${cls.category}`;
  const tldr = buildTldr(cls, severity, content, ctx);
  const summary =
    `This message ("${subject}") is assessed as ${severity.toLowerCase()}-severity ${cls.category} (${cls.subtitle}). ` +
    `Authentication scenario: ${describeScenario(auth.scenario)}. ` +
    `${redFlags.length} indicator${redFlags.length === 1 ? '' : 's'} were raised` +
    `${critCount ? `, including ${critCount} critical` : ''}${highCount ? `${critCount ? ' and' : ', including'} ${highCount} high-severity` : ''}. ` +
    `${campaigns.length ? `It shares indicators with a previously-analysed campaign. ` : ''}` +
    `${elevationNote}`.trim();

  const title = `${cls.category}: ${subject}`.slice(0, 120);

  return {
    id: `${slugify(subject)}-${dateIso}`,
    title,
    subtitle: cls.subtitle,
    date: dateIso,
    severity,
    category: cls.category,
    tags: cls.tags,
    summary,
    verdict,
    tldr,
    emailHeaders,
    redFlags,
    analysis: analysisSteps,
    recommendations: buildRecommendations(cls.category, auth, content, ctx, cls.impersonated),
    techniques,
    iocs: iocsFinal,
    _meta: { auth, campaigns, attachments: p.attachments, scenario: auth.scenario },
  };
}

function describeScenario(s) {
  return {
    'all-fail': 'all authentication failing/absent (easy to flag)',
    'spf-only': 'SPF pass only — a misleading pass on an attacker-controlled domain',
    'all-pass': 'all authentication passing — provides zero legitimacy signal here',
    'mixed': 'mixed results',
  }[s] || s;
}

function buildTldr(cls, severity, content, ctx) {
  if (cls.category === 'Sextortion') return 'Mass-template extortion scam — no real compromise; do not pay.';
  if (cls.category === 'BEC') return 'Likely BEC probe testing a live inbox — do not reply.';
  if (cls.category === 'Advance Fee Fraud') return 'Advance-fee fraud — the "fund" does not exist; the upfront fee is the scam.';
  if (cls.category === 'Phishing') return 'Credential/payment phishing — do not click or enter any login details.';
  return `${severity}-severity suspicious email — treat as hostile.`;
}

function buildAnalysisSteps(p, auth, headerRes, content, cls, campaigns) {
  const steps = [];

  // 1. Header inspection.
  const flagged = p.headers.filter((h, i) => headerRes.flaggedKeys.has(i));
  steps.push({
    step: '1. Email Header Inspection',
    content: flagged.length
      ? `${flagged.length} header${flagged.length === 1 ? '' : 's'} contribute to the threat assessment. Key fields: From "${headerRes.from.display || headerRes.from.email}" <${headerRes.from.email}>${headerRes.replyTo.email ? `, Reply-To <${headerRes.replyTo.email}>` : ''}.`
      : 'No individual header was independently flagged, but absence of negative header signals is not by itself a clean bill of health.',
    codeBlock: flagged.length ? {
      language: 'text', title: 'Flagged headers',
      code: flagged.map((h) => `${h.key}: ${h.value}`).join('\n'),
    } : undefined,
  });

  // 2. Authentication.
  steps.push({
    step: '2. Authentication Evaluation (SPF / DKIM / DMARC)',
    content: auth.notes.join('\n\n'),
    codeBlock: {
      language: 'text', title: 'Authentication results',
      code: [
        `SPF   : ${auth.spf || 'none'}${auth.spfDomain ? `  (smtp.mailfrom=${auth.spfDomain})` : ''}`,
        `DKIM  : ${auth.dkim || 'none'}${auth.dkimDomain ? `  (d=${auth.dkimDomain})` : ''}${auth.dkimAlg ? `  [${auth.dkimAlg}]` : ''}`,
        `DMARC : ${auth.dmarc || 'none'}`,
        `Scenario: ${auth.scenario}`,
      ].join('\n'),
    },
  });

  // 3. Routing.
  const recv = p.getAll('received');
  steps.push({
    step: '3. Routing & Infrastructure Analysis',
    content: recv.length
      ? `The message traversed ${recv.length} Received hop${recv.length === 1 ? '' : 's'}. Review them for falsified hostnames, third-party tracking infrastructure, and bulk-ESP relays that should not appear for a claimed personal/corporate sender.`
      : 'No Received headers were present (common when only the visible headers were pasted).',
    codeBlock: recv.length ? {
      language: 'text', title: 'Received chain (top = most recent)',
      code: recv.slice(0, 8).map((r, i) => `[${i}] ${r}`).join('\n\n'),
    } : undefined,
  });

  // 4. Content.
  const cbits = [];
  if (content.urls.length) cbits.push(`${content.urls.length} URL(s) extracted`);
  if (content.wallets.length) cbits.push(`${content.wallets.length} crypto wallet(s)`);
  if (content.phones.length) cbits.push(`${content.phones.length} phone number(s)`);
  steps.push({
    step: '4. Content & Evasion Analysis',
    content: (content.techniques.length
      ? `Detected techniques: ${content.techniques.join('; ')}.`
      : 'No specific evasion techniques were detected in the body.') +
      (cbits.length ? ` Extracted: ${cbits.join(', ')}.` : ''),
    codeBlock: content.urls.length ? {
      language: 'text', title: 'Extracted URLs', code: content.urls.slice(0, 20).join('\n'),
    } : undefined,
  });

  // 5. Identity & reply-channel.
  steps.push({
    step: '5. Identity & Reply-Channel Analysis',
    content:
      `Display name: "${headerRes.from.display || '(none)'}" on domain ${headerRes.from.domain || '(unknown)'}. ` +
      (headerRes.replyTo.email
        ? `Reply-To is <${headerRes.replyTo.email}>${registrableDomain(headerRes.replyTo.domain) !== registrableDomain(headerRes.from.domain) ? ' — which does NOT match the sender domain (reply-channel misdirection).' : '.'} `
        : 'No Reply-To override. ') +
      (cls.impersonated.length ? `Claimed identity matches a real person/institution: ${cls.impersonated.join(', ')}.` : 'No known real-person impersonation matched.'),
  });

  // 6. Campaign correlation.
  steps.push({
    step: '6. Cross-Case Campaign Correlation',
    content: campaigns.length
      ? campaigns.map((c) => `Shares indicators with ${c.label}: matched ${c.matched.join(', ')}. ${c.description}`).join('\n\n')
      : 'No correlation with the known reference campaigns was found.',
  });

  return steps;
}

export { parseAddress, registrableDomain };
