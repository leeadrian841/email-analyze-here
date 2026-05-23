// patterns.js — detection-pattern constants, keyword libraries, and known
// campaign fingerprints distilled from the analyst knowledge base (CLAUDE.md).

export const SEVERITY_ORDER = { Critical: 4, High: 3, Medium: 2, Low: 1 };

export const VALID_TLDS_SAMPLE = null; // we detect *suspicious* TLDs heuristically below

// TLDs referenced as non-existent / suspicious in the knowledge base.
export const SUSPICIOUS_TLDS = ['nuo', 'syk'];

// Ukrainian commercial second-level domain frequently abused.
export const SUSPICIOUS_DOMAIN_SUFFIXES = ['.biz.ua'];

// Known third-party tracking / routing infrastructure.
export const TRACKING_INFRA = [
  { value: 'efianalytics.com', note: 'Known third-party tracking infrastructure hop' },
  { value: '216.244.76.116', note: 'efianalytics.com tracking IP' },
];

// URL fragment / query tracking params seen in GCS phishing campaigns.
export const TRACKING_PARAMS = ['cid', 'pid', 'uid', 'vid', 'lid', 'ofid'];

// Personal / regional ISP domains that legitimate corporate execs do not use.
export const PERSONAL_ISP_DOMAINS = [
  'rcn.com', 'sccoast.net', 'gci.net', 'fibertel.com.ar', 'comcast.net',
  'verizon.net', 'cox.net', 'att.net', 'sbcglobal.net', 'charter.net',
  'optonline.net', 'earthlink.net', 'juno.com', 'aol.com',
];

export const FREEMAIL_DOMAINS = [
  'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'live.com',
  'protonmail.com', 'proton.me', 'gmx.com', 'mail.com', 'yandex.com',
  'icloud.com', 'aol.com',
];

// ESPs that legitimately pass auth but are abused for bulk fraud.
export const BULK_ESPS = [
  'getresponse.com', 'gr-mail', 'mailchimp', 'sendinblue', 'sendgrid.net',
  'sailthru', 'amazonses', 'mailgun', 'mandrill', 'constantcontact',
];

// Standard, valid Content-Transfer-Encoding values.
export const VALID_CTE = new Set(['7bit', '8bit', 'binary', 'quoted-printable', 'base64']);

// Shared-agent / Delaware LLC registered-agent address fragments.
export const REGISTERED_AGENT_HINTS = [
  '16192 coastal highway', 'lewes', ' de ', 'delaware',
];

// Real executives / institutions impersonated in the reference dataset.
export const KNOWN_IMPERSONATED = [
  'emily portney', 'charles w. scharf', 'charles scharf', 'amol dalvi',
  'bny mellon', 'wells fargo', 'hsbc', 'bnp paribas', 'citibank',
  'interpol', 'imf', 'united nations', 'un compensation', 'bny',
];

// Sextortion lexicon.
export const SEXTORTION_TERMS = [
  'pegasus', 'rat installed', 'recorded you', 'webcam', 'webmail',
  'spyware', 'malware on your', 'i have access to your', 'your password is',
  'compromised your device', 'filmed you', 'satisfying yourself',
  'adult', 'pornographic', 'embarrassing video', 'all your contacts',
];

// Advance-fee / 419 lexicon.
export const ADVANCE_FEE_TERMS = [
  'non-recourse', 'no repayment necessary', 'sblc', 'standby letter of credit',
  'next of kin', 'next-of-kin', 'inheritance', 'beneficiary', 'unclaimed',
  'compensation', 'atm card', 'fund release', 'transfer of', 'overdue',
  'consignment', 'diplomatic', 'deceased', 'late mr', 'late mrs',
  'business proposal', 'mutual benefit', 'confidential', 'reconfirm your',
  'guestbook', 'divert your fund', 'written agreement will protect',
];

// BEC probe phrases (single-line, payload-free).
export const BEC_PROBE_PHRASES = [
  'are you there', 'are you available', 'is this', 'quick question',
  'need your help', 'do you have a minute', 'are you at your desk',
  'can you help me with something', 'are you busy',
];

// Phishing / urgency CTA lexicon.
export const PHISHING_TERMS = [
  'verify your account', 'confirm your', 'failure notice', 'storage capacity',
  'payment failed', 'update your payment', 'suspended', 'click here',
  'login to', 'sign in to', 'reactivate', 'unusual activity', 'mailbox full',
  'quota exceeded', 'validate', 'unlock your account',
];

export const PII_SOLICITATION = [
  'full name', 'home address', 'phone number', 'occupation', 'date of birth',
  'next of kin', 'bank details', 'account number', 'copy of your id',
  'passport', 'driver', 'social security',
];

// Known campaign fingerprints — match new uploads against prior cases.
export const CAMPAIGN_FINGERPRINTS = [
  {
    id: 'gcs-bucket-actor',
    label: 'GCS-bucket phishing actor (Cases 1, 4, 5)',
    description:
      'Shared threat actor behind the fake cloud-storage payment phishing campaigns. ' +
      'Correlation indicators: campaign id cid=533743, an efianalytics.com routing hop, ' +
      'and X-Originating-IP 217.18.210.147.',
    indicators: [
      { kind: 'text', value: 'cid=533743' },
      { kind: 'text', value: 'efianalytics.com' },
      { kind: 'header', name: 'x-originating-ip', value: '217.18.210.147' },
    ],
    minMatches: 1,
  },
  {
    id: 'zimbra-vendor',
    label: 'Zimbra 10.1.16_GA_4850 toolkit (Cases 2, 7, 9)',
    description:
      'Compromised-account cases sharing the Zimbra 10.1.16_GA_4850 web-client fingerprint — ' +
      'possibly shared tooling or a shared credential vendor.',
    indicators: [
      { kind: 'text', value: '10.1.16_GA_4850' },
      { kind: 'text', value: 'Zimbra 10.1.16' },
    ],
    minMatches: 1,
  },
];

// ---- Regex library -------------------------------------------------------

export const RE = {
  url: /\b((?:https?:\/\/|www\.)[^\s"'<>()]+)/gi,
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  ipv4: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
  gcsBucket: /storage\.googleapis\.com\/([A-Za-z0-9._-]+)\//gi,
  btc: /\b(?:bc1[a-z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g,
  eth: /\b0x[a-fA-F0-9]{40}\b/g,
  ltc: /\b(?:ltc1[a-z0-9]{25,90}|[LM3][a-km-zA-HJ-NP-Z1-9]{26,33})\b/g,
  xmr: /\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/g,
  phone: /(?:\+?1[-.\s]?)?\(?([2-9]\d{2})\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
  bayesianJunk: /\[\d+_\d+_[A-Za-z]+\]/g,
  // Invalid custom HTML tags (lowercase letters+digits, not a known tag) used for parser confusion.
  customTag: /<([a-z]{4,}[0-9][a-z0-9]*)\b[^>]*>/gi,
};

// A compact set of legitimate HTML tag names to exclude from "custom tag" hits.
export const KNOWN_HTML_TAGS = new Set([
  'html', 'head', 'body', 'div', 'span', 'table', 'thead', 'tbody', 'tfoot',
  'tr', 'td', 'th', 'p', 'a', 'img', 'br', 'hr', 'ul', 'ol', 'li', 'b', 'i',
  'u', 'strong', 'em', 'font', 'center', 'style', 'script', 'meta', 'link',
  'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote', 'pre', 'code', 'small',
  'sup', 'sub', 'title', 'form', 'input', 'button', 'label', 'section',
  'article', 'header', 'footer', 'nav', 'main', 'figure', 'figcaption',
]);
