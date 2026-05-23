// samples.js — synthetic demo emails. Everything here is fictional and uses
// reserved ranges only: RFC 2606 domains (example.com / .example), RFC 5737 IPs
// (192.0.2.x, 198.51.100.x, 203.0.113.x), the 555-01xx reserved phone block, and
// the BIP-173 documentation Bitcoin address. No real person, organisation,
// domain, IP, phone number, or wallet is referenced. Attack-technique strings
// (junk subdomains, tracking params, software fingerprints) are not PII.

const sextortion = [
  'Delivered-To: jordan.doe@example.com',
  'Received: from mail.hijacked-shop.example (mail.hijacked-shop.example [203.0.113.45])',
  '\tby mx.example.com with ESMTP id ABC123; Mon, 12 May 2025 09:14:02 -0400',
  'Authentication-Results: mx.example.com; spf=fail (sender IP is 203.0.113.45) smtp.mailfrom=jordan.doe@example.com;',
  '\tdkim=none; dmarc=fail (p=none) header.from=example.com',
  'X-MS-Exchange-Organization-AuthAs: Anonymous',
  'X-SID-Result: FAIL',
  'From: <jordan.doe@example.com>',
  'To: <jordan.doe@example.com>',
  'Subject: Your account has been compromised - 48 hours',
  'Date: Mon, 12 May 2025 09:14:02 -0400',
  'Content-Type: text/plain; charset="utf-8"',
  '',
  'Hello,',
  '',
  'I instаlled Pegasus spyware on your device and recorded you through your webmail camera.',
  'I have access to your contacts and will send the embarrassing video to everyone unless you pay.',
  '',
  'Send $1450 in Bitcoin to: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
  'You have 48 hours. Do not reply, the address is spoofed.',
].join('\n');

const gcsPhishing = [
  'Delivered-To: user@example.com',
  'Delivered-To: me@example.com',
  'Received: from o3.ptr.tracking-relay.example (o3.ptr.tracking-relay.example [203.0.113.116])',
  '\tby mx.example.com with ESMTPS id XYZ789; Tue, 6 May 2025 11:02:55 +0000',
  'Received: from deals-portal.biz.ua (unknown [198.51.100.7]) by relay.unrelated-host.example',
  'Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=bounce@deals-portal.biz.ua;',
  '\tdkim=pass header.d=Xd3nc.WVksarv.sb100014.deals-portal.biz.ua; dmarc=none',
  'X-Originating-IP: [192.0.2.147]',
  'X-Google-Sender-Delegation: AAreoGVrkJ',
  'DomainKey-Signature: a=rsa-sha1; q=dns; c=nofws;',
  'Content-Transfer-Encoding: amazonses',
  'Content-Length: 353',
  'Content-Length: 1245',
  'From: "Acme Billing" <billing@deals-portal.biz.ua>',
  'List-Unsubscribe: <mailto:unsub@track.nuo>',
  'Message-ID: <44213.9981@send.syk>',
  'To: user@example.com',
  'Subject: Failure Notice',
  'Date: Tue, 6 May 2025 11:02:55 +0000',
  'Content-Type: text/html; charset="utf-8"',
  '',
  '<html><body>',
  '<kxxpurb4dw>Your payment could not be processed. Verify your account to avoid suspension.</kxxpurb4dw>',
  '<a href="https://storage.googleapis.com/inv-9921-secure/login.html#cid=533743&pid=88&uid=4421">Review payment</a>',
  '<span style="color:#ffffff;font-size:0px">[14_14_Aa] lorem ipsum filler voter registration form text</span>',
  '</body></html>',
].join('\n');

const becProbe = [
  'Delivered-To: cfo@example.com',
  'Received: from mail.webmail-provider.example (mail.webmail-provider.example [198.51.100.60]) by mx.example.com; Wed, 7 May 2025 08:30:00 -0400',
  'Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=robert.lee.ceo@example.com;',
  '\tdkim=pass header.d=example.com; dmarc=pass header.from=example.com',
  'DKIM-Signature: v=1; a=rsa-sha1; d=example.com; s=mail; h=from:to:subject;',
  'From: "Robert Lee - CEO" <robert.lee.ceo@example.com>',
  'Reply-To: "Robert Lee" <robert.lee.ceo@example.com>',
  'To: cfo@example.com',
  'Subject: Quick question',
  'Disposition-Notification-To: robert.lee.ceo@example.com',
  'X-Mailer: Zimbra 10.1.16_GA_4850 (ZimbraWebClient)',
  'X-Vade-Verdict: clean',
  'Date: Wed, 7 May 2025 08:30:00 -0400',
  'Content-Type: text/plain; charset="utf-8"',
  '',
  'Are you available? I need your help with something. Let me know.',
].join('\n');

const advanceFee = [
  'Received: from mail.university.example (mail.university.example [192.0.2.10]) by mx.example.com; Thu, 8 May 2025 14:20:00 +0100',
  'Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=registry@university.example;',
  '\tdkim=pass header.d=university.example; dmarc=pass header.from=university.example',
  'From: "Mrs. Margaret Whitfield (Trans-Atlantic Reserve Bank)" <registry@university.example>',
  'Reply-To: <mwhitfield.funds@webmail.example>',
  'To: undisclosed-recipients:;',
  'Subject: ATTENTION: NEXT OF KIN INHERITANCE',
  'Date: Thu, 8 May 2025 14:20:00 +0100',
  'Content-Type: text/plain; charset="utf-8"',
  '',
  'Dear Friend,',
  '',
  'I am Mrs. Margaret Whitfield, former director of the Trans-Atlantic Reserve Bank. A deceased client left an unclaimed',
  'inheritance of $18,500,000 and your address was found in our business guestbook as next of kin.',
  '',
  'To release the fund I require your full name, home address, phone number and occupation.',
  'A written agreement will protect you. Contact me only at mwhitfield.funds@webmail.example or call +1 213 555 0142.',
].join('\n');

export const SAMPLES = [
  { id: 'sextortion', label: 'Sextortion (all auth fail)', raw: sextortion },
  { id: 'gcs', label: 'Cloud-storage phishing (SPF-only)', raw: gcsPhishing },
  { id: 'bec', label: 'BEC probe (all auth pass)', raw: becProbe },
  { id: 'advance-fee', label: '419 inheritance fraud', raw: advanceFee },
];
