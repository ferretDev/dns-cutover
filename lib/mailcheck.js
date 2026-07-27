/**
 * Provider-aware mail record analysis.
 * Detects Google Workspace / Microsoft 365 from signature records, then checks
 * that the provider's full expected record set exists — on the Cloudflare side
 * (the future truth), noting when a gap already existed in Enom.
 */

function has(recs, pred) {
  return recs.some(pred);
}

const isTxtAt = (name) => (r) => r.type === 'TXT' && r.name === name;
const txtContains = (frag) => (r) => r.type === 'TXT' && r.content.toLowerCase().includes(frag);
const cnameAt = (name) => (r) => r.type === 'CNAME' && r.name === name;

export function analyzeMail(enomRecs, cfRecs, domain) {
  const all = [...enomRecs, ...cfRecs];
  const mx = (recs) => recs.filter((r) => r.type === 'MX');

  // Common client typo: DMARC policy published at dmarc.domain (no underscore) —
  // syntactically valid, completely invisible to mail receivers.
  const misplaced = all.find((r) => r.type === 'TXT' && r.name === `dmarc.${domain}` && /v=dmarc1/i.test(r.content));
  const hasRealDmarc = has(cfRecs, isTxtAt(`_dmarc.${domain}`));
  const misplacedDmarc = misplaced && !hasRealDmarc ? { content: misplaced.content } : null;

  const isGoogle = has(all, (r) => r.type === 'MX' && /google(?:mail)?\.com$/.test(r.content));
  const isMicrosoft = has(all, (r) => r.type === 'MX' && r.content.endsWith('mail.protection.outlook.com'))
    || has(all, (r) => r.type === 'CNAME' && r.content === 'autodiscover.outlook.com')
    || has(all, txtContains('spf.protection.outlook.com'));

  const checks = [];
  const check = (label, pred, { required = true } = {}) => {
    checks.push({
      label,
      required,
      ok: has(cfRecs, pred),
      inEnom: has(enomRecs, pred),
    });
  };

  let provider = null;

  if (isGoogle) {
    provider = 'Google Workspace';
    check('Google MX', (r) => r.type === 'MX' && /google(?:mail)?\.com$/.test(r.content));
    check('SPF includes Google', txtContains('_spf.google.com'));
    check('DKIM (google._domainkey)', (r) => r.name === `google._domainkey.${domain}` && (r.type === 'TXT' || r.type === 'CNAME'));
    check('DMARC (_dmarc)', isTxtAt(`_dmarc.${domain}`));
    check('Site verification (google-site-verification)', txtContains('google-site-verification'), { required: false });
  } else if (isMicrosoft) {
    provider = 'Microsoft 365';
    check('M365 MX (mail.protection.outlook.com)', (r) => r.type === 'MX' && r.content.endsWith('mail.protection.outlook.com'));
    check('SPF includes Microsoft', txtContains('spf.protection.outlook.com'));
    check('Autodiscover CNAME', cnameAt(`autodiscover.${domain}`));
    check('DKIM selector1 CNAME', (r) => r.name === `selector1._domainkey.${domain}`);
    check('DKIM selector2 CNAME', (r) => r.name === `selector2._domainkey.${domain}`);
    check('DMARC (_dmarc)', isTxtAt(`_dmarc.${domain}`));
    check('Domain verification (MS=…)', (r) => r.type === 'TXT' && /^ms=ms\d+/i.test(r.content), { required: false });
    check('Teams/Skype SIP CNAMEs', (r) => r.type === 'CNAME' && (r.name === `sip.${domain}` || r.name === `lyncdiscover.${domain}`), { required: false });
    check('Intune enrollment CNAMEs', (r) => r.type === 'CNAME' && (r.name === `enterpriseregistration.${domain}` || r.name === `enterpriseenrollment.${domain}`), { required: false });
  } else if (has(all, (r) => r.type === 'MX')) {
    provider = 'Custom mail';
    check('MX present', (r) => r.type === 'MX');
    check('SPF (v=spf1)', txtContains('v=spf1'));
    check('DMARC (_dmarc)', isTxtAt(`_dmarc.${domain}`));
  }

  if (!provider) return { provider: null, checks: [], gaps: 0, misplacedDmarc };
  const gaps = checks.filter((c) => c.required && !c.ok).length;
  return { provider, checks, gaps, mxCount: mx(cfRecs).length, misplacedDmarc };
}
