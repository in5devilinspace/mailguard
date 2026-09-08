import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  analyzeHeaders,
  parseAddress,
  parseAuthResults,
  parseDkimSignature,
  parseHeaderBlock,
  parseReceived,
  parseRfc5322Date,
} from '../src/headers.ts';
import type { Finding } from '../src/types.ts';
import { HeadersInputError } from '../src/types.ts';
import { readEml } from './helpers.ts';

const byId = (findings: Finding[], id: string) => findings.filter((f) => f.id === id);

test('parseHeaderBlock handles CRLF, LF, unfolding, the body boundary and a leading From line', () => {
  const crlf = parseHeaderBlock('Subject: one\r\n two\r\nX-Test: a\r\n\r\nSubject: body\r\n');
  assert.deepEqual(crlf, [{ name: 'Subject', value: 'one two' }, { name: 'X-Test', value: 'a' }]);
  const lf = parseHeaderBlock('Subject: one\n\ttwo\nX-Test: a');
  assert.deepEqual(lf, [{ name: 'Subject', value: 'one two' }, { name: 'X-Test', value: 'a' }]);
  const mbox = parseHeaderBlock(readEml('headers-only.txt'));
  assert.equal(mbox[0]?.name, 'Received');
  assert.equal(mbox.length, 5);
  assert.throws(() => parseHeaderBlock(''), HeadersInputError);
  assert.throws(() => parseHeaderBlock('   \n\n'), HeadersInputError);
  assert.throws(() => parseHeaderBlock('no colon here\n'), HeadersInputError);
});

test('parseRfc5322Date covers comments, obsolete zones, missing seconds, two-digit years and garbage', () => {
  const base = Date.UTC(2025, 6, 1, 10, 0, 0);
  assert.equal(parseRfc5322Date('Tue, 1 Jul 2025 10:00:00 +0000'), base);
  assert.equal(parseRfc5322Date('Tue, 1 Jul 2025 03:00:00 -0700 (PDT)'), base);
  assert.equal(parseRfc5322Date('1 Jul 2025 10:00:00 GMT'), base);
  assert.equal(parseRfc5322Date('Tue, 1 Jul 2025 06:00:00 EDT'), base);
  assert.equal(parseRfc5322Date('Tue, 1 Jul 2025 10:00 +0000'), base);
  assert.equal(parseRfc5322Date('Tue, 1 Jul 25 10:00:00 +0000'), base);
  assert.equal(parseRfc5322Date('Tue, 01 Jul 2025 12:00:00 +0200'), base);
  assert.equal(parseRfc5322Date('Tue, 32 Foo 2025 10:00:05 +0000'), null);
  assert.equal(parseRfc5322Date('yesterday'), null);
  assert.equal(parseRfc5322Date(''), null);
  assert.equal(parseRfc5322Date('Tue, 31 Jun 2025 10:00:00 +0000'), null);
});

test('parseReceived splits Postfix, Gmail and Exchange shaped clauses', () => {
  const postfix = parseReceived('from mail.example.com (mail.example.com [192.0.2.10]) by mx.example.net (Postfix) with ESMTPS id 4XyZ12abc3 for <bob@example.net>; Tue, 1 Jul 2025 10:00:05 +0000 (UTC)');
  assert.equal(postfix.from, 'mail.example.com (mail.example.com [192.0.2.10])');
  assert.equal(postfix.by, 'mx.example.net (Postfix)');
  assert.equal(postfix.with, 'ESMTPS');
  assert.equal(postfix.id, '4XyZ12abc3');
  assert.equal(postfix.for, 'bob@example.net');
  assert.equal(postfix.date, 'Tue, 1 Jul 2025 10:00:05 +0000 (UTC)');
  const local = parseReceived('by app.example.com (Postfix, from userid 1000) id 2DeF78ghi9; Tue, 1 Jul 2025 10:00:00 +0000');
  assert.equal(local.from, null);
  assert.equal(local.by, 'app.example.com (Postfix, from userid 1000)');
  assert.equal(local.id, '2DeF78ghi9');
  const exchange = parseReceived('from mail.example.com (192.0.2.10) by BN8PR12MB3379.namprd12.prod.example.net (2001:db8:408:6a::12) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.8880.19 via Frontend Transport; Tue, 1 Jul 2025 10:00:05 +0000');
  assert.equal(exchange.from, 'mail.example.com (192.0.2.10)');
  assert.equal(exchange.by, 'BN8PR12MB3379.namprd12.prod.example.net (2001:db8:408:6a::12)');
  assert.match(exchange.with ?? '', /^Microsoft SMTP Server/);
  assert.equal(exchange.id, '15.20.8880.19');
  assert.equal(exchange.via, 'Frontend Transport');
  const noDate = parseReceived('from a.example.com by b.example.com with ESMTP');
  assert.equal(noDate.date, null);
  assert.equal(noDate.by, 'b.example.com');
});

test('parseAuthResults honors quoted strings, comments, versions and ptype.property pairs', () => {
  const parsed = parseAuthResults('mx.example.net 1; dkim/1=pass (2048-bit key; secure) header.d=example.com header.s=google; spf=pass (mx.example.net: domain designates 192.0.2.10 as permitted sender) smtp.mailfrom=bounce@example.com; dmarc=fail reason="No valid SPF; no valid DKIM" header.from=example.com');
  assert.equal(parsed.authservId, 'mx.example.net');
  assert.deepEqual(parsed.results.map((r) => [r.method, r.result]), [['dkim', 'pass'], ['spf', 'pass'], ['dmarc', 'fail']]);
  assert.deepEqual(parsed.results[0]?.properties, { 'header.d': 'example.com', 'header.s': 'google' });
  assert.equal(parsed.results[1]?.properties['smtp.mailfrom'], 'bounce@example.com');
  assert.equal(parsed.results[2]?.reason, 'No valid SPF; no valid DKIM');
  const none = parseAuthResults('mx.example.net; none');
  assert.equal(none.authservId, 'mx.example.net');
  assert.deepEqual(none.results, []);
  const exchange = parseAuthResults('spf=pass (sender IP is 192.0.2.10) smtp.mailfrom=example.com; dkim=pass (signature was verified) header.d=example.com;dmarc=pass action=none header.from=example.com;compauth=pass reason=100');
  assert.deepEqual(exchange.results.map((r) => r.method), ['spf', 'dkim', 'dmarc', 'compauth']);
  assert.equal(exchange.results[3]?.reason, '100');
  assert.equal(exchange.results[2]?.properties['action'], 'none');
});

test('parseDkimSignature and parseAddress', () => {
  const sig = parseDkimSignature('v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=google; h=From:To:Subject; bh=x; b=y');
  assert.deepEqual(sig, { d: 'example.com', s: 'google', a: 'rsa-sha256', c: 'relaxed/relaxed', fromSigned: true });
  assert.equal(parseDkimSignature('v=1; d=example.com; s=x; h=to:subject').fromSigned, false);
  assert.deepEqual(parseAddress('Alice Example <alice@example.com>'), { raw: 'Alice Example <alice@example.com>', address: 'alice@example.com', domain: 'example.com' });
  assert.deepEqual(parseAddress('alice@Example.COM'), { raw: 'alice@Example.COM', address: 'alice@Example.COM', domain: 'example.com' });
  assert.deepEqual(parseAddress('<>'), { raw: '<>', address: '', domain: null });
  assert.deepEqual(parseAddress(''), { raw: '', address: null, domain: null });
  assert.deepEqual(parseAddress('"Alice (Sales)" <alice@example.com> (comment)').domain, 'example.com');
});

test('gmail-pass.eml: four hops oldest first, delays 2/3/6, total 11, all pass, aligned', () => {
  const report = analyzeHeaders(readEml('gmail-pass.eml'));
  assert.equal(report.hops.length, 4);
  assert.deepEqual(report.hops.map((h) => h.delaySeconds), [null, 2, 3, 6]);
  assert.equal(report.totalTransitSeconds, 11);
  assert.equal(report.hops[0]?.by, 'app.example.com (Postfix, from userid 1000)');
  assert.equal(report.hops[3]?.by, 'inbox.example.net');
  assert.equal(report.hops[3]?.for, 'bob@example.net');
  assert.deepEqual(report.hops.flatMap((h) => h.flags), []);
  assert.deepEqual(report.verdict, { authservId: 'mx.example.net', spf: 'pass', dkim: 'pass', dmarc: 'pass' });
  assert.deepEqual(report.alignment.dkim, { domain: 'example.com', relaxed: true, strict: true });
  assert.deepEqual(report.alignment.spf, { domain: 'example.com', relaxed: true, strict: true });
  assert.equal(report.alignment.verdict, 'aligned');
  assert.deepEqual(report.from, { raw: 'Alice Example <alice@example.com>', address: 'alice@example.com', domain: 'example.com' });
  assert.equal(report.returnPath.domain, 'example.com');
  assert.deepEqual(report.dkimSignatures, [{ d: 'example.com', s: 'google', a: 'rsa-sha256', c: 'relaxed/relaxed', fromSigned: true }]);
  assert.equal(report.authResults.length, 1);
  assert.equal(report.findings.filter((f) => f.severity !== 'info').length, 0);
  assert.equal(report.findings.some((f) => f.message.includes('body')), false);
});

test('misaligned-dkim.eml: DKIM d= does not align with From, dmarc fail reported', () => {
  const report = analyzeHeaders(readEml('misaligned-dkim.eml'));
  assert.equal(report.alignment.dkim.domain, 'bulk-mailer.net');
  assert.equal(report.alignment.dkim.relaxed, false);
  assert.equal(report.alignment.spf.relaxed, false);
  assert.equal(report.alignment.verdict, 'misaligned');
  const warning = byId(report.findings, 'alignment.dkim')[0];
  assert.equal(warning?.severity, 'warning');
  assert.match(warning?.message ?? '', /example\.com/);
  assert.match(warning?.message ?? '', /bulk-mailer\.net/);
  assert.equal(byId(report.findings, 'alignment.spf').length, 1);
  const fail = byId(report.findings, 'auth.fail')[0];
  assert.equal(fail?.severity, 'error');
  assert.match(fail?.message ?? '', /dmarc=fail/);
  assert.equal(byId(report.findings, 'dkim-signature.from-unsigned').length, 1);
  assert.match(byId(report.findings, 'return-path.differs')[0]?.message ?? '', /bulk-mailer\.net/);
});

test('clock-skew, slow-hop and bad-date fixtures flag hops without throwing', () => {
  const skew = analyzeHeaders(readEml('clock-skew.eml'));
  assert.deepEqual(skew.hops.map((h) => h.delaySeconds), [null, -5, 25]);
  assert.deepEqual(skew.hops[1]?.flags, ['clock-skew']);
  assert.match(byId(skew.findings, 'received.clock-skew')[0]?.message ?? '', /clock/);
  assert.equal(skew.totalTransitSeconds, 20);

  const slow = analyzeHeaders(readEml('slow-hop.eml'));
  assert.deepEqual(slow.hops[1]?.flags, ['slow']);
  assert.equal(slow.hops[1]?.delaySeconds, 400);
  assert.equal(byId(slow.findings, 'received.slow').length, 1);

  const bad = analyzeHeaders(readEml('bad-date.eml'));
  assert.deepEqual(bad.hops.map((h) => h.delaySeconds), [null, null]);
  assert.deepEqual(bad.hops[1]?.flags, ['no-date']);
  assert.equal(bad.hops[1]?.timestamp, null);
  assert.equal(bad.totalTransitSeconds, null);
  assert.equal(byId(bad.findings, 'received.no-date').length, 1);
});

test('no-auth-results.eml: auth.none info, verdict none, null Return-Path handled', () => {
  const report = analyzeHeaders(readEml('no-auth-results.eml'));
  assert.deepEqual(report.verdict, { authservId: null, spf: 'none', dkim: 'none', dmarc: 'none' });
  assert.equal(byId(report.findings, 'auth.none')[0]?.message, 'no Authentication-Results header found');
  assert.equal(report.alignment.verdict, 'unknown');
  assert.deepEqual(report.returnPath, { raw: '<>', address: '', domain: null });
  assert.equal(report.hops[0]?.from, null);
});

test('two-authres.eml: verdict from the topmost header, both listed in order', () => {
  const report = analyzeHeaders(readEml('two-authres.eml'));
  assert.equal(report.verdict.authservId, 'inbox.example.net');
  assert.equal(report.verdict.spf, 'pass');
  assert.deepEqual(report.authResults.map((a) => a.authservId), ['inbox.example.net', 'relay.example.org']);
  assert.equal(report.authResults[1]?.results[0]?.result, 'softfail');
  assert.equal(byId(report.findings, 'auth.fail').length, 0);
});

test('exchange-style.eml parses Microsoft shaped Received and Authentication-Results', () => {
  const report = analyzeHeaders(readEml('exchange-style.eml'));
  assert.equal(report.hops.length, 2);
  assert.equal(report.hops[0]?.from, 'mail.example.com (192.0.2.10)');
  assert.match(report.hops[0]?.by ?? '', /^BN8PR12MB3379\.namprd12\.prod\.example\.net/);
  assert.match(report.hops[0]?.with ?? '', /^Microsoft SMTP Server/);
  assert.equal(report.hops[0]?.id, '15.20.8880.19');
  assert.equal(report.hops[1]?.with, 'HTTPS');
  assert.equal(report.hops[1]?.delaySeconds, 2);
  assert.equal(report.verdict.authservId, null);
  assert.deepEqual([report.verdict.spf, report.verdict.dkim, report.verdict.dmarc], ['pass', 'pass', 'pass']);
  assert.equal(report.alignment.spf.domain, 'example.com');
  assert.equal(report.alignment.verdict, 'aligned');
  assert.equal(report.dkimSignatures[0]?.fromSigned, true);
});
