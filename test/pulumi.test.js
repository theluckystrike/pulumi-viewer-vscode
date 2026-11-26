'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const {
  parsePulumi,
  buildAuditMarkdown,
  buildDiffMarkdown,
  buildRedactedConfigCsv,
  buildRedactedConfigMarkdown,
} = require('../src/pulumi');
const { PulumiViewModel } = require('../src/view');
const { editorHtml, csp } = require('../src/html');

test('parses sample Pulumi.dev.yaml with plaintext secret, hardcoded cloud token and missing secretsprovider', () => {
  const buf = fs.readFileSync(path.join(__dirname, '..', 'samples', 'Pulumi.dev.yaml'));
  const parsed = parsePulumi(buf, 'Pulumi.dev.yaml');
  assert.equal(parsed.kind, 'stack');
  assert.equal(parsed.stackName, 'dev');
  assert.equal(parsed.stats.configCount, 6);
  assert.equal(parsed.stats.secureCount, 1);
  const rules = new Set(parsed.findings.map((f) => f.rule));
  assert.ok(rules.has('plaintext-secret'));
  assert.ok(rules.has('hardcoded-cloud-token'));
  assert.ok(rules.has('missing-secretsprovider'));
  // Ensure plaintext secret and ciphertext are masked in row output
  assert.ok(!parsed.rows.some((r) => r.value.includes('dev_example_plaintext_pw')));
  assert.ok(!parsed.rows.some((r) => r.value.includes('AAABAC7')));
});

test('parses clean hardened Pulumi.prod.yaml with zero findings', () => {
  const buf = fs.readFileSync(path.join(__dirname, '..', 'samples', 'Pulumi.prod.yaml'));
  const parsed = parsePulumi(buf, 'Pulumi.prod.yaml');
  assert.equal(parsed.kind, 'stack');
  assert.equal(parsed.stackName, 'prod');
  assert.equal(parsed.stats.secureCount, 2);
  assert.equal(parsed.findings.length, 0);
});

test('parses Pulumi.yaml project file and flags unpinned plugin version and AWS token', () => {
  const fakeAws = 'AKIA' + '1234567890ABCDEF';
  const yaml = `
name: demo-infra
runtime:
  name: nodejs
  options:
    version: latest
backend:
  url: s3://my-pulumi-state
plugins:
  providers:
    - name: aws
      version: latest
config:
  app:keyId: ${fakeAws}
`;
  const parsed = parsePulumi(yaml, 'Pulumi.yaml');
  assert.equal(parsed.kind, 'project');
  assert.equal(parsed.meta.name, 'demo-infra');
  assert.equal(parsed.meta.backendUrl, 's3://my-pulumi-state');
  const rules = new Set(parsed.findings.map((f) => f.rule));
  assert.ok(rules.has('unpinned-version'));
  assert.ok(rules.has('hardcoded-cloud-token'));
});

test('PulumiViewModel filters by secure, plain, findings and text', () => {
  const buf = fs.readFileSync(path.join(__dirname, '..', 'samples', 'Pulumi.dev.yaml'));
  const parsed = parsePulumi(buf, 'Pulumi.dev.yaml');
  const vm = new PulumiViewModel(parsed, 'Pulumi.dev.yaml', buf.length);
  assert.equal(vm.setFilter({ text: '', kind: 'secure' }), 1);
  assert.equal(vm.setFilter({ text: '', kind: 'findings' }), 2);
  assert.equal(vm.setFilter({ text: 'us-east-1', kind: '' }), 1);
  const det = vm.detail(1);
  assert.ok(det && det.key === 'aws:region');
});

test('Pro report builders produce audit, stack diff, redacted CSV and Markdown inventory', () => {
  const dev = parsePulumi(fs.readFileSync(path.join(__dirname, '..', 'samples', 'Pulumi.dev.yaml')), 'Pulumi.dev.yaml');
  const prod = parsePulumi(fs.readFileSync(path.join(__dirname, '..', 'samples', 'Pulumi.prod.yaml')), 'Pulumi.prod.yaml');
  const audit = buildAuditMarkdown([{ fileName: 'Pulumi.dev.yaml', parsed: dev }]);
  assert.match(audit, /Pulumi Stack Secret-Hygiene & Config Audit/);
  assert.match(audit, /plaintext-secret/);
  const diff = buildDiffMarkdown('Pulumi.dev.yaml', dev, 'Pulumi.prod.yaml', prod);
  assert.match(diff, /Config Key Differences/);
  assert.match(diff, /Encryption changed/);
  const csv = buildRedactedConfigCsv(dev);
  assert.match(csv, /^scope,namespace,key,value_redacted,encrypted,status,line/);
  const md = buildRedactedConfigMarkdown(dev, 'Pulumi.dev.yaml');
  assert.match(md, /Configuration Keys \(Secrets Masked\)/);
});

test('editorHtml enforces strict CSP with nonce and no unsafe-inline', () => {
  const html = editorHtml({ cspSource: 'vscode-webview://test', script: 'v.js', styleUri: 'v.css', title: 'Pulumi.dev.yaml', nonce: 'pul123' });
  assert.match(html, /default-src 'none'/);
  assert.match(html, /script-src 'nonce-pul123'/);
  assert.doesNotMatch(csp('vscode-webview://test', 'pul123'), /unsafe-inline/);
});
