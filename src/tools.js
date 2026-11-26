'use strict';
// Pro tools for Pulumi Stack & Policy Viewer:
//   1. auditStack: Offline Markdown stack secret-hygiene and config audit.
//   2. diffStacks: Compare two Pulumi.<env>.yaml stack files in Markdown.
//   3. exportConfigDoc: Non-destructive Markdown and CSV redacted stack configuration inventory.
const vscode = require('vscode');
const fs = require('fs');
const path = require('path');
const {
  parsePulumi,
  buildAuditMarkdown,
  buildDiffMarkdown,
  buildRedactedConfigCsv,
  buildRedactedConfigMarkdown,
} = require('./pulumi');

const PULUMI_RE = /^Pulumi(\.[^.]+)?\.ya?ml$/i;

function uniquePath(targetPath) {
  if (!fs.existsSync(targetPath)) return targetPath;
  const dir = path.dirname(targetPath);
  const ext = path.extname(targetPath);
  const base = path.basename(targetPath, ext);
  for (let i = 1; i < 10000; i += 1) {
    const cand = path.join(dir, `${base}-${i}${ext}`);
    if (!fs.existsSync(cand)) return cand;
  }
  return path.join(dir, `${base}-${Date.now()}${ext}`);
}

async function resolveTargetUri(uri, provider, openLabel = 'Select Pulumi project or stack file') {
  if (uri && uri.scheme) return uri;
  if (provider && provider.active && provider.active.uri) return provider.active.uri;
  const ed = vscode.window.activeTextEditor;
  if (ed && ed.document && PULUMI_RE.test(path.basename(ed.document.uri.fsPath || ed.document.uri.path))) {
    return ed.document.uri;
  }
  const picked = await vscode.window.showOpenDialog({
    canSelectMany: false,
    openLabel,
  });
  return picked && picked[0] ? picked[0] : null;
}

function listPulumiFilesInDir(dirPath, maxDepth = 4) {
  const out = [];
  function walk(dir, depth) {
    if (depth > maxDepth) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (e) { return; }
    for (const e of entries) {
      if (e.name === 'node_modules' || e.name === '.git') continue;
      const full = path.join(dir, e.name);
      if (e.isFile() && PULUMI_RE.test(e.name)) out.push(full);
      else if (e.isDirectory() && depth < maxDepth) walk(full, depth + 1);
    }
  }
  walk(dirPath, 0);
  return out.sort();
}

function createTools({ provider, pro, reach }) {
  async function auditStack(uri, opts = {}) {
    if (!(await pro.allowed('auditStack', opts))) return undefined;
    const target = await resolveTargetUri(uri, provider);
    if (!target) return undefined;

    const targetPath = target.fsPath;
    const isDir = target.scheme === 'file' && fs.existsSync(targetPath) && fs.statSync(targetPath).isDirectory();
    const files = isDir ? listPulumiFilesInDir(targetPath) : [targetPath];
    if (!files.length) {
      vscode.window.showInformationMessage('No Pulumi YAML files were found in this folder.');
      return undefined;
    }

    const entries = [];
    for (const f of files) {
      const buf = f === targetPath && target.scheme !== 'file'
        ? Buffer.from(await vscode.workspace.fs.readFile(target))
        : fs.readFileSync(f);
      const label = isDir ? path.relative(targetPath, f) : path.basename(f);
      entries.push({ fileName: label, parsed: parsePulumi(buf, label) });
    }
    const md = buildAuditMarkdown(entries);
    const doc = await vscode.workspace.openTextDocument({ content: md, language: 'markdown' });
    await vscode.window.showTextDocument(doc, { preview: false });
    await pro.produced('auditStack');
    if (reach) reach.refresh();
    return { files: files.length, markdown: md };
  }

  async function diffStacks(uri, opts = {}) {
    if (!(await pro.allowed('diffStacks', opts))) return undefined;
    const left = await resolveTargetUri(uri, provider, 'Select baseline Pulumi stack file');
    if (!left) return undefined;

    let right = opts.compareUri || null;
    if (!right) {
      const picked = await vscode.window.showOpenDialog({
        canSelectMany: false,
        openLabel: 'Select second Pulumi stack file to compare',
      });
      right = picked && picked[0] ? picked[0] : null;
    }
    if (!right) return undefined;

    const leftBuf = Buffer.from(await vscode.workspace.fs.readFile(left));
    const rightBuf = Buffer.from(await vscode.workspace.fs.readFile(right));
    const leftName = path.basename(left.fsPath || left.path);
    const rightName = path.basename(right.fsPath || right.path);
    const md = buildDiffMarkdown(
      leftName,
      parsePulumi(leftBuf, leftName),
      rightName,
      parsePulumi(rightBuf, rightName),
    );
    const doc = await vscode.workspace.openTextDocument({ content: md, language: 'markdown' });
    await vscode.window.showTextDocument(doc, { preview: false });
    await pro.produced('diffStacks');
    if (reach) reach.refresh();
    return { markdown: md };
  }

  async function exportConfigDoc(uri, opts = {}) {
    if (!(await pro.allowed('exportConfigDoc', opts))) return undefined;
    const target = await resolveTargetUri(uri, provider);
    if (!target) return undefined;

    const targetPath = target.fsPath;
    const bytes = await vscode.workspace.fs.readFile(target);
    const baseName = path.basename(targetPath);
    const parsed = parsePulumi(Buffer.from(bytes), baseName);
    const stemRaw = baseName.replace(/[^a-zA-Z0-9._-]+/g, '_') || 'pulumi';
    const defaultOut = uniquePath(path.join(path.dirname(targetPath), `${stemRaw}.config.md`));
    const saveUri = opts.outPath
      ? vscode.Uri.file(uniquePath(opts.outPath))
      : await vscode.window.showSaveDialog({
        defaultUri: vscode.Uri.file(defaultOut),
        filters: { 'Markdown Config Inventory': ['md'] },
        saveLabel: 'Save redacted Pulumi config Markdown and CSV',
      });
    if (!saveUri) return undefined;

    const mdPath = uniquePath(saveUri.fsPath);
    const dir = path.dirname(mdPath);
    const stem = path.basename(mdPath, '.md').replace(/\.config$/i, '');
    const csvPath = uniquePath(path.join(dir, `${stem}.config.csv`));

    fs.writeFileSync(mdPath, buildRedactedConfigMarkdown(parsed, baseName), 'utf8');
    fs.writeFileSync(csvPath, buildRedactedConfigCsv(parsed), 'utf8');

    const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(mdPath));
    await vscode.window.showTextDocument(doc, { preview: false });
    await pro.produced('exportConfigDoc');
    if (reach) reach.refresh();
    return { files: [mdPath, csvPath], rows: parsed.stats.rowCount };
  }

  return { auditStack, diffStacks, exportConfigDoc };
}

module.exports = { createTools, uniquePath, listPulumiFilesInDir };
