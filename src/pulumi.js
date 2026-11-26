'use strict';
// Offline Pulumi.yaml and Pulumi.<stack>.yaml parser, secret-hygiene analyzer and Pro report builders.
// Zero Pulumi CLI, shell, network or cloud calls.

const SECRET_KEY_RE = /(secret|password|passwd|pwd|token|api[_-]?key|private[_-]?key|client[_-]?secret|access[_-]?key|connection[_-]?string|conn[_-]?str|credential|auth[_-]?key|bearer|webhook)/i;
const CLOUD_TOKEN_PATTERNS = [
  { name: 'AWS Access Key ID', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'GCP API Key', re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { name: 'GitHub Token', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/ },
  { name: 'Azure SAS / SharedKey', re: /(?:SharedAccessKey|AccountKey)=[A-Za-z0-9+/=]{16,}/i },
  { name: 'PEM Private Key', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
];

function stripYamlComment(line) {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle) inDouble = !inDouble;
    else if (ch === '#' && !inSingle && !inDouble && (i === 0 || /\s/.test(line[i - 1]))) {
      return line.slice(0, i);
    }
  }
  return line;
}

function unquote(val) {
  const s = String(val || '').trim();
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    return s.slice(1, -1);
  }
  return s;
}

function maskValue(val) {
  const s = String(val || '');
  if (!s) return '***';
  if (s.length <= 6) return '***';
  return `${s.slice(0, 3)}***${s.slice(-2)}`;
}

function detectFileKind(fileName, topKeys) {
  const base = String(fileName || '').split(/[\\/]/).pop() || '';
  const m = base.match(/^Pulumi\.([^.]+)\.ya?ml$/i);
  if (m) return { kind: 'stack', stackName: m[1] };
  if (topKeys.has('config') && !topKeys.has('runtime')) return { kind: 'stack', stackName: 'stack' };
  return { kind: 'project', stackName: '' };
}

function parsePulumi(input, fileName = 'Pulumi.yaml') {
  const text = Buffer.isBuffer(input) ? input.toString('utf8') : String(input || '');
  const lines = text.split(/\r?\n/);

  const topKeys = new Set();
  const metadata = [];
  const configEntries = [];
  const plugins = [];
  const findings = [];
  const rows = [];
  let rowIndex = 0;

  let section = '';
  let sectionIndent = -1;
  let pendingConfig = null;
  let pendingPlugin = null;

  const metaMap = {
    name: '',
    description: '',
    runtime: '',
    runtimeOptions: {},
    backendUrl: '',
    secretsProvider: '',
    encryptionSalt: '',
  };

  const addFinding = (severity, category, rule, line, scope, message, rowRef = null) => {
    const f = { severity, category, rule, line, scope, message };
    findings.push(f);
    if (rowRef) {
      rowRef.findings.push(f);
      if (severity === 'error') rowRef.errorCount += 1;
      else rowRef.warningCount += 1;
    }
  };

  const pushRow = (entry) => {
    rowIndex += 1;
    const row = { index: rowIndex, errorCount: 0, warningCount: 0, findings: [], ...entry };
    rows.push(row);
    return row;
  };

  for (let i = 0; i < lines.length; i += 1) {
    const lineNo = i + 1;
    const rawLine = lines[i];
    const noComment = stripYamlComment(rawLine);
    if (!noComment.trim()) continue;

    const indent = noComment.match(/^(\s*)/)[1].length;
    const trimmed = noComment.trim();

    if (indent === 0) {
      pendingConfig = null;
      pendingPlugin = null;
      const kv = trimmed.match(/^([A-Za-z0-9_.-]+)\s*:\s*(.*)$/);
      if (!kv) continue;
      const key = kv[1];
      const val = unquote(kv[2]);
      topKeys.add(key);
      section = key;
      sectionIndent = 0;

      if (key === 'name') metaMap.name = val;
      else if (key === 'description') metaMap.description = val;
      else if (key === 'runtime' && val) metaMap.runtime = val;
      else if (key === 'secretsprovider') metaMap.secretsProvider = val;
      else if (key === 'encryptionsalt') metaMap.encryptionSalt = val;

      if (val && !['config', 'plugins', 'packages', 'backend', 'resources', 'outputs', 'variables'].includes(key)) {
        const displayVal = key === 'encryptionsalt' ? `${val.slice(0, 12)}... (encrypted salt)` : val;
        metadata.push({ key, value: displayVal, line: lineNo });
        const row = pushRow({
          line: lineNo,
          scope: 'metadata',
          namespace: 'project',
          key,
          value: displayVal,
          isSecure: key === 'encryptionsalt',
          status: key === 'encryptionsalt' ? 'ENCRYPTED' : 'META',
          raw: key === 'encryptionsalt' ? `${key}: [masked]` : trimmed,
          attrs: [
            { key: 'Scope', value: 'Metadata' },
            { key: 'Key', value: key },
            { key: 'Value', value: displayVal },
            { key: 'Line', value: String(lineNo) },
          ],
        });
        if (key === 'runtime' && /^(latest|\*)$/i.test(val)) {
          addFinding('warning', 'Versioning', 'unpinned-version', lineNo, 'runtime', `Runtime "${val}" is unpinned; pin a concrete runtime name and version.`, row);
        }
      }
      continue;
    }

    // Nested under runtime
    if (section === 'runtime') {
      const kv = trimmed.match(/^([A-Za-z0-9_.-]+)\s*:\s*(.*)$/);
      if (kv) {
        const k = kv[1];
        const v = unquote(kv[2]);
        if (k === 'name' && v) metaMap.runtime = v;
        else if (v) metaMap.runtimeOptions[k] = v;
        if (v) {
          metadata.push({ key: `runtime.${k}`, value: v, line: lineNo });
          const row = pushRow({
            line: lineNo,
            scope: 'metadata',
            namespace: 'runtime',
            key: `runtime.${k}`,
            value: v,
            isSecure: false,
            status: 'META',
            raw: trimmed,
            attrs: [
              { key: 'Scope', value: 'Runtime' },
              { key: 'Option', value: k },
              { key: 'Value', value: v },
              { key: 'Line', value: String(lineNo) },
            ],
          });
          if ((k === 'version' || k === 'toolchain') && /^(latest|\*)$/i.test(v)) {
            addFinding('warning', 'Versioning', 'unpinned-version', lineNo, `runtime.${k}`, `Runtime ${k} is set to "${v}"; pin a specific version.`, row);
          }
        }
      }
      continue;
    }

    // Nested under backend
    if (section === 'backend') {
      const kv = trimmed.match(/^([A-Za-z0-9_.-]+)\s*:\s*(.*)$/);
      if (kv && kv[1] === 'url') {
        const v = unquote(kv[2]);
        metaMap.backendUrl = v;
        metadata.push({ key: 'backend.url', value: v, line: lineNo });
        pushRow({
          line: lineNo,
          scope: 'metadata',
          namespace: 'backend',
          key: 'backend.url',
          value: v,
          isSecure: false,
          status: 'BACKEND',
          raw: trimmed,
          attrs: [
            { key: 'Scope', value: 'Backend' },
            { key: 'URL', value: v },
            { key: 'Line', value: String(lineNo) },
          ],
        });
      }
      continue;
    }

    // Nested under plugins or packages
    if (section === 'plugins' || section === 'packages') {
      const listMatch = trimmed.match(/^-\s*name\s*:\s*(.*)$/) || trimmed.match(/^([A-Za-z0-9_./@-]+)\s*:\s*(.*)$/);
      if (trimmed.startsWith('-')) {
        const kv = trimmed.replace(/^-\s*/, '').match(/^([A-Za-z0-9_.-]+)\s*:\s*(.*)$/);
        if (kv) {
          pendingPlugin = { name: kv[1] === 'name' ? unquote(kv[2]) : kv[1], version: kv[1] === 'version' ? unquote(kv[2]) : '', line: lineNo };
          plugins.push(pendingPlugin);
        }
      } else if (pendingPlugin && indent > sectionIndent + 2) {
        const kv = trimmed.match(/^([A-Za-z0-9_.-]+)\s*:\s*(.*)$/);
        if (kv && kv[1] === 'version') pendingPlugin.version = unquote(kv[2]);
      } else if (listMatch) {
        const pName = listMatch[1];
        const pVal = unquote(listMatch[2]);
        if (pName !== 'providers' && pName !== 'analyzers' && pName !== 'languages') {
          pendingPlugin = { name: pName, version: pVal, line: lineNo };
          plugins.push(pendingPlugin);
        }
      }
      continue;
    }

    // Nested under config
    if (section === 'config') {
      // Child of a pending config key (e.g. "secure: AAAB..." or nested object)
      if (pendingConfig && indent > pendingConfig.indent) {
        const subKv = trimmed.match(/^([A-Za-z0-9_.-]+)\s*:\s*(.*)$/);
        if (subKv && subKv[1] === 'secure') {
          pendingConfig.isSecure = true;
          pendingConfig.secureCipher = unquote(subKv[2]);
          pendingConfig.displayValue = '[secure: encrypted]';
          pendingConfig.row.isSecure = true;
          pendingConfig.row.status = 'SECURE';
          pendingConfig.row.value = '[secure: encrypted]';
          pendingConfig.row.raw = `${pendingConfig.fullKey}: { secure: [masked] }`;
          pendingConfig.row.attrs = [
            { key: 'Namespace', value: pendingConfig.namespace },
            { key: 'Config Key', value: pendingConfig.fullKey },
            { key: 'Value', value: '[secure: encrypted]' },
            { key: 'Encrypted', value: 'yes (Pulumi secure ciphertext)' },
            { key: 'Line', value: String(pendingConfig.line) },
          ];
        } else if (subKv && !pendingConfig.isSecure) {
          const subKey = subKv[1];
          const subVal = unquote(subKv[2]);
          if (subVal) {
            for (const pat of CLOUD_TOKEN_PATTERNS) {
              if (pat.re.test(subVal)) {
                addFinding('error', 'Secrets', 'hardcoded-cloud-token', lineNo, `${pendingConfig.fullKey}.${subKey}`, `Hardcoded ${pat.name} detected in config value; encrypt with "pulumi config set --secret".`, pendingConfig.row);
              }
            }
            if (SECRET_KEY_RE.test(subKey)) {
              addFinding('error', 'Secrets', 'plaintext-secret', lineNo, `${pendingConfig.fullKey}.${subKey}`, `Nested config key "${subKey}" looks like a secret stored in plaintext without a secure: wrapper.`, pendingConfig.row);
              pendingConfig.row.value = `${subKey}: ${maskValue(subVal)}`;
            }
          }
        }
        continue;
      }

      const kv = trimmed.match(/^"?([A-Za-z0-9_.:/-]+)"?\s*:\s*(.*)$/);
      if (!kv) continue;
      const fullKey = kv[1];
      const rawVal = kv[2].trim();
      const val = unquote(rawVal);
      const colonIdx = fullKey.indexOf(':');
      const namespace = colonIdx > 0 ? fullKey.slice(0, colonIdx) : 'default';
      const shortKey = colonIdx > 0 ? fullKey.slice(colonIdx + 1) : fullKey;

      const inlineSecure = /^\{\s*secure\s*:/i.test(rawVal);
      const isPlainSecret = !inlineSecure && val && SECRET_KEY_RE.test(fullKey);

      const entry = {
        line: lineNo,
        indent,
        namespace,
        shortKey,
        fullKey,
        rawValue: val,
        displayValue: inlineSecure ? '[secure: encrypted]' : (isPlainSecret ? maskValue(val) : (val || '(object)')),
        isSecure: inlineSecure,
        secureCipher: '',
        row: null,
      };

      const row = pushRow({
        line: lineNo,
        scope: 'config',
        namespace,
        key: fullKey,
        value: entry.displayValue,
        isSecure: inlineSecure,
        status: inlineSecure ? 'SECURE' : (isPlainSecret ? 'PLAINTEXT' : 'PLAIN'),
        raw: inlineSecure ? `${fullKey}: { secure: [masked] }` : (isPlainSecret ? `${fullKey}: ${maskValue(val)}` : trimmed),
        attrs: [
          { key: 'Namespace', value: namespace },
          { key: 'Config Key', value: fullKey },
          { key: 'Value', value: entry.displayValue },
          { key: 'Encrypted', value: inlineSecure ? 'yes (Pulumi secure ciphertext)' : 'no' },
          { key: 'Line', value: String(lineNo) },
        ],
      });
      entry.row = row;
      configEntries.push(entry);
      pendingConfig = entry;

      if (!inlineSecure && val) {
        let hitToken = false;
        for (const pat of CLOUD_TOKEN_PATTERNS) {
          if (pat.re.test(val)) {
            hitToken = true;
            addFinding('error', 'Secrets', 'hardcoded-cloud-token', lineNo, fullKey, `Hardcoded ${pat.name} detected in "${fullKey}"; rotate immediately and encrypt with "pulumi config set --secret".`, row);
            row.value = maskValue(val);
            row.raw = `${fullKey}: ${maskValue(val)}`;
            row.status = 'TOKEN';
          }
        }
        if (isPlainSecret && !hitToken) {
          addFinding('error', 'Secrets', 'plaintext-secret', lineNo, fullKey, `Key "${fullKey}" appears to hold a secret in plaintext instead of a Pulumi secure: block.`, row);
        }
      }
    }
  }

  // Evaluate plugins for unpinned versions
  for (const p of plugins) {
    const ver = p.version || '';
    const row = pushRow({
      line: p.line,
      scope: 'plugin',
      namespace: 'plugins',
      key: p.name,
      value: ver || '(unpinned)',
      isSecure: false,
      status: !ver || /^(latest|\*)$/i.test(ver) ? 'UNPINNED' : 'PINNED',
      raw: `${p.name}: ${ver || '(no version)'}`,
      attrs: [
        { key: 'Scope', value: 'Plugin / Package' },
        { key: 'Name', value: p.name },
        { key: 'Version', value: ver || '(unpinned)' },
        { key: 'Line', value: String(p.line) },
      ],
    });
    if (!ver || /^(latest|\*)$/i.test(ver)) {
      addFinding('warning', 'Versioning', 'unpinned-version', p.line, `plugin:${p.name}`, `Plugin or package "${p.name}" uses unpinned version "${ver || 'none'}"; pin an explicit semver version.`, row);
    }
  }

  const fileInfo = detectFileKind(fileName, topKeys);
  if (fileInfo.kind === 'stack' && !metaMap.secretsProvider && !metaMap.encryptionSalt) {
    addFinding('warning', 'Encryption', 'missing-secretsprovider', 1, 'stack', 'Stack file has neither secretsprovider nor encryptionsalt; configure a KMS or passphrase secrets provider.');
  }

  const secureCount = configEntries.filter((c) => c.isSecure).length;
  const plainCount = configEntries.length - secureCount;
  const findingErrors = findings.filter((f) => f.severity === 'error').length;
  const findingWarnings = findings.filter((f) => f.severity === 'warning').length;

  return {
    title: fileName,
    kind: fileInfo.kind,
    stackName: fileInfo.stackName,
    totalLines: lines.length,
    meta: metaMap,
    metadata,
    configEntries,
    plugins,
    rows,
    findings,
    stats: {
      rowCount: rows.length,
      configCount: configEntries.length,
      secureCount,
      plainCount,
      pluginCount: plugins.length,
      namespaceCount: new Set(configEntries.map((c) => c.namespace)).size,
      findingErrors,
      findingWarnings,
    },
  };
}

function csvCell(v) {
  const s = String(v == null ? '' : v);
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function buildAuditMarkdown(entries) {
  const lines = ['# Pulumi Stack Secret-Hygiene & Config Audit', ''];
  let totalErrors = 0;
  let totalWarnings = 0;
  for (const e of entries) {
    totalErrors += e.parsed.stats.findingErrors;
    totalWarnings += e.parsed.stats.findingWarnings;
  }
  lines.push(`- **Files audited:** ${entries.length}`);
  lines.push(`- **Total errors:** ${totalErrors}`);
  lines.push(`- **Total warnings:** ${totalWarnings}`);
  lines.push('');

  for (const { fileName, parsed } of entries) {
    const st = parsed.stats;
    lines.push(`## ${fileName} (${parsed.kind}${parsed.stackName ? `: ${parsed.stackName}` : ''})`);
    lines.push(`- Config keys: ${st.configCount} (${st.secureCount} secure, ${st.plainCount} plaintext) | Plugins: ${st.pluginCount}`);
    if (parsed.meta.secretsProvider) lines.push(`- Secrets provider: \`${parsed.meta.secretsProvider}\``);
    if (parsed.meta.runtime) lines.push(`- Runtime: \`${parsed.meta.runtime}\``);
    lines.push('');
    if (!parsed.findings.length) {
      lines.push('No secret-hygiene or versioning findings.');
      lines.push('');
    } else {
      lines.push('| Severity | Category | Rule | Line | Scope | Finding |');
      lines.push('| --- | --- | --- | ---: | --- | --- |');
      for (const f of parsed.findings) {
        lines.push(`| ${f.severity.toUpperCase()} | ${f.category} | \`${f.rule}\` | ${f.line} | \`${f.scope}\` | ${f.message.replace(/\|/g, '\\|')} |`);
      }
      lines.push('');
    }
  }
  return lines.join('\n');
}

function buildDiffMarkdown(leftName, left, rightName, right) {
  const lines = [`# Pulumi Stack Diff: ${leftName} vs ${rightName}`, ''];
  lines.push('## Summary');
  lines.push('| Metric | Baseline | Target | Delta |');
  lines.push('| --- | ---: | ---: | ---: |');
  const metrics = [
    ['Config Keys', left.stats.configCount, right.stats.configCount],
    ['Secure Keys', left.stats.secureCount, right.stats.secureCount],
    ['Plaintext Keys', left.stats.plainCount, right.stats.plainCount],
    ['Errors', left.stats.findingErrors, right.stats.findingErrors],
    ['Warnings', left.stats.findingWarnings, right.stats.findingWarnings],
  ];
  for (const [label, a, b] of metrics) {
    const d = b - a;
    lines.push(`| ${label} | ${a} | ${b} | ${d > 0 ? `+${d}` : d} |`);
  }
  lines.push('');

  const leftMap = new Map(left.configEntries.map((c) => [c.fullKey, c]));
  const rightMap = new Map(right.configEntries.map((c) => [c.fullKey, c]));
  const allKeys = [...new Set([...leftMap.keys(), ...rightMap.keys()])].sort();

  lines.push('## Config Key Differences (Redacted)');
  lines.push('| Key | Baseline | Target | Status |');
  lines.push('| --- | --- | --- | --- |');
  let diffRows = 0;
  for (const k of allKeys) {
    const a = leftMap.get(k);
    const b = rightMap.get(k);
    const av = a ? a.displayValue : '(missing)';
    const bv = b ? b.displayValue : '(missing)';
    if (!a) {
      lines.push(`| \`${k}\` | (missing) | \`${bv}\` | Added |`);
      diffRows += 1;
    } else if (!b) {
      lines.push(`| \`${k}\` | \`${av}\` | (missing) | Removed |`);
      diffRows += 1;
    } else if (a.isSecure !== b.isSecure) {
      lines.push(`| \`${k}\` | \`${av}\` | \`${bv}\` | Encryption changed |`);
      diffRows += 1;
    } else if (!a.isSecure && a.rawValue !== b.rawValue) {
      lines.push(`| \`${k}\` | \`${av}\` | \`${bv}\` | Value changed |`);
      diffRows += 1;
    }
  }
  if (!diffRows) {
    lines.push('| - | - | - | No config key differences |');
  }
  lines.push('');
  return lines.join('\n');
}

function buildRedactedConfigCsv(parsed) {
  const header = 'scope,namespace,key,value_redacted,encrypted,status,line';
  const out = [header];
  for (const r of parsed.rows) {
    out.push([r.scope, r.namespace, r.key, r.value, r.isSecure ? 'yes' : 'no', r.status, r.line].map(csvCell).join(','));
  }
  return out.join('\n') + '\n';
}

function buildRedactedConfigMarkdown(parsed, fileName) {
  const lines = [`# Pulumi Redacted Configuration Inventory: ${fileName}`, ''];
  lines.push(`- **File kind:** ${parsed.kind}${parsed.stackName ? ` (${parsed.stackName})` : ''}`);
  lines.push(`- **Config keys:** ${parsed.stats.configCount} (${parsed.stats.secureCount} encrypted, ${parsed.stats.plainCount} plaintext)`);
  lines.push(`- **Findings:** ${parsed.stats.findingErrors} errors, ${parsed.stats.findingWarnings} warnings`);
  lines.push('');
  lines.push('## Configuration Keys (Secrets Masked)');
  lines.push('| Line | Namespace | Key | Value (Redacted) | Status |');
  lines.push('| ---: | --- | --- | --- | --- |');
  for (const r of parsed.rows) {
    lines.push(`| ${r.line} | \`${r.namespace}\` | \`${r.key}\` | \`${String(r.value).replace(/\|/g, '\\|')}\` | ${r.status} |`);
  }
  lines.push('');
  return lines.join('\n');
}

module.exports = {
  parsePulumi,
  buildAuditMarkdown,
  buildDiffMarkdown,
  buildRedactedConfigCsv,
  buildRedactedConfigMarkdown,
};
