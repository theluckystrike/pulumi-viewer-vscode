'use strict';
// View model for Pulumi Stack & Policy Viewer: pagination, namespace/security filtering and detail inspection.

class PulumiViewModel {
  constructor(parsed, name, fileSize) {
    this.parsed = parsed;
    this.name = name;
    this.fileSize = fileSize;
    this.filter = { text: '', kind: '' };
    this.filtered = parsed.rows.slice();
  }

  summary() {
    const p = this.parsed;
    const s = p.stats;
    return {
      name: this.name,
      fileSize: this.fileSize,
      title: p.title,
      kind: p.kind,
      stackName: p.stackName,
      totalLines: p.totalLines,
      meta: p.meta,
      metadata: p.metadata,
      plugins: p.plugins,
      rowCount: s.rowCount,
      configCount: s.configCount,
      secureCount: s.secureCount,
      plainCount: s.plainCount,
      pluginCount: s.pluginCount,
      namespaceCount: s.namespaceCount,
      findingErrors: s.findingErrors,
      findingWarnings: s.findingWarnings,
      findings: p.findings,
    };
  }

  totalCount() {
    return this.parsed.rows.length;
  }

  count() {
    return this.filtered.length;
  }

  setFilter(f) {
    const text = f && typeof f.text === 'string' ? f.text.trim().toLowerCase() : '';
    const kind = f && typeof f.kind === 'string' ? f.kind.trim() : '';
    this.filter = { text, kind };
    this.filtered = this.parsed.rows.filter((r) => {
      if (kind === 'secure' && !r.isSecure) return false;
      if (kind === 'plain' && (r.scope !== 'config' || r.isSecure)) return false;
      if (kind === 'meta' && r.scope !== 'metadata') return false;
      if (kind === 'plugin' && r.scope !== 'plugin') return false;
      if (kind === 'findings' && !r.errorCount && !r.warningCount) return false;
      if (text) {
        const hay = `${r.scope} ${r.namespace} ${r.key} ${r.value} ${r.status}`.toLowerCase();
        if (!hay.includes(text)) return false;
      }
      return true;
    });
    return this.filtered.length;
  }

  rows(from, limit) {
    const start = Math.max(0, Number(from) || 0);
    const n = Math.max(1, Math.min(500, Number(limit) || 100));
    return this.filtered.slice(start, start + n).map((r) => ({
      index: r.index,
      line: r.line,
      scope: r.scope,
      namespace: r.namespace,
      key: r.key,
      value: r.value,
      isSecure: r.isSecure,
      status: r.status,
      errorCount: r.errorCount,
      warningCount: r.warningCount,
    }));
  }

  detail(index) {
    const r = this.parsed.rows.find((x) => x.index === index) || this.parsed.rows[0] || null;
    if (!r) return null;
    return {
      index: r.index,
      line: r.line,
      scope: r.scope,
      namespace: r.namespace,
      key: r.key,
      value: r.value,
      status: r.status,
      raw: r.raw,
      findings: r.findings,
      attrs: r.attrs,
    };
  }
}

module.exports = { PulumiViewModel };
