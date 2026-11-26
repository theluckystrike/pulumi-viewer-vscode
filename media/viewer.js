/* global acquireVsCodeApi */
(function () {
  'use strict';
  const vscode = acquireVsCodeApi();
  const app = document.getElementById('app');

  let state = {
    name: '',
    summary: null,
    pageSize: 100,
    page: 0,
    total: 0,
    rows: [],
    selected: null,
    tab: 'config',
    req: 0,
  };

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function post(msg) {
    state.req += 1;
    vscode.postMessage({ ...msg, req: state.req });
  }

  function fmtSize(n) {
    if (n >= 1048576) return `${(n / 1048576).toFixed(1)} MB`;
    if (n >= 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${n} B`;
  }

  function statusClass(st) {
    if (st === 'PLAINTEXT' || st === 'TOKEN') return 'bad';
    if (st === 'UNPINNED') return 'warn-text';
    if (st === 'SECURE' || st === 'ENCRYPTED') return 'ok';
    return '';
  }

  function renderShell() {
    const s = state.summary;
    const errChip = s.findingErrors > 0 ? `<span class="chip bad"><b>Errors:</b> ${s.findingErrors}</span>` : '<span class="chip"><b>Errors:</b> 0</span>';
    const warnChip = s.findingWarnings > 0 ? `<span class="chip warn"><b>Warnings:</b> ${s.findingWarnings}</span>` : '';
    const kindLabel = s.kind === 'stack' ? `STACK${s.stackName ? `: ${s.stackName}` : ''}` : 'PROJECT';

    app.innerHTML = `
      <div class="top">
        <div class="title">
          <span class="name">${esc(s.title || state.name)}</span>
          <span class="kind">Pulumi ${esc(kindLabel)} · ${s.totalLines} lines · ${fmtSize(s.fileSize)} · 100% offline (no CLI or cloud calls)</span>
        </div>
        <div class="summary">
          <span class="chip"><b>Config Keys:</b> ${s.configCount}</span>
          <span class="chip"><b>Encrypted:</b> ${s.secureCount}</span>
          <span class="chip"><b>Namespaces:</b> ${s.namespaceCount}</span>
          <span class="chip"><b>Plugins:</b> ${s.pluginCount}</span>
          ${errChip}${warnChip}
        </div>
        <div class="toolbar">
          <input id="q" type="search" placeholder="Filter by namespace, key, value, status..." />
          <select id="kindFilter">
            <option value="">All entries</option>
            <option value="secure">Encrypted (secure:)</option>
            <option value="plain">Plaintext config</option>
            <option value="meta">Project / Runtime metadata</option>
            <option value="plugin">Plugins &amp; Packages</option>
            <option value="findings">With Findings</option>
          </select>
          <button id="filterBtn" type="button">Filter</button>
          <span class="sep"></span>
          <div id="protools"></div>
        </div>
        <div class="tabs">
          <button class="tab on" data-tab="config" type="button">All Entries (${s.rowCount})</button>
          <button class="tab" data-tab="meta" type="button">Metadata (${(s.metadata || []).length})</button>
          <button class="tab" data-tab="findings" type="button">Findings (${(s.findings || []).length})</button>
        </div>
        <div id="hint" class="hint"></div>
      </div>
      <div class="main">
        <div id="leftPane" class="tablewrap"></div>
        <div id="detail" class="detail"><p class="muted">Select a config key, metadata field or plugin to inspect its encryption posture and static findings.</p></div>
      </div>
      <div class="pager">
        <button id="prev" type="button">Prev</button>
        <span id="pageInfo"></span>
        <button id="next" type="button">Next</button>
      </div>
    `;

    const q = document.getElementById('q');
    const kSel = document.getElementById('kindFilter');
    const runFilter = () => {
      state.page = 0;
      post({ type: 'filter', filter: { text: q.value, kind: kSel.value } });
    };
    document.getElementById('filterBtn').addEventListener('click', runFilter);
    q.addEventListener('keydown', (e) => { if (e.key === 'Enter') runFilter(); });
    kSel.addEventListener('change', runFilter);

    document.querySelectorAll('.tab').forEach((btn) => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach((b) => b.classList.remove('on'));
        btn.classList.add('on');
        state.tab = btn.dataset.tab;
        renderPane();
      });
    });

    document.getElementById('prev').addEventListener('click', () => {
      if (state.page > 0) { state.page -= 1; loadPage(); }
    });
    document.getElementById('next').addEventListener('click', () => {
      if ((state.page + 1) * state.pageSize < state.total) { state.page += 1; loadPage(); }
    });
  }

  function loadPage() {
    post({ type: 'page', from: state.page * state.pageSize, n: state.pageSize });
  }

  function bindRowClicks(left) {
    left.querySelectorAll('tbody tr[data-idx]').forEach((tr) => {
      tr.addEventListener('click', () => {
        const idx = Number(tr.dataset.idx);
        state.selected = idx;
        left.querySelectorAll('tbody tr').forEach((row) => row.classList.toggle('sel', Number(row.dataset.idx) === idx));
        post({ type: 'detail', index: idx });
      });
    });
  }

  function renderPane() {
    const left = document.getElementById('leftPane');
    const pager = document.querySelector('.pager');
    const s = state.summary;

    if (state.tab === 'meta') {
      pager.style.display = 'none';
      const rows = (s.metadata || []).map((m) => `<tr>
        <td class="num">${m.line}</td>
        <td><strong><code>${esc(m.key)}</code></strong></td>
        <td><code>${esc(m.value)}</code></td>
      </tr>`).join('');
      left.innerHTML = `<table id="grid">
        <thead><tr><th class="num">Line</th><th>Metadata Key</th><th>Value</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="3" class="muted">No project or stack metadata fields found.</td></tr>'}</tbody>
      </table>`;
      return;
    }

    if (state.tab === 'findings') {
      pager.style.display = 'none';
      const fRows = (s.findings || []).map((f) => `<tr>
        <td class="${f.severity === 'error' ? 'bad' : 'warn-text'}"><strong>${esc(f.severity.toUpperCase())}</strong></td>
        <td>${esc(f.category)}</td>
        <td><code>${esc(f.rule)}</code></td>
        <td class="num">${f.line}</td>
        <td><code>${esc(f.scope)}</code></td>
        <td>${esc(f.message)}</td>
      </tr>`).join('');
      left.innerHTML = fRows
        ? `<table id="grid"><thead><tr><th>Severity</th><th>Category</th><th>Rule</th><th class="num">Line</th><th>Scope</th><th>Finding</th></tr></thead><tbody>${fRows}</tbody></table>`
        : '<p class="muted" style="padding:12px;">No Pulumi secret-hygiene or versioning findings.</p>';
      return;
    }

    pager.style.display = 'flex';
    const body = state.rows.map((r) => {
      const sel = state.selected === r.index ? ' class="sel"' : '';
      return `<tr data-idx="${r.index}"${sel}>
        <td class="num">${r.line}</td>
        <td><code>${esc(r.namespace)}</code></td>
        <td><strong><code>${esc(r.key)}</code></strong></td>
        <td><code>${esc(r.value)}</code></td>
        <td class="${statusClass(r.status)}"><strong>${esc(r.status)}</strong></td>
      </tr>`;
    }).join('');
    left.innerHTML = `<table id="grid">
      <thead><tr><th class="num">Line</th><th>Namespace</th><th>Key</th><th>Value (Masked)</th><th>Status</th></tr></thead>
      <tbody>${body || '<tr><td colspan="5" class="muted">No matching entries.</td></tr>'}</tbody>
    </table>`;
    bindRowClicks(left);

    const pages = Math.max(1, Math.ceil(state.total / state.pageSize));
    document.getElementById('pageInfo').textContent = `Page ${state.page + 1} of ${pages} (${state.total} entries)`;
    document.getElementById('prev').disabled = state.page <= 0;
    document.getElementById('next').disabled = (state.page + 1) * state.pageSize >= state.total;
  }

  function renderDetail(d) {
    const el = document.getElementById('detail');
    if (!d) {
      el.innerHTML = '<p class="muted">No entry selected.</p>';
      return;
    }
    const attrRows = (d.attrs || []).map((a) => `<tr><td><strong>${esc(a.key)}</strong></td><td><code>${esc(a.value)}</code></td></tr>`).join('');
    const findHtml = (d.findings && d.findings.length)
      ? `<div class="attr-head"><strong>Findings</strong></div>` + d.findings.map((f) => `<div class="error" style="margin:4px 0;padding:6px 10px;"><strong>${esc(f.rule)}</strong>: ${esc(f.message)}</div>`).join('')
      : '';
    const rawHtml = d.raw ? `<div class="attr-head"><strong>Redacted Line</strong></div><pre class="trace">${esc(d.raw)}</pre>` : '';

    el.innerHTML = `
      <div class="dhead"><strong>Line ${d.line}: ${esc(d.key)}</strong><span class="${statusClass(d.status)}">${esc(d.status)}</span></div>
      <table class="splits"><thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>${attrRows}</tbody></table>
      ${findHtml}${rawHtml}
    `;
  }

  window.addEventListener('message', (ev) => {
    const m = ev.data;
    if (!m || typeof m !== 'object') return;
    switch (m.type) {
      case 'init':
        if (m.error) {
          app.innerHTML = `<div class="error"><strong>Could not open ${esc(m.name)}</strong><p>${esc(m.error)}</p></div>`;
          return;
        }
        state.name = m.name;
        state.summary = m.summary;
        state.pageSize = m.pageSize || 100;
        state.page = 0;
        renderShell();
        loadPage();
        return;
      case 'pageResult':
        state.total = m.total;
        state.rows = m.rows || [];
        renderPane();
        if (state.rows.length && state.selected == null) {
          state.selected = state.rows[0].index;
          post({ type: 'detail', index: state.selected });
        }
        return;
      case 'filterResult':
        state.total = m.count;
        document.getElementById('hint').textContent = m.count < m.total ? `Showing ${m.count} of ${m.total} entries.` : '';
        loadPage();
        return;
      case 'detailResult':
        renderDetail(m.detail);
        return;
      case 'zovoAlso': {
        const anchor = m.anchor && document.getElementById(m.anchor);
        if (anchor && m.html) {
          const old = document.querySelector('.zovo-also');
          if (old) old.remove();
          anchor.insertAdjacentHTML('afterend', m.html);
        }
        return;
      }
      case 'hint':
        if (document.getElementById('hint')) document.getElementById('hint').textContent = m.text || '';
        return;
      default:
    }
  });

  post({ type: 'ready' });
})();
