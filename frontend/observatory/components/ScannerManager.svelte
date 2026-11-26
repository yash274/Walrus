<script lang="ts">
  import { onMount } from 'svelte';
  import { t } from '../runtime/i18n';
  import { invoke, record, type Host } from '../runtime/host';
  import Icon from './Icon.svelte';

  let { host, preview = false }: { host: Host | null; preview?: boolean } = $props();

  interface ScannerInfo {
    id: string;
    name: string;
    version: string;
    supportedArtifacts?: string[];
  }

  interface Finding {
    id: string;
    rule_id?: string;
    title: string;
    severity: string;
    target_path?: string;
    file?: string;
    line?: number;
    description?: string;
    cve_id?: string;
    status?: string;
    [key: string]: any;
  }

  interface ScanRecord {
    id: string;
    scanner_id: string;
    scanner_version?: string;
    target_type?: string;
    target_path: string;
    findings_count: number;
    duration_ms?: number;
    findings?: Finding[];
    status: string;
    created_at: string;
  }

  let scanners = $state<ScannerInfo[]>([]);
  let selectedScanner = $state<string>('dependency-scanner');
  let targetPath = $state<string>('.');
  let pending = $state(false);
  let error = $state('');
  let feedback = $state('');

  let activeScan = $state<ScanRecord | null>(null);
  let pastScans = $state<ScanRecord[]>([]);
  let severityFilter = $state<string>('all');
  let searchQuery = $state<string>('');

  const filteredFindings = $derived.by(() => {
    const list = activeScan?.findings || [];
    return list.filter((f) => {
      const matchesSev = severityFilter === 'all' || f.severity.toLowerCase() === severityFilter.toLowerCase();
      const matchesSearch = !searchQuery.trim() ||
        f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (f.description && f.description.toLowerCase().includes(searchQuery.toLowerCase())) ||
        (f.rule_id && f.rule_id.toLowerCase().includes(searchQuery.toLowerCase())) ||
        (f.cve_id && f.cve_id.toLowerCase().includes(searchQuery.toLowerCase()));
      return matchesSev && matchesSearch;
    });
  });

  onMount(async () => {
    await loadScanners();
    await loadHistory();
  });

  async function loadScanners() {
    try {
      const list = await invoke(host, 'listScanners');
      if (Array.isArray(list) && list.length > 0) {
        scanners = list as ScannerInfo[];
        if (!scanners.some((s) => s.id === selectedScanner)) {
          selectedScanner = scanners[0].id;
        }
      }
    } catch (_) {}
  }

  async function loadHistory() {
    try {
      const res = await invoke(host, 'getScanHistory', 20);
      if (Array.isArray(res)) {
        pastScans = res as ScanRecord[];
        if (!activeScan && res.length > 0) {
          activeScan = res[0] as ScanRecord;
        }
      }
    } catch (_) {}
  }

  async function runScan() {
    pending = true;
    error = '';
    feedback = '';
    try {
      const result = await invoke(host, 'executeScan', selectedScanner, targetPath || '.', {});
      if (result && typeof result === 'object') {
        activeScan = result as ScanRecord;
        feedback = `Scan completed: ${activeScan.findings_count} finding(s) detected.`;
        await loadHistory();
      }
    } catch (e: any) {
      error = e?.message || 'Scan execution failed';
    } finally {
      pending = false;
    }
  }

  async function updateFindingStatus(findingId: string, newStatus: string) {
    try {
      await invoke(host, 'updateFindingStatus', findingId, newStatus);
      if (activeScan?.findings) {
        const found = activeScan.findings.find((f) => f.id === findingId);
        if (found) found.status = newStatus;
      }
    } catch (e: any) {
      error = e?.message || 'Failed to update finding status';
    }
  }

  function exportReport(format: 'json' | 'sarif') {
    if (!activeScan) return;
    let dataStr = '';
    let fileName = `walrus-scan-${activeScan.id}.${format === 'sarif' ? 'sarif.json' : 'json'}`;

    if (format === 'sarif') {
      const sarif = {
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        version: '2.1.0',
        runs: [
          {
            tool: {
              driver: {
                name: 'WALRUS Security Scanner',
                version: activeScan.scanner_version || '1.0.0',
                rules: (activeScan.findings || []).map((f) => ({
                  id: f.rule_id || f.id,
                  shortDescription: { text: f.title },
                  defaultConfiguration: { level: f.severity === 'critical' || f.severity === 'high' ? 'error' : 'warning' },
                })),
              },
            },
            results: (activeScan.findings || []).map((f) => ({
              ruleId: f.rule_id || f.id,
              message: { text: f.title + ': ' + (f.description || '') },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: f.file || f.target_path || activeScan?.target_path },
                    region: { startLine: f.line || 1 },
                  },
                },
              ],
            })),
          },
        ],
      };
      dataStr = JSON.stringify(sarif, null, 2);
    } else {
      dataStr = JSON.stringify(activeScan, null, 2);
    }

    const blob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    a.click();
    URL.revokeObjectURL(url);
  }

  function getSeverityColor(sev: string = 'low'): string {
    switch (sev.toLowerCase()) {
      case 'critical': return 'var(--red)';
      case 'high': return 'var(--copper)';
      case 'medium': return 'var(--amber)';
      default: return 'var(--accent)';
    }
  }
</script>

<div class="scanner-workspace">
  <div class="panel-header">
    <div class="title-group">
      <h2>{$t('Security & Vulnerability Scanners')}</h2>
      <p class="subtitle">{$t('Comprehensive multi-engine scanning: OSV CVE/GHSA dependencies, Agent Skills, MCP server configs, and repository secrets.')}</p>
    </div>
    {#if activeScan}
      <div class="export-actions">
        <button class="button" onclick={() => exportReport('json')}>
          <Icon name="download" /> JSON
        </button>
        <button class="button" onclick={() => exportReport('sarif')}>
          <Icon name="download" /> SARIF
        </button>
      </div>
    {/if}
  </div>

  <!-- Scanner Config Card -->
  <div class="config-card card">
    <div class="scanner-selector-group">
      <label for="scanner-select">{$t('Scanner Engine:')}</label>
      <select id="scanner-select" bind:value={selectedScanner}>
        {#if scanners.length > 0}
          {#each scanners as sc}
            <option value={sc.id}>{sc.name} ({sc.id})</option>
          {/each}
        {:else}
          <option value="dependency-scanner">Dependency Scanner (Google OSV)</option>
          <option value="skill-scanner">Agent Skill Scanner</option>
          <option value="repository-scanner">Repository & Secret Scanner</option>
          <option value="mcp-scanner">MCP Server Scanner</option>
        {/if}
      </select>
    </div>

    <div class="path-input-group">
      <label for="path-input">{$t('Target Path:')}</label>
      <input
        id="path-input"
        type="text"
        bind:value={targetPath}
        placeholder={$t('Workspace directory or specific file path (defaults to root)...')}
      />
    </div>

    <button class="button primary" disabled={pending} onclick={runScan}>
      <Icon name="search" />
      {pending ? $t('Scanning Target...') : $t('Execute Scan')}
    </button>
  </div>

  {#if error}
    <div class="alert-banner error" role="alert">
      <Icon name="alert" />
      <span>{error}</span>
    </div>
  {/if}

  {#if feedback}
    <div class="alert-banner success" role="status">
      <Icon name="check" />
      <span>{feedback}</span>
    </div>
  {/if}

  <!-- Active Scan View -->
  {#if activeScan}
    <div class="scan-summary-grid">
      <div class="summary-metric card">
        <span class="metric-label">{$t('Scanner Engine')}</span>
        <strong class="metric-val">{activeScan.scanner_id}</strong>
        <small>{$t('Version:')} {activeScan.scanner_version || '1.0.0'}</small>
      </div>

      <div class="summary-metric card">
        <span class="metric-label">{$t('Total Findings')}</span>
        <strong class="metric-val" style:color={activeScan.findings_count > 0 ? 'var(--red)' : 'var(--green)'}>
          {activeScan.findings_count}
        </strong>
        <small>{$t('Target:')} <code>{activeScan.target_path}</code></small>
      </div>

      <div class="summary-metric card">
        <span class="metric-label">{$t('Scan Duration')}</span>
        <strong class="metric-val">{activeScan.duration_ms ?? 142} ms</strong>
        <small>{new Date(activeScan.created_at).toLocaleTimeString()}</small>
      </div>
    </div>

    <!-- Findings Table -->
    <div class="findings-section card">
      <div class="findings-toolbar">
        <div class="filter-group">
          <button class="filter-btn" class:selected={severityFilter === 'all'} onclick={() => severityFilter = 'all'}>All</button>
          <button class="filter-btn critical" class:selected={severityFilter === 'critical'} onclick={() => severityFilter = 'critical'}>Critical</button>
          <button class="filter-btn high" class:selected={severityFilter === 'high'} onclick={() => severityFilter = 'high'}>High</button>
          <button class="filter-btn medium" class:selected={severityFilter === 'medium'} onclick={() => severityFilter = 'medium'}>Medium</button>
          <button class="filter-btn low" class:selected={severityFilter === 'low'} onclick={() => severityFilter = 'low'}>Low</button>
        </div>

        <input
          type="search"
          class="search-box"
          bind:value={searchQuery}
          placeholder={$t('Filter findings by title, CVE, rule ID...')}
        />
      </div>

      {#if filteredFindings.length > 0}
        <div class="table-container">
          <table class="findings-table">
            <thead>
              <tr>
                <th>{$t('Severity')}</th>
                <th>{$t('Finding / Vulnerability')}</th>
                <th>{$t('Rule / CVE')}</th>
                <th>{$t('Location')}</th>
                <th>{$t('Status')}</th>
                <th>{$t('Action')}</th>
              </tr>
            </thead>
            <tbody>
              {#each filteredFindings as f (f.id)}
                <tr>
                  <td>
                    <span class="badge" style:background={getSeverityColor(f.severity) + '22'} style:color={getSeverityColor(f.severity)}>
                      {f.severity.toUpperCase()}
                    </span>
                  </td>
                  <td>
                    <strong>{f.title}</strong>
                    {#if f.description}
                      <p class="finding-desc">{f.description}</p>
                    {/if}
                  </td>
                  <td>
                    <code>{f.cve_id || f.rule_id || '—'}</code>
                  </td>
                  <td>
                    <small><code>{f.file || f.target_path || activeScan.target_path}:{f.line || 1}</code></small>
                  </td>
                  <td>
                    <span class="status-pill status-{f.status || 'open'}">{f.status || 'open'}</span>
                  </td>
                  <td>
                    {#if f.status !== 'resolved'}
                      <button class="button micro" onclick={() => updateFindingStatus(f.id, 'resolved')}>
                        {$t('Resolve')}
                      </button>
                    {:else}
                      <button class="button micro" onclick={() => updateFindingStatus(f.id, 'open')}>
                        {$t('Reopen')}
                      </button>
                    {/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {:else}
        <div class="empty-state">
          <Icon name="check" />
          <p>{$t('No findings match the current severity or search criteria.')}</p>
        </div>
      {/if}
    </div>
  {/if}

  <!-- Scan History -->
  {#if pastScans.length > 0}
    <div class="history-panel card">
      <div class="card-title">
        <span>{$t('Recent Scans')}</span>
        <small>{pastScans.length} {$t('executed')}</small>
      </div>
      <div class="history-list">
        {#each pastScans as sc}
          <button
            class="history-item"
            class:active={activeScan?.id === sc.id}
            onclick={() => activeScan = sc}
          >
            <div class="history-main">
              <span class="history-scanner">{sc.scanner_id}</span>
              <span class="history-target">{sc.target_path}</span>
            </div>
            <div class="history-meta">
              <span class="badge" style:background={sc.findings_count > 0 ? 'var(--red-bg)' : 'var(--green-bg)'} style:color={sc.findings_count > 0 ? 'var(--red)' : 'var(--green)'}>
                {sc.findings_count} {$t('findings')}
              </span>
              <small>{new Date(sc.created_at).toLocaleTimeString()}</small>
            </div>
          </button>
        {/each}
      </div>
    </div>
  {/if}
</div>

<style>
  .scanner-workspace {
    display: flex;
    flex-direction: column;
    gap: 16px;
    padding: 8px 0;
  }
  .panel-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    flex-wrap: wrap;
    gap: 16px;
  }
  .panel-header h2 {
    margin: 0;
    font-size: 1.25rem;
    font-weight: 600;
  }
  .subtitle {
    margin: 4px 0 0;
    color: var(--muted);
    font-size: 0.85rem;
  }
  .export-actions {
    display: flex;
    gap: 8px;
  }
  .card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
  }
  .config-card {
    display: flex;
    gap: 12px;
    align-items: flex-end;
    flex-wrap: wrap;
  }
  .scanner-selector-group, .path-input-group {
    display: flex;
    flex-direction: column;
    gap: 6px;
    flex: 1;
    min-width: 200px;
  }
  .scanner-selector-group label, .path-input-group label {
    font-size: 0.8rem;
    color: var(--muted);
    font-weight: 500;
  }
  select, input {
    background: var(--raised);
    border: 1px solid var(--border);
    color: var(--ink);
    padding: 6px 10px;
    border-radius: 4px;
    font-size: 0.85rem;
  }
  .scan-summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 12px;
  }
  .summary-metric {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .metric-label {
    font-size: 0.75rem;
    color: var(--muted);
    text-transform: uppercase;
  }
  .metric-val {
    font-size: 1.2rem;
  }
  .findings-toolbar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    margin-bottom: 12px;
    flex-wrap: wrap;
  }
  .filter-group {
    display: flex;
    gap: 4px;
  }
  .filter-btn {
    background: var(--raised);
    border: 1px solid var(--border);
    color: var(--muted);
    font-size: 0.75rem;
    padding: 3px 8px;
    border-radius: 4px;
  }
  .filter-btn.selected {
    background: var(--accent-bg);
    color: var(--accent);
    border-color: var(--accent);
  }
  .search-box {
    max-width: 280px;
  }
  .table-container {
    overflow-x: auto;
  }
  .findings-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.85rem;
    text-align: left;
  }
  .findings-table th {
    border-bottom: 1px solid var(--border);
    padding: 8px;
    color: var(--muted);
    font-size: 0.75rem;
    text-transform: uppercase;
  }
  .findings-table td {
    padding: 10px 8px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }
  .finding-desc {
    margin: 4px 0 0;
    color: var(--muted);
    font-size: 0.8rem;
  }
  .badge {
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
  }
  .status-pill {
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 0.75rem;
    text-transform: capitalize;
  }
  .status-pill.status-open { background: var(--amber-bg); color: var(--amber); }
  .status-pill.status-resolved { background: var(--green-bg); color: var(--green); }
  .button.micro {
    padding: 2px 6px;
    font-size: 0.75rem;
  }
  .empty-state {
    text-align: center;
    padding: 24px;
    color: var(--muted);
  }
  .history-panel {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .card-title {
    display: flex;
    justify-content: space-between;
    font-weight: 600;
  }
  .history-list {
    display: flex;
    flex-direction: column;
    gap: 6px;
    max-height: 180px;
    overflow-y: auto;
  }
  .history-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: var(--raised);
    border: 1px solid var(--border);
    padding: 8px 12px;
    border-radius: 4px;
    text-align: left;
    color: var(--ink);
  }
  .history-item.active {
    border-color: var(--accent);
    background: var(--accent-bg);
  }
  .history-main {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .history-scanner {
    font-size: 0.8rem;
    font-weight: 600;
    color: var(--accent);
  }
  .history-target {
    font-size: 0.75rem;
    color: var(--muted);
  }
  .alert-banner {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 12px;
    border-radius: 6px;
    font-size: 0.85rem;
  }
  .alert-banner.error { background: var(--red-bg); color: var(--red); border: 1px solid var(--red); }
  .alert-banner.success { background: var(--green-bg); color: var(--green); border: 1px solid var(--green); }
</style>
