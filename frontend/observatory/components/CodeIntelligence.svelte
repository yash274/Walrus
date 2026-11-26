<script lang="ts">
  import { onMount } from 'svelte';
  import { t } from '../runtime/i18n';
  import { invoke, record, type Host } from '../runtime/host';
  import Icon from './Icon.svelte';

  let { host, preview = false }: { host: Host | null; preview?: boolean } = $props();

  let scope = $state<'staged' | 'unstaged' | 'last-commit' | 'custom'>('staged');
  let customDiff = $state('');
  let pending = $state(false);
  let error = $state('');
  let feedback = $state('');

  interface Finding {
    id: string;
    file: string;
    line: number;
    title: string;
    severity: string;
    matchedSnippet?: string;
    explanation?: string;
    recommendation?: string;
  }

  interface CodeReviewReport {
    id: string;
    repository_path: string;
    git_branch: string;
    commit_hash: string;
    scope: string;
    summary: string;
    impact?: {
      score?: number;
      level?: string;
      summary?: string;
      impactedFiles?: string[];
      affectedDependencies?: string[];
    };
    walkthrough?: Array<{
      file: string;
      additions: number;
      deletions: number;
      description?: string;
    }>;
    findings?: Finding[];
    suggested_fixes?: Array<{
      findingId: string;
      file: string;
      line: number;
      patch: string;
    }>;
    created_at: string;
  }

  let activeReport = $state<CodeReviewReport | null>(null);
  let pastReviews = $state<any[]>([]);
  let severityFilter = $state<string>('all');
  let proposedRemediations = $state<Record<string, string>>({});

  const filteredFindings = $derived.by(() => {
    if (!activeReport?.findings) return [];
    if (severityFilter === 'all') return activeReport.findings;
    return activeReport.findings.filter((f) => f.severity.toLowerCase() === severityFilter.toLowerCase());
  });

  onMount(async () => {
    await loadHistory();
  });

  async function loadHistory() {
    try {
      const res = await invoke(host, 'listCodeReviews', 20);
      if (Array.isArray(res)) {
        pastReviews = res;
        if (!activeReport && res.length > 0) {
          activeReport = res[0];
        }
      }
    } catch (_) {}
  }

  async function runReview() {
    pending = true;
    error = '';
    feedback = '';
    try {
      const options: Record<string, unknown> = { scope };
      if (scope === 'custom') {
        options.rawDiff = customDiff;
      }
      const result = await invoke(host, 'runCodeReview', options);
      if (result && typeof result === 'object') {
        activeReport = result as CodeReviewReport;
        feedback = `Code review completed: ${activeReport.findings?.length || 0} finding(s) detected.`;
        await loadHistory();
      }
    } catch (e: any) {
      error = e?.message || 'Failed to execute code review';
    } finally {
      pending = false;
    }
  }

  async function proposeFix(finding: Finding) {
    try {
      const proposal = await invoke(host, 'proposeRemediation', {
        finding,
        file: finding.file,
        targetText: finding.matchedSnippet || '',
        replacementText: `/* Remediation: ${finding.recommendation || 'Fix issue'} */`,
        explanation: finding.explanation || finding.title,
      });
      const pRecord = record(proposal);
      if (pRecord.id) {
        proposedRemediations[finding.id] = String(pRecord.id);
        feedback = `Remediation proposed for ${finding.title} (ID: ${pRecord.id})`;
      }
    } catch (e: any) {
      error = e?.message || 'Failed to create remediation proposal';
    }
  }

  function getSeverityColor(sev: string): string {
    switch (sev.toLowerCase()) {
      case 'critical': return 'var(--red)';
      case 'high': return 'var(--copper)';
      case 'medium': return 'var(--amber)';
      default: return 'var(--accent)';
    }
  }

  function getImpactBadgeClass(level: string = 'low'): string {
    const l = level.toLowerCase();
    if (l === 'critical') return 'badge-critical';
    if (l === 'high') return 'badge-high';
    if (l === 'medium') return 'badge-medium';
    return 'badge-low';
  }
</script>

<div class="code-intel-workspace">
  <div class="panel-header">
    <div class="title-group">
      <h2>{$t('Code Intelligence & Contextual Review')}</h2>
      <p class="subtitle">{$t('Automated semantic code review, diff security analysis and architectural blast radius calculation.')}</p>
    </div>
    <div class="controls-group">
      <div class="scope-selector" role="group" aria-label="Review Scope">
        <button class="button" class:active={scope === 'staged'} onclick={() => scope = 'staged'}>staged</button>
        <button class="button" class:active={scope === 'unstaged'} onclick={() => scope = 'unstaged'}>unstaged</button>
        <button class="button" class:active={scope === 'last-commit'} onclick={() => scope = 'last-commit'}>HEAD~1</button>
        <button class="button" class:active={scope === 'custom'} onclick={() => scope = 'custom'}>custom diff</button>
      </div>
      <button class="button primary" disabled={pending} onclick={runReview}>
        <Icon name="search" />
        {pending ? $t('Analyzing...') : $t('Run Code Review')}
      </button>
    </div>
  </div>

  {#if scope === 'custom'}
    <div class="custom-diff-box">
      <label for="custom-diff-input">{$t('Paste Git Unified Diff:')}</label>
      <textarea
        id="custom-diff-input"
        bind:value={customDiff}
        placeholder="--- a/file.js&#10;+++ b/file.js&#10;@@ -1,3 +1,4 @@&#10;+ eval(userInput);"
        rows="5"
      ></textarea>
    </div>
  {/if}

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

  {#if activeReport}
    <!-- Summary & Blast Radius -->
    <div class="overview-grid">
      <div class="card impact-card">
        <div class="card-title">
          <span>{$t('Architectural Blast Radius')}</span>
          <span class="badge {getImpactBadgeClass(activeReport.impact?.level)}">
            {activeReport.impact?.level?.toUpperCase() || 'LOW'}
          </span>
        </div>
        <p class="impact-summary">{activeReport.impact?.summary || $t('No architectural risk identified.')}</p>
        <div class="meta-row">
          <small>{$t('Branch:')} <strong>{activeReport.git_branch || 'main'}</strong></small>
          <small>{$t('Commit:')} <code>{activeReport.commit_hash?.slice(0, 8) || 'working-tree'}</code></small>
          <small>{$t('Risk Score:')} <strong>{activeReport.impact?.score ?? 0}/100</strong></small>
        </div>
        {#if activeReport.impact?.affectedDependencies?.length}
          <div class="dep-list">
            <small>{$t('Affected Modules:')}</small>
            <div class="chips">
              {#each activeReport.impact.affectedDependencies as dep}
                <span class="chip">{dep}</span>
              {/each}
            </div>
          </div>
        {/if}
      </div>

      <div class="card walkthrough-card">
        <div class="card-title">
          <span>{$t('Modified Files & Walkthrough')}</span>
          <small>{activeReport.walkthrough?.length || 0} {$t('files')}</small>
        </div>
        {#if activeReport.walkthrough && activeReport.walkthrough.length > 0}
          <ul class="file-list">
            {#each activeReport.walkthrough as item}
              <li>
                <div class="file-info">
                  <Icon name="fileCode" />
                  <span class="filename">{item.file}</span>
                </div>
                <div class="diff-stats">
                  <span class="add">+{item.additions}</span>
                  <span class="del">-{item.deletions}</span>
                </div>
              </li>
            {/each}
          </ul>
        {:else}
          <p class="empty-state">{$t('No changed files detected in this scope.')}</p>
        {/if}
      </div>
    </div>

    <!-- Findings Section -->
    <div class="findings-container">
      <div class="findings-header">
        <h3>{$t('Security & Quality Findings')} ({activeReport.findings?.length || 0})</h3>
        <div class="filter-group">
          <button class="filter-btn" class:selected={severityFilter === 'all'} onclick={() => severityFilter = 'all'}>All</button>
          <button class="filter-btn critical" class:selected={severityFilter === 'critical'} onclick={() => severityFilter = 'critical'}>Critical</button>
          <button class="filter-btn high" class:selected={severityFilter === 'high'} onclick={() => severityFilter = 'high'}>High</button>
          <button class="filter-btn medium" class:selected={severityFilter === 'medium'} onclick={() => severityFilter = 'medium'}>Medium</button>
          <button class="filter-btn minor" class:selected={severityFilter === 'minor'} onclick={() => severityFilter = 'minor'}>Minor</button>
        </div>
      </div>

      {#if filteredFindings.length > 0}
        <div class="findings-list">
          {#each filteredFindings as finding (finding.id)}
            <div class="finding-card" style:border-left-color={getSeverityColor(finding.severity)}>
              <div class="finding-top">
                <div class="finding-identity">
                  <span class="badge" style:background={getSeverityColor(finding.severity) + '22'} style:color={getSeverityColor(finding.severity)}>
                    {finding.severity.toUpperCase()}
                  </span>
                  <h4>{finding.title}</h4>
                </div>
                <div class="finding-location">
                  <code>{finding.file}:{finding.line}</code>
                </div>
              </div>

              <p class="finding-explanation">{finding.explanation}</p>

              {#if finding.matchedSnippet}
                <div class="snippet-box">
                  <code>{finding.matchedSnippet}</code>
                </div>
              {/if}

              {#if finding.recommendation}
                <div class="recommendation-box">
                  <strong>{$t('Recommendation:')}</strong> {finding.recommendation}
                </div>
              {/if}

              <div class="finding-actions">
                {#if proposedRemediations[finding.id]}
                  <span class="proposal-success">
                    <Icon name="check" /> {$t('Remediation Proposed')} (<code>{proposedRemediations[finding.id]}</code>)
                  </span>
                {:else}
                  <button class="button small" onclick={() => proposeFix(finding)}>
                    <Icon name="spark" />
                    {$t('Propose Remediation')}
                  </button>
                {/if}
              </div>
            </div>
          {/each}
        </div>
      {:else}
        <div class="empty-state card">
          <Icon name="check" />
          <p>{$t('No security or quality findings in this review scope.')}</p>
        </div>
      {/if}
    </div>
  {:else}
    <div class="empty-workspace card">
      <Icon name="fileCode" />
      <h3>{$t('No Code Review Selected')}</h3>
      <p>{$t('Select a Git scope and click "Run Code Review" to inspect changes for vulnerabilities, blast radius and regressions.')}</p>
    </div>
  {/if}

  <!-- History -->
  {#if pastReviews.length > 0}
    <div class="history-panel card">
      <div class="card-title">
        <span>{$t('Review History')}</span>
        <small>{pastReviews.length} {$t('recorded')}</small>
      </div>
      <div class="history-list">
        {#each pastReviews as rev}
          <button
            class="history-item"
            class:active={activeReport?.id === rev.id}
            onclick={() => activeReport = rev}
          >
            <div class="history-main">
              <span class="history-scope">{rev.scope}</span>
              <span class="history-summary">{rev.summary}</span>
            </div>
            <div class="history-meta">
              <span class="badge {getImpactBadgeClass(rev.impact?.level)}">{rev.impact?.level || 'low'}</span>
              <small>{new Date(rev.created_at).toLocaleTimeString()}</small>
            </div>
          </button>
        {/each}
      </div>
    </div>
  {/if}
</div>

<style>
  .code-intel-workspace {
    display: flex;
    flex-direction: column;
    gap: 16px;
    padding: 8px 0;
  }
  .panel-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 16px;
    flex-wrap: wrap;
  }
  .title-group h2 {
    margin: 0;
    font-size: 1.25rem;
    font-weight: 600;
    color: var(--ink);
  }
  .subtitle {
    margin: 4px 0 0;
    color: var(--muted);
    font-size: 0.85rem;
  }
  .controls-group {
    display: flex;
    gap: 8px;
    align-items: center;
  }
  .scope-selector {
    display: flex;
    background: var(--raised);
    padding: 2px;
    border-radius: 6px;
    border: 1px solid var(--border);
  }
  .scope-selector button {
    border: none;
    background: transparent;
    color: var(--muted);
    padding: 4px 10px;
    font-size: 0.8rem;
    border-radius: 4px;
  }
  .scope-selector button.active {
    background: var(--panel);
    color: var(--ink);
    font-weight: 500;
  }
  .custom-diff-box {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .custom-diff-box textarea {
    background: var(--raised);
    color: var(--ink);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 8px;
    font-family: var(--mono);
    font-size: 0.8rem;
  }
  .overview-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
    gap: 16px;
  }
  .card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
  }
  .card-title {
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-weight: 600;
    margin-bottom: 12px;
    color: var(--ink);
  }
  .impact-summary {
    color: var(--muted);
    font-size: 0.9rem;
    margin-bottom: 12px;
  }
  .meta-row {
    display: flex;
    gap: 16px;
    color: var(--faint);
    font-size: 0.8rem;
    margin-bottom: 8px;
  }
  .meta-row code {
    color: var(--accent);
  }
  .badge {
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.5px;
  }
  .badge-critical { background: var(--red-bg); color: var(--red); }
  .badge-high { background: rgba(251, 146, 60, 0.15); color: var(--copper); }
  .badge-medium { background: var(--amber-bg); color: var(--amber); }
  .badge-low { background: var(--green-bg); color: var(--green); }

  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    margin-top: 4px;
  }
  .chip {
    background: var(--raised);
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 0.75rem;
    font-family: var(--mono);
    color: var(--muted);
  }
  .file-list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .file-list li {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 4px 8px;
    background: var(--raised);
    border-radius: 4px;
    font-size: 0.85rem;
  }
  .file-info {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .diff-stats .add { color: var(--green); font-family: var(--mono); margin-right: 6px; }
  .diff-stats .del { color: var(--red); font-family: var(--mono); }

  .findings-container {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .findings-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .findings-header h3 {
    margin: 0;
    font-size: 1.1rem;
    font-weight: 600;
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
  .finding-card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-left-width: 4px;
    border-radius: 6px;
    padding: 12px 16px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .finding-top {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .finding-identity {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .finding-identity h4 {
    margin: 0;
    font-size: 0.95rem;
    font-weight: 600;
  }
  .finding-location code {
    font-family: var(--mono);
    font-size: 0.8rem;
    color: var(--faint);
  }
  .finding-explanation {
    margin: 0;
    font-size: 0.85rem;
    color: var(--muted);
  }
  .snippet-box {
    background: var(--raised);
    padding: 6px 10px;
    border-radius: 4px;
    font-family: var(--mono);
    font-size: 0.8rem;
    color: var(--red);
    overflow-x: auto;
  }
  .recommendation-box {
    background: var(--green-bg);
    color: var(--green);
    font-size: 0.8rem;
    padding: 6px 10px;
    border-radius: 4px;
  }
  .finding-actions {
    display: flex;
    justify-content: flex-end;
    margin-top: 4px;
  }
  .button.small {
    padding: 3px 10px;
    font-size: 0.75rem;
  }
  .proposal-success {
    font-size: 0.8rem;
    color: var(--green);
    display: flex;
    align-items: center;
    gap: 4px;
  }
  .empty-state {
    text-align: center;
    padding: 32px 16px;
    color: var(--muted);
  }
  .empty-workspace {
    text-align: center;
    padding: 48px 16px;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 8px;
  }
  .history-panel {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .history-list {
    display: flex;
    flex-direction: column;
    gap: 6px;
    max-height: 200px;
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
  .history-scope {
    font-size: 0.75rem;
    font-family: var(--mono);
    color: var(--accent);
  }
  .history-summary {
    font-size: 0.85rem;
  }
  .history-meta {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .alert-banner {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 12px;
    border-radius: 6px;
    font-size: 0.85rem;
  }
  .alert-banner.error {
    background: var(--red-bg);
    color: var(--red);
    border: 1px solid var(--red);
  }
  .alert-banner.success {
    background: var(--green-bg);
    color: var(--green);
    border: 1px solid var(--green);
  }
</style>
