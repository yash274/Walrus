<script lang="ts">
  import { onMount } from 'svelte';
  import { t } from '../runtime/i18n';
  import { invoke, record, type Host } from '../runtime/host';
  import Icon from './Icon.svelte';

  let { host, preview = false }: { host: Host | null; preview?: boolean } = $props();

  const SPECIALIST_OPTIONS = [
    { id: 'SecurityAnalyst', name: 'Security Analyst', desc: 'Examines suspicious prompts, instruction injections, tool calls and runtime behavior.' },
    { id: 'CodeReviewer', name: 'Code Reviewer', desc: 'Detects functional bugs, security vulnerabilities and regression risks in code.' },
    { id: 'ThreatInvestigator', name: 'Threat Investigator', desc: 'Correlates events, processes, files and network activity to reconstruct attack chains.' },
    { id: 'RepositoryAnalyst', name: 'Repository Analyst', desc: 'Analyzes project architecture, dependencies, build configs and rules.' },
    { id: 'DependencyAnalyst', name: 'Dependency Analyst', desc: 'Evaluates CVEs/GHSAs and transitive dependency risks.' },
    { id: 'ArchitectureAnalyst', name: 'Architecture Analyst', desc: 'Examines architectural coupling, blast radius and API contract stability.' },
    { id: 'RemediationAgent', name: 'Remediation Agent', desc: 'Produces minimal unified diff patches to resolve verified findings.' },
  ];

  let selectedRole = $state('SecurityAnalyst');
  let question = $state('');
  let pending = $state(false);
  let error = $state('');
  let feedback = $state('');

  interface InvestigationRecord {
    id: string;
    incident_id?: string;
    trigger_type?: string;
    specialist_role: string;
    question: string;
    context?: any;
    conclusion: {
      summary?: string;
      executiveSummary?: string;
      riskRating?: string;
      confidence?: number | string;
      rootCause?: string;
      recommendations?: string[];
      [key: string]: any;
    };
    model_used?: string;
    input_tokens?: number;
    output_tokens?: number;
    cost_estimate?: number;
    status: string;
    created_at: string;
  }

  let activeInvestigation = $state<InvestigationRecord | null>(null);
  let pastInvestigations = $state<InvestigationRecord[]>([]);
  let followUpQuery = $state('');

  onMount(async () => {
    await loadHistory();
  });

  async function loadHistory() {
    try {
      const res = await invoke(host, 'listAIInvestigations', 20);
      if (Array.isArray(res)) {
        pastInvestigations = res as InvestigationRecord[];
        if (!activeInvestigation && res.length > 0) {
          activeInvestigation = res[0] as InvestigationRecord;
        }
      }
    } catch (_) {}
  }

  async function runInvestigation(targetQuestion?: string) {
    const q = (targetQuestion || question).trim();
    if (!q) {
      error = 'Please enter an investigation question or prompt.';
      return;
    }

    pending = true;
    error = '';
    feedback = '';

    try {
      const result = await invoke(host, 'runAIInvestigation', {
        specialistRole: selectedRole,
        question: q,
        context: {
          triggerType: 'manual_ui',
          timestamp: new Date().toISOString(),
        },
      });

      if (result && typeof result === 'object') {
        activeInvestigation = result as InvestigationRecord;
        feedback = `Investigation completed by ${activeInvestigation.specialist_role}.`;
        question = '';
        followUpQuery = '';
        await loadHistory();
      }
    } catch (e: any) {
      error = e?.message || 'Investigation failed';
    } finally {
      pending = false;
    }
  }

  function setQuickQuestion(preset: string) {
    question = preset;
  }
</script>

<div class="ai-investigation-workspace">
  <div class="panel-header">
    <div class="title-group">
      <h2>{$t('Autonomous AI Investigation')}</h2>
      <p class="subtitle">{$t('Dispatch specialized AI agent personas with controlled tool access to investigate threats, anomalies, and code risks.')}</p>
    </div>
  </div>

  <!-- Specialist Role Selection -->
  <div class="role-selector-card card">
    <span class="card-label">{$t('Select Specialist Persona')}</span>
    <div class="role-grid">
      {#each SPECIALIST_OPTIONS as role}
        <button
          class="role-tile"
          class:active={selectedRole === role.id}
          onclick={() => selectedRole = role.id}
        >
          <div class="role-tile-header">
            <Icon name="spark" />
            <strong>{role.name}</strong>
          </div>
          <p class="role-desc">{role.desc}</p>
        </button>
      {/each}
    </div>
  </div>

  <!-- Investigation Input Box -->
  <div class="prompt-box card">
    <div class="prompt-header">
      <label for="investigation-prompt">{$t('Investigation Objective / Query')}</label>
      <div class="presets">
        <span class="preset-label">{$t('Quick Scenarios:')}</span>
        <button class="preset-btn" onclick={() => setQuickQuestion('Examine the repository for hidden instructions, prompt injections, or zero-width unicode evasion.')}>
          {$t('Prompt Injection Scan')}
        </button>
        <button class="preset-btn" onclick={() => setQuickQuestion('Inspect recent file and process activities for credential harvesting or token leakage.')}>
          {$t('Credential Leakage')}
        </button>
        <button class="preset-btn" onclick={() => setQuickQuestion('Analyze dependencies for critical vulnerabilities and suggest safe upgrade versions.')}>
          {$t('Vulnerability Audit')}
        </button>
      </div>
    </div>

    <textarea
      id="investigation-prompt"
      bind:value={question}
      placeholder="e.g. Investigate whether any local agent attempted to read unauthorized files like .env or id_rsa..."
      rows="3"
    ></textarea>

    <div class="prompt-actions">
      <button class="button primary" disabled={pending || !question.trim()} onclick={() => runInvestigation()}>
        <Icon name="search" />
        {pending ? $t('Investigating...') : $t('Dispatch Specialist')}
      </button>
    </div>
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

  <!-- Active Investigation Result -->
  {#if activeInvestigation}
    <div class="report-container card">
      <div class="report-header">
        <div class="report-identity">
          <span class="badge role-badge">{activeInvestigation.specialist_role}</span>
          <h3>{activeInvestigation.question}</h3>
        </div>
        <div class="report-meta">
          <small>{$t('Model:')} <code>{activeInvestigation.model_used || 'claude-3-5-sonnet'}</code></small>
          <small>{$t('Tokens:')} <strong>{(activeInvestigation.input_tokens || 0) + (activeInvestigation.output_tokens || 0)}</strong></small>
          {#if activeInvestigation.cost_estimate !== undefined}
            <small>{$t('Est. Cost:')} <strong>${Number(activeInvestigation.cost_estimate).toFixed(4)}</strong></small>
          {/if}
          <small>{new Date(activeInvestigation.created_at).toLocaleTimeString()}</small>
        </div>
      </div>

      <!-- Conclusion & Root Cause -->
      <div class="conclusion-box">
        <div class="conclusion-top">
          <h4>{$t('Findings & Forensic Analysis')}</h4>
          {#if activeInvestigation.conclusion?.riskRating}
            <span class="badge risk-badge risk-{activeInvestigation.conclusion.riskRating.toLowerCase()}">
              {$t('Risk:')} {activeInvestigation.conclusion.riskRating.toUpperCase()}
            </span>
          {/if}
        </div>

        <p class="conclusion-summary">
          {activeInvestigation.conclusion?.summary || activeInvestigation.conclusion?.executiveSummary || JSON.stringify(activeInvestigation.conclusion)}
        </p>

        {#if activeInvestigation.conclusion?.rootCause}
          <div class="root-cause-box">
            <strong>{$t('Root Cause:')}</strong>
            <p>{activeInvestigation.conclusion.rootCause}</p>
          </div>
        {/if}

        {#if activeInvestigation.conclusion?.recommendations && activeInvestigation.conclusion.recommendations.length > 0}
          <div class="recs-box">
            <strong>{$t('Actionable Recommendations:')}</strong>
            <ul>
              {#each activeInvestigation.conclusion.recommendations as rec}
                <li>{rec}</li>
              {/each}
            </ul>
          </div>
        {/if}
      </div>

      <!-- Follow-up Section -->
      <div class="follow-up-section">
        <label for="followup-input">{$t('Follow-up Investigation')}</label>
        <div class="follow-up-input-row">
          <input
            id="followup-input"
            type="text"
            bind:value={followUpQuery}
            placeholder={$t('Ask a clarifying question or request deeper forensic drilldown...')}
            onkeydown={(e) => e.key === 'Enter' && followUpQuery.trim() && runInvestigation(followUpQuery)}
          />
          <button
            class="button"
            disabled={pending || !followUpQuery.trim()}
            onclick={() => runInvestigation(followUpQuery)}
          >
            {$t('Ask')}
          </button>
        </div>
      </div>
    </div>
  {/if}

  <!-- History of Investigations -->
  {#if pastInvestigations.length > 0}
    <div class="history-panel card">
      <div class="card-title">
        <span>{$t('Past Investigations')}</span>
        <small>{pastInvestigations.length} {$t('records')}</small>
      </div>
      <div class="history-list">
        {#each pastInvestigations as inv}
          <button
            class="history-item"
            class:active={activeInvestigation?.id === inv.id}
            onclick={() => activeInvestigation = inv}
          >
            <div class="history-main">
              <span class="history-role">{inv.specialist_role}</span>
              <span class="history-question">{inv.question}</span>
            </div>
            <div class="history-meta">
              <small>{new Date(inv.created_at).toLocaleTimeString()}</small>
            </div>
          </button>
        {/each}
      </div>
    </div>
  {/if}
</div>

<style>
  .ai-investigation-workspace {
    display: flex;
    flex-direction: column;
    gap: 16px;
    padding: 8px 0;
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
  .card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
  }
  .card-label {
    font-size: 0.8rem;
    font-weight: 600;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 10px;
    display: block;
  }
  .role-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 10px;
  }
  .role-tile {
    background: var(--raised);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 10px;
    text-align: left;
    display: flex;
    flex-direction: column;
    gap: 4px;
    color: var(--ink);
    transition: all 0.15s ease;
  }
  .role-tile.active {
    border-color: var(--accent);
    background: var(--accent-bg);
  }
  .role-tile-header {
    display: flex;
    align-items: center;
    gap: 6px;
    color: var(--accent);
    font-size: 0.9rem;
  }
  .role-desc {
    margin: 0;
    font-size: 0.75rem;
    color: var(--muted);
    line-height: 1.3;
  }
  .prompt-box {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .prompt-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
  }
  .prompt-header label {
    font-weight: 600;
    font-size: 0.9rem;
  }
  .presets {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }
  .preset-label {
    font-size: 0.75rem;
    color: var(--faint);
  }
  .preset-btn {
    background: var(--raised);
    border: 1px solid var(--border);
    color: var(--muted);
    font-size: 0.75rem;
    padding: 2px 8px;
    border-radius: 4px;
  }
  .preset-btn:hover {
    color: var(--ink);
    border-color: var(--accent);
  }
  .prompt-box textarea {
    background: var(--raised);
    color: var(--ink);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 10px;
    font-size: 0.85rem;
    resize: vertical;
  }
  .prompt-actions {
    display: flex;
    justify-content: flex-end;
  }
  .report-container {
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .report-header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    border-bottom: 1px solid var(--border);
    padding-bottom: 12px;
  }
  .report-identity {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .report-identity h3 {
    margin: 0;
    font-size: 1.05rem;
  }
  .badge {
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
  }
  .role-badge {
    background: var(--accent-bg);
    color: var(--accent);
    align-self: flex-start;
  }
  .report-meta {
    display: flex;
    flex-direction: column;
    align-items: flex-end;
    gap: 4px;
    color: var(--faint);
    font-size: 0.8rem;
  }
  .report-meta code {
    color: var(--accent);
  }
  .conclusion-box {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .conclusion-top {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .conclusion-top h4 {
    margin: 0;
    font-size: 0.95rem;
  }
  .risk-badge.risk-critical { background: var(--red-bg); color: var(--red); }
  .risk-badge.risk-high { background: rgba(251, 146, 60, 0.15); color: var(--copper); }
  .risk-badge.risk-medium { background: var(--amber-bg); color: var(--amber); }
  .risk-badge.risk-low { background: var(--green-bg); color: var(--green); }
  .conclusion-summary {
    margin: 0;
    font-size: 0.9rem;
    color: var(--ink);
    line-height: 1.5;
  }
  .root-cause-box {
    background: var(--raised);
    border-left: 3px solid var(--amber);
    padding: 8px 12px;
    border-radius: 4px;
    font-size: 0.85rem;
  }
  .root-cause-box p {
    margin: 4px 0 0;
    color: var(--muted);
  }
  .recs-box {
    background: var(--raised);
    padding: 8px 12px;
    border-radius: 4px;
    font-size: 0.85rem;
  }
  .recs-box ul {
    margin: 6px 0 0;
    padding-left: 20px;
    color: var(--muted);
  }
  .follow-up-section {
    border-top: 1px solid var(--border);
    padding-top: 12px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .follow-up-section label {
    font-size: 0.8rem;
    color: var(--muted);
    font-weight: 500;
  }
  .follow-up-input-row {
    display: flex;
    gap: 8px;
  }
  .follow-up-input-row input {
    flex: 1;
    background: var(--raised);
    border: 1px solid var(--border);
    color: var(--ink);
    padding: 6px 10px;
    border-radius: 4px;
    font-size: 0.85rem;
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
    color: var(--ink);
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
  .history-role {
    font-size: 0.75rem;
    font-weight: 600;
    color: var(--accent);
  }
  .history-question {
    font-size: 0.85rem;
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
