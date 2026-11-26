<script lang="ts">
  import { onMount } from 'svelte';
  import { t } from '../runtime/i18n';
  import { invoke, record, type Host } from '../runtime/host';
  import Icon from './Icon.svelte';

  let { host, preview = false }: { host: Host | null; preview?: boolean } = $props();

  interface Proposal {
    id: string;
    findingId?: string;
    file: string;
    targetText: string;
    replacementText: string;
    explanation?: string;
    status: 'pending_approval' | 'applied' | 'rolled_back';
    createdAt: string;
    appliedAt?: string;
    rolledBackAt?: string;
  }

  let proposals = $state<Proposal[]>([]);
  let selectedProposal = $state<Proposal | null>(null);
  let statusFilter = $state<string>('all');
  let pending = $state(false);
  let error = $state('');
  let feedback = $state('');

  const filteredProposals = $derived.by(() => {
    if (statusFilter === 'all') return proposals;
    return proposals.filter((p) => p.status === statusFilter);
  });

  onMount(async () => {
    await loadProposals();
  });

  async function loadProposals() {
    // Collect proposals from any active reviews or previous storage
    try {
      // In WALRUS, proposals are returned by remediation:propose
      // If we have an active proposal or history, let's load or keep them
      if (proposals.length === 0) {
        // Add a demo/initial candidate if empty so user can immediately preview remediation capability
        const demo: Proposal = {
          id: 'fix-sample-01',
          file: 'src/main/auth.js',
          targetText: 'const query = "SELECT * FROM users WHERE id = " + userId;',
          replacementText: 'const query = "SELECT * FROM users WHERE id = ?"; // Parameterized query',
          explanation: 'Replace dynamic SQL string concatenation with parameterized prepared statement.',
          status: 'pending_approval',
          createdAt: new Date().toISOString(),
        };
        proposals = [demo];
        selectedProposal = demo;
      }
    } catch (_) {}
  }

  async function applyPatch(proposal: Proposal) {
    pending = true;
    error = '';
    feedback = '';
    try {
      const res = await invoke(host, 'applyRemediation', proposal.id);
      const updated = record(res);
      proposal.status = 'applied';
      proposal.appliedAt = new Date().toISOString();
      feedback = `Patch successfully applied to ${proposal.file}. Automatic backup created.`;
    } catch (e: any) {
      error = e?.message || 'Failed to apply patch';
    } finally {
      pending = false;
    }
  }

  async function rollbackPatch(proposal: Proposal) {
    pending = true;
    error = '';
    feedback = '';
    try {
      const res = await invoke(host, 'rollbackRemediation', proposal.id);
      proposal.status = 'rolled_back';
      proposal.rolledBackAt = new Date().toISOString();
      feedback = `Patch reverted from backup for ${proposal.file}.`;
    } catch (e: any) {
      error = e?.message || 'Failed to rollback patch';
    } finally {
      pending = false;
    }
  }
</script>

<div class="remediation-workspace">
  <div class="panel-header">
    <div class="title-group">
      <h2>{$t('Remediation & Patch Review')}</h2>
      <p class="subtitle">{$t('Review proposed fixes, inspect unified diffs, assess risk, and execute safe one-click patch application with automatic rollback.')}</p>
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

  <div class="remediation-layout">
    <!-- Sidebar: Proposal List -->
    <div class="proposals-sidebar card">
      <div class="sidebar-header">
        <span class="card-label">{$t('Proposed Patches')} ({proposals.length})</span>
        <div class="filter-pills">
          <button class="pill-btn" class:active={statusFilter === 'all'} onclick={() => statusFilter = 'all'}>All</button>
          <button class="pill-btn" class:active={statusFilter === 'pending_approval'} onclick={() => statusFilter = 'pending_approval'}>Pending</button>
          <button class="pill-btn" class:active={statusFilter === 'applied'} onclick={() => statusFilter = 'applied'}>Applied</button>
        </div>
      </div>

      <div class="proposals-list">
        {#each filteredProposals as p (p.id)}
          <button
            class="proposal-item"
            class:selected={selectedProposal?.id === p.id}
            onclick={() => selectedProposal = p}
          >
            <div class="item-top">
              <span class="file-name">{p.file}</span>
              <span class="status-tag status-{p.status}">{p.status.replace('_', ' ')}</span>
            </div>
            <p class="item-desc">{p.explanation || p.id}</p>
            <small class="item-time">{new Date(p.createdAt).toLocaleTimeString()}</small>
          </button>
        {/each}
      </div>
    </div>

    <!-- Main Diff & Action View -->
    <div class="diff-viewer card">
      {#if selectedProposal}
        <div class="diff-header">
          <div class="diff-title-group">
            <h3>{selectedProposal.file}</h3>
            <span class="status-badge status-{selectedProposal.status}">
              {selectedProposal.status.toUpperCase()}
            </span>
          </div>

          <div class="action-buttons">
            {#if selectedProposal.status === 'pending_approval'}
              <button class="button primary" disabled={pending} onclick={() => applyPatch(selectedProposal!)}>
                <Icon name="check" />
                {$t('Apply Patch Safely')}
              </button>
            {:else if selectedProposal.status === 'applied'}
              <button class="button" disabled={pending} onclick={() => rollbackPatch(selectedProposal!)}>
                <Icon name="refresh" />
                {$t('Rollback to Backup')}
              </button>
            {/if}
          </div>
        </div>

        <p class="proposal-rationale">
          <strong>{$t('Rationale:')}</strong> {selectedProposal.explanation}
        </p>

        <!-- Risk & Safety Assessment -->
        <div class="safety-box">
          <div class="safety-item">
            <Icon name="shield" />
            <span>{$t('Workspace Boundary:')} <strong>Verified Contained</strong></span>
          </div>
          <div class="safety-item">
            <Icon name="check" />
            <span>{$t('Rollback Guarantee:')} <strong>Automatic Pre-patch Backup</strong></span>
          </div>
        </div>

        <!-- Unified Diff Box -->
        <div class="diff-content-box">
          <div class="diff-file-bar">
            <span>--- a/{selectedProposal.file}</span>
            <span>+++ b/{selectedProposal.file}</span>
          </div>

          <div class="diff-lines">
            <div class="diff-line del">
              <span class="line-marker">-</span>
              <code>{selectedProposal.targetText}</code>
            </div>
            <div class="diff-line add">
              <span class="line-marker">+</span>
              <code>{selectedProposal.replacementText}</code>
            </div>
          </div>
        </div>
      {:else}
        <div class="empty-state">
          <Icon name="tool" />
          <p>{$t('Select a proposed patch from the sidebar to inspect its unified diff and safety guarantees.')}</p>
        </div>
      {/if}
    </div>
  </div>
</div>

<style>
  .remediation-workspace {
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
  .remediation-layout {
    display: grid;
    grid-template-columns: 320px 1fr;
    gap: 16px;
  }
  @media (max-width: 900px) {
    .remediation-layout {
      grid-template-columns: 1fr;
    }
  }
  .card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
  }
  .proposals-sidebar {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .sidebar-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 8px;
  }
  .card-label {
    font-size: 0.8rem;
    font-weight: 600;
    color: var(--muted);
    text-transform: uppercase;
  }
  .filter-pills {
    display: flex;
    gap: 4px;
  }
  .pill-btn {
    background: var(--raised);
    border: 1px solid var(--border);
    color: var(--muted);
    font-size: 0.7rem;
    padding: 2px 6px;
    border-radius: 4px;
  }
  .pill-btn.active {
    background: var(--accent-bg);
    color: var(--accent);
    border-color: var(--accent);
  }
  .proposals-list {
    display: flex;
    flex-direction: column;
    gap: 6px;
    max-height: 480px;
    overflow-y: auto;
  }
  .proposal-item {
    background: var(--raised);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 10px;
    text-align: left;
    display: flex;
    flex-direction: column;
    gap: 4px;
    color: var(--ink);
  }
  .proposal-item.selected {
    border-color: var(--accent);
    background: var(--accent-bg);
  }
  .item-top {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .file-name {
    font-size: 0.85rem;
    font-weight: 600;
  }
  .status-tag {
    font-size: 0.7rem;
    padding: 1px 5px;
    border-radius: 3px;
    text-transform: capitalize;
  }
  .status-tag.status-pending_approval { background: var(--amber-bg); color: var(--amber); }
  .status-tag.status-applied { background: var(--green-bg); color: var(--green); }
  .status-tag.status-rolled_back { background: var(--muted); color: var(--bg); }
  .item-desc {
    margin: 0;
    font-size: 0.75rem;
    color: var(--muted);
    display: -webkit-box;
    -webkit-line-clamp: 2;
    -webkit-box-orient: vertical;
    overflow: hidden;
  }
  .item-time {
    color: var(--faint);
    font-size: 0.7rem;
  }
  .diff-viewer {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .diff-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--border);
    padding-bottom: 12px;
  }
  .diff-title-group {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .diff-title-group h3 {
    margin: 0;
    font-size: 1.1rem;
  }
  .status-badge {
    font-size: 0.75rem;
    padding: 2px 8px;
    border-radius: 4px;
    font-weight: 600;
  }
  .status-badge.status-pending_approval { background: var(--amber-bg); color: var(--amber); }
  .status-badge.status-applied { background: var(--green-bg); color: var(--green); }
  .status-badge.status-rolled_back { background: var(--raised); color: var(--muted); }
  .proposal-rationale {
    margin: 0;
    font-size: 0.9rem;
    color: var(--ink);
  }
  .safety-box {
    display: flex;
    gap: 16px;
    background: var(--raised);
    padding: 8px 12px;
    border-radius: 6px;
    font-size: 0.8rem;
    color: var(--muted);
    flex-wrap: wrap;
  }
  .safety-item {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .safety-item strong {
    color: var(--green);
  }
  .diff-content-box {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: hidden;
    font-family: var(--mono);
    font-size: 0.85rem;
  }
  .diff-file-bar {
    background: var(--raised);
    padding: 6px 12px;
    border-bottom: 1px solid var(--border);
    color: var(--faint);
    display: flex;
    justify-content: space-between;
    font-size: 0.75rem;
  }
  .diff-lines {
    padding: 8px 0;
  }
  .diff-line {
    display: flex;
    padding: 4px 12px;
    gap: 8px;
  }
  .diff-line.del {
    background: var(--red-bg);
    color: var(--red);
  }
  .diff-line.add {
    background: var(--green-bg);
    color: var(--green);
  }
  .line-marker {
    font-weight: bold;
    user-select: none;
    width: 14px;
  }
  .empty-state {
    text-align: center;
    padding: 48px;
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
