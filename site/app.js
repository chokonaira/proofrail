import { createPermitRailKeyPair } from '@permitrail/core';
import { PermitRailGateway, InMemoryAuditLog } from '@permitrail/mcp-gateway';
import { LocalApprovalProvider } from '@permitrail/provider-local';

const $ = (id) => document.getElementById(id);

const policy = {
  version: 'permitrail.policy.v1',
  id: 'sandbox',
  defaults: { unconfiguredTool: 'deny' },
  tools: {
    'email.send': {
      id: 'email-send',
      risk: 'medium',
      require: {
        claim: 'human.approved_action',
        value: true,
        assurance: ['human_approved'],
        maxAgeSeconds: 300,
        bindActionInputHash: true,
      },
    },
    'payments.create_transfer': {
      id: 'payments-transfer',
      risk: 'high',
      require: {
        claim: 'human.approved_spend',
        value: true,
        assurance: ['human_approved'],
        maxAgeSeconds: 120,
        bindActionInputHash: true,
      },
    },
    'database.delete_rows': {
      id: 'delete-rows',
      risk: 'high',
      require: {
        claim: 'admin.approved_action',
        value: true,
        assurance: ['human_approved'],
        bindActionInputHash: true,
      },
    },
  },
};

const scenarios = {
  email: {
    glyph: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="16" x="2" y="4" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>',
    title: 'Approve a customer invoice email',
    sub: 'Medium risk · external message',
    summary: 'The sales agent wants to email invoice INV-123 to an existing customer.',
    recommendation: 'approve if the recipient and invoice match',
    recommendedDecision: 'approve',
    approveLabel: 'Approve invoice email',
    denyLabel: 'Deny email send',
    action: {
      tool: 'email.send',
      audience: 'sales-agent',
      subject: 'user_henry',
      purpose: 'Send invoice INV-123 to client@example.com',
      risk: 'medium',
      chainId: 'chain_sandbox',
      input: { to: 'client@example.com', subject: 'Invoice INV-123', attachment: 'inv-123.pdf' },
    },
  },
  payment: {
    glyph: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="12" x="2" y="6" rx="2"/><circle cx="12" cy="12" r="2"/><path d="M6 12h.01M18 12h.01"/></svg>',
    title: 'Reject a suspicious payment request',
    sub: 'High risk · money movement',
    summary: 'An untrusted email tells the finance agent to send 5,000 USD to a new account.',
    recommendation: 'deny because the recipient is not verified',
    recommendedDecision: 'deny',
    approveLabel: 'Approve transfer anyway',
    denyLabel: 'Deny suspicious transfer',
    action: {
      tool: 'payments.create_transfer',
      audience: 'finance-agent',
      subject: 'user_henry',
      purpose: 'Transfer 5,000 USD to acct_new_vendor from an untrusted email',
      risk: 'high',
      chainId: 'chain_sandbox',
      input: { amount: 5000, currency: 'USD', recipient: 'acct_new_vendor', source: 'untrusted_email' },
    },
  },
  delete: {
    glyph: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5V19A9 3 0 0 0 21 19V5"/><path d="M3 12A9 3 0 0 0 21 12"/></svg>',
    title: 'Approve a production cleanup',
    sub: 'High risk · database mutation',
    summary: 'An ops agent wants to delete expired rows after an admin reviewed the exact filter.',
    recommendation: 'approve only after checking the table and filter',
    recommendedDecision: 'approve',
    approveLabel: 'Approve cleanup',
    denyLabel: 'Deny deletion',
    action: {
      tool: 'database.delete_rows',
      audience: 'db-agent',
      subject: 'admin_1',
      purpose: 'Delete 1,204 expired rows from the events table',
      risk: 'high',
      chainId: 'chain_sandbox',
      input: { table: 'events', where: { expired: true } },
    },
  },
};

const toolResults = {
  'email.send': { simulated: true, delivered: true, messageId: 'msg_8f21c' },
  'payments.create_transfer': { simulated: true, transferId: 'txn_sandbox_only', status: 'would_submit' },
  'database.delete_rows': { simulated: true, deleted: 1204 },
};

let gateway;
let provider;
let current = null;
let challenge = null;
let proof = null;

async function init() {
  provider = await LocalApprovalProvider.create();
  const receiptKeyPair = await createPermitRailKeyPair({ kid: 'sandbox-receipts' });
  gateway = new PermitRailGateway({
    policy,
    provider,
    trustedProofKeys: [provider.publicKeyPem],
    receiptKeyPair,
    auditSink: new InMemoryAuditLog(),
  });

  $('engineDot').classList.add('ready');
  $('engineState').textContent = 'signing engine ready';
  renderScenarios();
}

function renderScenarios() {
  const host = $('scenarios');
  host.innerHTML = '';
  let firstButton = null;
  for (const [key, scn] of Object.entries(scenarios)) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'scn';
    btn.setAttribute('aria-selected', 'false');
    btn.innerHTML =
      `<span class="glyph">${scn.glyph}</span>` +
      `<span class="scn-copy"><span class="scn-title">${scn.title}</span><span class="scn-sub">${scn.sub}</span></span>` +
      `<span class="scn-decision" data-decision="${scn.recommendedDecision}">${scn.recommendedDecision}</span>`;
    btn.addEventListener('click', () => selectScenario(key, btn));
    host.appendChild(btn);
    firstButton ??= btn;
  }
  if (firstButton) selectScenario('email', firstButton);
}

function selectScenario(key, btn) {
  current = key;
  challenge = null;
  proof = null;
  for (const el of document.querySelectorAll('.scn')) el.setAttribute('aria-selected', 'false');
  btn.setAttribute('aria-selected', 'true');

  const scenario = scenarios[key];
  const { action } = scenario;
  $('acTool').textContent = action.tool;
  const risk = $('acRisk');
  risk.textContent = action.risk;
  risk.dataset.risk = action.risk;
  $('acSummary').textContent = scenario.summary;
  $('acRecommendation').textContent = scenario.recommendation;
  $('acPurpose').textContent = action.purpose;
  showJson($('acInput'), action.input);
  $('inputDetails').open = !isSmallScreen();
  $('approveBtn').textContent = scenario.approveLabel;
  $('denyBtn').textContent = scenario.denyLabel;
  $('approveBtn').dataset.recommended = scenario.recommendedDecision === 'approve' ? 'true' : 'false';
  $('denyBtn').dataset.recommended = scenario.recommendedDecision === 'deny' ? 'true' : 'false';

  resetRail();
  setVerdict('idle', 'ready');
  note('readoutHint', 'run the check to begin');
  showJson($('output'), 'Run the check to see whether this action needs approval.', true);
  const run = $('runBtn');
  run.disabled = false;
  run.textContent = 'Check this action';
  hide('approveActions');
  hide('executeActions');
  $('executeBtn').removeAttribute('hidden');
  hide('replayBtn');
}

async function run() {
  if (!current) return;
  const { action } = scenarios[current];
  $('runBtn').disabled = true;
  setStage('authorize', 'active');

  const decision = await gateway.authorize(action);
  setVerdict(decision.outcome, decision.outcome.replace('_', ' '));

  if (decision.outcome === 'require_proof' && decision.challenge) {
    challenge = decision.challenge;
    setStage('authorize', 'done');
    setStage('approve', 'active');
    note('st-authorize', 'policy says this action needs approval');
    note('readoutHint', 'approve or reject it below');
    showJson($('output'), {
      decision: decision.outcome,
      reason: decision.reason,
      policyId: decision.policyId,
      challenge: challenge.id,
      requires: challenge.request.claim,
      next: scenarios[current].recommendation,
    });
    show('approveActions');
    focusStep('approve');
  } else if (decision.outcome === 'allow') {
    setStage('authorize', 'done');
    setStage('approve', 'done');
    setStage('execute', 'active');
    show('executeActions');
    focusStep('execute');
  } else {
    setStage('authorize', 'blocked');
    showJson($('output'), { decision: decision.outcome, reason: decision.reason });
    focusOutput();
  }
}

async function approve() {
  if (!challenge) return;
  proof = await provider.approve(challenge.id, { approvedBy: 'you@sandbox' });
  setStage('approve', 'done');
  setStage('execute', 'active');
  note('st-approve', 'approved, a signed proof was issued for this exact request');
  note('readoutHint', 'now run it once');
  hide('approveActions');
  showJson($('output'), proofView(proof));
  show('executeActions');
  focusStep('execute');
}

async function deny() {
  if (!challenge) return;
  const receipt = await provider.deny(challenge.id, { reason: 'User rejected this action.' });
  setStage('approve', 'blocked');
  setVerdict('blocked', 'blocked');
  note('st-approve', 'rejected, a signed receipt was saved');
  note('readoutHint', 'rejected and recorded');
  hide('approveActions');
  showJson($('output'), receiptView(receipt));
  addReceipt(receipt);
  focusOutput();
}

async function execute() {
  if (!current || !proof) return;
  const { action } = scenarios[current];
  const result = await gateway.execute(action, () => toolResults[action.tool], { proofEnvelope: proof });

  if (result.ok) {
    setStage('execute', 'done');
    setVerdict('allowed', 'allowed');
    note('st-execute', 'the action ran once and a signed receipt was saved');
    note('readoutHint', 'now try reusing the same proof');
    showJson($('output'), { result: result.result, receipt: receiptView(result.receipt) });
    addReceipt(result.receipt);
    $('executeBtn').setAttribute('hidden', '');
    show('replayBtn');
    focusOutput();
  }
}

async function replay() {
  if (!current || !proof) return;
  const { action } = scenarios[current];
  const result = await gateway.execute(action, () => toolResults[action.tool], { proofEnvelope: proof });

  setStage('execute', 'blocked');
  setVerdict('blocked', 'replay blocked');
  note('st-execute', 'same proof, second time: refused');
  note('readoutHint', 'blocked, each proof works only once');
  showJson($('output'), { ok: result.ok, reason: result.receipt.payload.reason, receipt: receiptView(result.receipt) });
  addReceipt(result.receipt);
  $('replayBtn').setAttribute('hidden', '');
  focusOutput();
}

/* ---- view helpers ---- */

function trunc(value, max = 24) {
  return typeof value === 'string' && value.length > max ? `${value.slice(0, max)}…` : value;
}

function proofView(envelope) {
  const p = envelope.payload;
  return {
    kind: p.kind,
    claim: p.claim,
    value: p.value,
    subject: p.subject,
    audience: p.audience,
    purpose: p.purpose,
    assurance: p.assurance,
    actionInputHash: trunc(p.actionInputHash, 30),
    expiresAt: p.expiresAt,
    signature: `ed25519:${trunc(envelope.signature, 44)}`,
  };
}

function receiptView(envelope) {
  const p = envelope.payload;
  return {
    kind: p.kind,
    id: p.id,
    decision: p.decision,
    reason: p.reason,
    inputHash: trunc(p.inputHash, 30),
    chainId: p.chainId,
    signature: `ed25519:${trunc(envelope.signature, 44)}`,
  };
}

let receiptCount = 0;
function addReceipt(envelope) {
  const p = envelope.payload;
  const list = $('auditList');
  const empty = list.querySelector('.empty');
  if (empty) empty.remove();
  const allowed = p.decision === 'allowed';
  const row = document.createElement('div');
  row.className = `receipt ${allowed ? 'allowed' : 'denied'}`;
  row.innerHTML =
    `<span class="pill"></span>` +
    `<span class="rid">${p.id} · <span class="rhash">${trunc(p.inputHash ?? 'no-input', 22)}</span></span>` +
    `<span class="rdec">${p.decision}</span>`;
  list.prepend(row);
  receiptCount += 1;
  $('auditCount').textContent = `${receiptCount} receipt${receiptCount === 1 ? '' : 's'}`;
}

function setStage(name, status) {
  const el = document.querySelector(`.stage[data-stage="${name}"]`);
  if (el) el.dataset.status = status;
}

function resetRail() {
  for (const el of document.querySelectorAll('.stage')) el.removeAttribute('data-status');
  note('st-authorize', 'PermitRail checks this action against the policy');
  note('st-approve', 'a person approves or rejects the exact request');
  note('st-execute', 'the action runs once, then a signed receipt is saved');
}

function note(id, text) {
  const el = $(id);
  if (el) el.textContent = text;
}

function setVerdict(state, text) {
  const v = $('verdict');
  v.dataset.state = state;
  $('verdictValue').textContent = text;
}

function show(id) {
  $(id).removeAttribute('hidden');
}
function hide(id) {
  $(id).setAttribute('hidden', '');
}

function isSmallScreen() {
  return window.matchMedia('(max-width: 720px)').matches;
}

function focusStep(stage) {
  if (!isSmallScreen()) return;
  document.querySelector(`.stage[data-stage="${stage}"]`)?.scrollIntoView({
    behavior: 'smooth',
    block: 'center',
  });
}

function focusOutput() {
  if (!isSmallScreen()) return;
  $('output').scrollIntoView({ behavior: 'smooth', block: 'center' });
}

function showJson(el, obj, raw = false) {
  const text = raw && typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
  el.querySelector('code').innerHTML = highlight(text);
}

function highlight(input) {
  const escaped = input.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return escaped.replace(
    /("(?:\\.|[^"\\])*")(\s*:)?|\b(?:true|false|null)\b|-?\d+(?:\.\d+)?/g,
    (match, str, colon) => {
      if (str) return colon ? `<span class="k">${str}</span>${colon}` : `<span class="s">${str}</span>`;
      return `<span class="n">${match}</span>`;
    },
  );
}

$('runBtn').addEventListener('click', run);
$('approveBtn').addEventListener('click', approve);
$('denyBtn').addEventListener('click', deny);
$('executeBtn').addEventListener('click', execute);
$('replayBtn').addEventListener('click', replay);

init().catch((error) => {
  $('engineState').textContent = `engine error: ${error.message}`;
});
