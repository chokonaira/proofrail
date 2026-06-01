import { createPermitRailKeyPair } from '@permitrail/core';
import { PermitRailGateway, InMemoryAuditLog, createPermitRailMcpTools } from '@permitrail/mcp-gateway';
import { LocalApprovalProvider } from '@permitrail/provider-local';

const $ = (id) => document.getElementById(id);
const clone = (v) => JSON.parse(JSON.stringify(v));
const VERSION = '0.1.0';

const policy = {
  version: 'permitrail.policy.v1',
  id: 'sandbox',
  defaults: { unconfiguredTool: 'deny' },
  tools: {
    'email.send': {
      id: 'email-send',
      risk: 'medium',
      require: { claim: 'human.approved_action', value: true, assurance: ['human_approved'], maxAgeSeconds: 300, bindActionInputHash: true },
    },
    'payments.create_transfer': {
      id: 'payments-transfer',
      risk: 'high',
      require: { claim: 'human.approved_spend', value: true, assurance: ['human_approved'], maxAgeSeconds: 120, bindActionInputHash: true },
    },
    'database.delete_rows': {
      id: 'delete-rows',
      risk: 'high',
      require: { claim: 'admin.approved_action', value: true, assurance: ['human_approved'], bindActionInputHash: true },
    },
  },
};

const PRESETS = [
  {
    id: 'email',
    label: 'email.send',
    action: {
      tool: 'email.send',
      audience: 'sales-agent',
      subject: 'user_henry',
      purpose: 'Send invoice INV-123 to client@example.com',
      input: { to: 'client@example.com', subject: 'Invoice INV-123', attachment: 'inv-123.pdf' },
    },
  },
  {
    id: 'payment',
    label: 'payments.create_transfer',
    action: {
      tool: 'payments.create_transfer',
      audience: 'finance-agent',
      subject: 'user_henry',
      purpose: 'Transfer 5,000 USD to acct_new_vendor from an untrusted email',
      input: { amount: 5000, currency: 'USD', recipient: 'acct_new_vendor' },
    },
  },
  {
    id: 'database',
    label: 'database.delete_rows',
    action: {
      tool: 'database.delete_rows',
      audience: 'db-agent',
      subject: 'admin_1',
      purpose: 'Delete 1,204 expired rows from the events table',
      input: { table: 'events', where: { expired: true } },
    },
  },
  {
    id: 'blank',
    label: 'blank',
    action: {
      tool: 'your.tool',
      audience: 'my-agent',
      subject: 'user_123',
      purpose: 'Describe exactly what this action does',
      input: {},
    },
  },
];

const toolResults = {
  'email.send': { delivered: true, messageId: 'msg_8f21c' },
  'payments.create_transfer': { transferId: 'txn_sandbox_only', status: 'would_submit' },
  'database.delete_rows': { deleted: 1204 },
};

let gateway;
let provider;
let mcp;
let challenge = null;
let proof = null;
let tamperedProof = null;
let tampered = false;
let lastAction = null;
let callCount = 0;
let ready = false;
let busy = false;
let runMode = 'ready';
const mobileFlow = window.matchMedia('(max-width: 860px)');
const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const runLabels = {
  ready: 'Run policy check',
  checking: 'Checking policy...',
  approval: 'Awaiting approval',
  execute: 'Proof ready',
  receipt: 'Edit request to rerun',
  working: 'Working...',
};

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
  mcp = createPermitRailMcpTools({ gateway, provider });

  $('engineDot').classList.add('ready');
  $('engineState').textContent = 'signing engine ready';
  $('engineDot2').classList.add('ready');
  $('liveLabel').textContent = `@permitrail/core@${VERSION}`;

  renderPresets();
  loadPreset(0);
  ready = true;
  setRunMode('ready');
}

// Every call runs through here so the console shows an in-flight state.
// The spinner reads as a real request; the latency badge still reports the
// true compute time measured around the call itself.
async function withBusy(fn, busyLabel = 'working') {
  if (busy) return;
  busy = true;
  setBusy(true, busyLabel);
  await sleep(busyLabel === 'checking' ? 260 : 180);
  try {
    await fn();
  } finally {
    busy = false;
    setBusy(false);
  }
}

function setBusy(on, busyLabel = 'working') {
  if (on) {
    $('spinner').removeAttribute('hidden');
    setStatus('running', 'running', null);
  } else {
    $('spinner').setAttribute('hidden', '');
  }
  const run = $('runBtn');
  run.disabled = on || !ready || runMode !== 'ready';
  run.textContent = on ? runLabels[busyLabel] : runLabels[runMode];
  for (const b of document.querySelectorAll('.call-btn')) b.disabled = on;
}

function setRunMode(mode) {
  runMode = mode;
  const run = $('runBtn');
  run.dataset.mode = mode;
  run.textContent = runLabels[mode];
  run.disabled = busy || !ready || mode !== 'ready';
}

function setEditorState(text, state) {
  const el = $('editorState');
  el.textContent = text;
  el.dataset.state = state;
}

function setFlowStep(step) {
  for (const el of document.querySelectorAll('.flow-step')) {
    const active = el.dataset.step === step;
    el.dataset.state = active ? 'active' : '';
    el.setAttribute('aria-current', active ? 'step' : 'false');
  }
}

function focusStep(step) {
  setFlowStep(step);
  const target =
    step === 'approval' ? $('callActions') :
    step === 'receipt' ? $('resBody') :
    step === 'policy' ? $('statusPill') :
    $('reqBody');
  if (!target) return;
  pulseTarget(target);
  if (mobileFlow.matches) {
    const behavior = reducedMotion.matches ? 'auto' : 'smooth';
    requestAnimationFrame(() => target.scrollIntoView({ behavior, block: 'center' }));
  }
}

function pulseTarget(target) {
  target.classList.remove('focus-pulse');
  void target.offsetWidth;
  target.classList.add('focus-pulse');
}

function renderPresets() {
  const host = $('presets');
  host.innerHTML = '';
  PRESETS.forEach((p, i) => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'preset';
    btn.textContent = p.label;
    btn.setAttribute('aria-selected', 'false');
    btn.addEventListener('click', () => loadPreset(i, btn));
    host.appendChild(btn);
  });
}

function loadPreset(i, btn) {
  for (const el of document.querySelectorAll('.preset')) el.setAttribute('aria-selected', 'false');
  const target = btn || document.querySelectorAll('.preset')[i];
  if (target) target.setAttribute('aria-selected', 'true');
  $('reqBody').value = JSON.stringify(PRESETS[i].action, null, 2);
  resetCall();
}

function resetCall() {
  challenge = null;
  proof = null;
  tamperedProof = null;
  tampered = false;
  lastAction = null;
  hide('reqError');
  setStatus('idle', 'idle', null);
  setActions([]);
  setRunMode('ready');
  setFlowStep('request');
  setEditorState('ready to edit', 'ready');
  showCode($('resBody'), '// run a call to see the real response from the package');
  showCode($('eqCode'), '// the call you run shows up here');
}

function parseRequest() {
  let parsed;
  try {
    parsed = JSON.parse($('reqBody').value);
  } catch (error) {
    return showReqError(`Invalid JSON: ${error.message}`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return showReqError('The request must be a JSON object.');
  if (!parsed.tool || !parsed.audience || !parsed.subject || !parsed.purpose) {
    return showReqError('Include at least tool, audience, subject, and purpose.');
  }
  hide('reqError');
  return parsed;
}

function showReqError(message) {
  const el = $('reqError');
  el.textContent = message;
  el.removeAttribute('hidden');
  return null;
}

async function timed(fn) {
  const t0 = performance.now();
  const r = await fn();
  return { r, ms: performance.now() - t0 };
}

/* ---- calls (each one hits the real package) ---- */

async function runAuthorize() {
  const action = parseRequest();
  if (!action) return;
  lastAction = action;
  challenge = null;
  proof = null;
  tampered = false;

  try {
    setFlowStep('policy');
    const { r: decision, ms } = await timed(() => mcp.callTool('permitrail_authorize_tool_call', { action }));
    const kind = decision.outcome === 'allow' ? 'allow' : decision.outcome === 'require_proof' ? 'pending' : 'deny';
    setStatus(kind, decision.outcome, ms);
    showJson($('resBody'), decision);
    logCall('permitrail_authorize_tool_call', decision.outcome, ms, kind);
    showCode($('eqCode'), `// MCP tool: permitrail_authorize_tool_call\nconst decision = await gateway.authorize(action);\n// decision.outcome === "${decision.outcome}"`);

    if (decision.outcome === 'require_proof' && decision.challenge) {
      challenge = decision.challenge;
      setRunMode('approval');
      setActions([actApprove(), actDeny()]);
      focusStep('approval');
    } else if (decision.outcome === 'allow') {
      setRunMode('execute');
      setActions([actExecute()]);
      focusStep('approval');
    } else {
      setRunMode('receipt');
      setActions([]);
      focusStep('receipt');
    }
  } catch (error) {
    failResponse(error);
  }
}

async function approve() {
  if (!challenge) return;
  try {
    const { r: signed, ms } = await timed(() => provider.approve(challenge.id, { approvedBy: 'you@sandbox' }));
    proof = signed;
    tampered = false;
    setStatus('allow', 'proof issued', ms);
    showJson($('resBody'), signed);
    logCall('approval channel · signs proof', 'proof issued', ms, 'allow');
    showCode($('eqCode'), `// your approval channel signs a short-lived proof\nconst proof = await provider.approve(decision.challenge.id);`);
    setRunMode('execute');
    setActions([actExecute(), actVerify(), actTamper()]);
    focusStep('approval');
  } catch (error) {
    failResponse(error);
  }
}

async function deny() {
  if (!challenge) return;
  try {
    const { r: receipt, ms } = await timed(() => provider.deny(challenge.id, { reason: 'User rejected this action.' }));
    setStatus('deny', 'denied', ms);
    showJson($('resBody'), receipt);
    logCall('approval channel · deny', 'denied', ms, 'deny');
    showCode($('eqCode'), `const receipt = await provider.deny(decision.challenge.id, { reason });`);
    setRunMode('receipt');
    setActions([]);
    focusStep('receipt');
  } catch (error) {
    failResponse(error);
  }
}

async function execute() {
  if (!proof || !lastAction) return;
  try {
    const { r: result, ms } = await timed(() =>
      gateway.execute(lastAction, () => toolResults[lastAction.tool] ?? { ran: true }, { proofEnvelope: proof }),
    );
    if (result.ok) {
      setStatus('allow', 'allowed · receipt signed', ms);
      showJson($('resBody'), { ok: true, result: result.result, receipt: result.receipt });
      logCall('gateway.execute', 'allowed', ms, 'allow');
      showCode($('eqCode'), `const { ok, receipt } = await gateway.execute(action, runTool, {\n  proofEnvelope: proof,\n});`);
      setRunMode('receipt');
      setActions([actReplay(), actVerify(), actTamper()]);
      focusStep('receipt');
    }
  } catch (error) {
    failResponse(error);
  }
}

async function replay() {
  if (!proof || !lastAction) return;
  try {
    const { r: result, ms } = await timed(() =>
      gateway.execute(lastAction, () => toolResults[lastAction.tool] ?? { ran: true }, { proofEnvelope: proof }),
    );
    setStatus('deny', 'replay blocked', ms);
    showJson($('resBody'), { ok: result.ok, reason: result.receipt.payload.reason, receipt: result.receipt });
    logCall('gateway.execute · replay', 'replay blocked', ms, 'deny');
    showCode($('eqCode'), `// same proof, second time -> refused (single-use)`);
    setRunMode('receipt');
    setActions([actVerify(), actTamper()]);
    focusStep('receipt');
  } catch (error) {
    failResponse(error);
  }
}

async function verify() {
  if (!proof) return;
  const envelope = tampered ? tamperedProof : proof;
  try {
    const { r: res, ms } = await timed(() => mcp.callTool('permitrail_verify_proof', { proofEnvelope: envelope }));
    setStatus(res.ok ? 'allow' : 'deny', res.ok ? 'verified' : 'verification failed', ms);
    showJson($('resBody'), res);
    logCall('permitrail_verify_proof', res.ok ? 'ok' : 'failed', ms, res.ok ? 'allow' : 'deny');
    showCode($('eqCode'), `// MCP tool: permitrail_verify_proof\nconst result = await verifyProof(proofEnvelope, { publicKeyPem });\n// result.ok === ${res.ok}`);
    focusStep('receipt');
  } catch (error) {
    failResponse(error);
  }
}

async function toggleTamper() {
  if (!proof) return;
  tampered = !tampered;
  if (tampered) {
    tamperedProof = clone(proof);
    const sig = tamperedProof.signature || '';
    tamperedProof.signature = (sig[0] === 'A' ? 'B' : 'A') + sig.slice(1);
  }
  // refresh the tamper button label, then run a real verify so the effect is visible
  const actions = [...$('callActions').querySelectorAll('.call-btn')].map((b) => b.dataset.act);
  rebuildActions(actions);
  await verify();
}

function failResponse(error) {
  setStatus('deny', 'error', null);
  showJson($('resBody'), { error: String(error && error.message ? error.message : error) });
  setRunMode('ready');
  focusStep('receipt');
}

/* ---- contextual call buttons ---- */

function actApprove() { return { act: 'approve', label: 'Approve', cls: 'approve', fn: approve }; }
function actDeny() { return { act: 'deny', label: 'Deny', cls: 'deny', fn: deny }; }
function actExecute() { return { act: 'execute', label: 'Execute tool', cls: 'go', fn: execute }; }
function actReplay() { return { act: 'replay', label: 'Replay proof', cls: 'replay', fn: replay }; }
function actVerify() { return { act: 'verify', label: 'Verify proof', cls: '', fn: verify }; }
function actTamper() { return { act: 'tamper', label: tampered ? 'Restore proof' : 'Tamper', cls: tampered ? 'tamper on' : 'tamper', fn: toggleTamper }; }

const ACTIONS = {
  approve: actApprove, deny: actDeny, execute: actExecute, replay: actReplay, verify: actVerify, tamper: actTamper,
};

function rebuildActions(actKeys) {
  setActions(actKeys.map((k) => ACTIONS[k]()));
}

function setActions(list) {
  const host = $('callActions');
  host.innerHTML = '';
  host.dataset.state = list.length ? 'active' : 'empty';
  for (const a of list) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = `call-btn ${a.cls}`.trim();
    btn.dataset.act = a.act;
    btn.textContent = a.label;
    btn.addEventListener('click', () => withBusy(a.fn));
    host.appendChild(btn);
  }
  if (list.length) pulseTarget(host);
}

/* ---- response + status + log ---- */

function setStatus(kind, text, ms) {
  const pill = $('statusPill');
  pill.dataset.kind = kind;
  pill.textContent = text;
  $('latency').textContent = ms == null ? '' : `${ms.toFixed(1)} ms`;
  pulseTarget(pill);
}

function logCall(tool, status, ms, kind) {
  const list = $('callLog');
  const empty = list.querySelector('.cw-empty');
  if (empty) empty.remove();
  callCount += 1;
  const row = document.createElement('div');
  row.className = 'log-row';
  row.innerHTML =
    `<span class="lg-tool">${escapeHtml(tool)}</span>` +
    `<span class="lg-status" data-kind="${kind}">${escapeHtml(status)}</span>` +
    `<span class="lg-ms">${ms.toFixed(1)} ms</span>`;
  list.prepend(row);
  $('logCount').textContent = `${callCount} call${callCount === 1 ? '' : 's'}`;
}

/* ---- rendering helpers ---- */

function show(id) { $(id).removeAttribute('hidden'); }
function hide(id) { $(id).setAttribute('hidden', ''); }

function escapeHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function showCode(el, text) {
  const code = el.querySelector('code') || el;
  code.textContent = text;
}

function showJson(el, obj) {
  const text = JSON.stringify(obj, null, 2);
  el.querySelector('code').innerHTML = highlight(text);
}

function highlight(input) {
  const escaped = escapeHtml(input);
  return escaped.replace(
    /("(?:\\.|[^"\\])*")(\s*:)?|\b(?:true|false|null)\b|-?\d+(?:\.\d+)?/g,
    (match, str, colon) => {
      if (str) return colon ? `<span class="k">${str}</span>${colon}` : `<span class="s">${str}</span>`;
      return `<span class="n">${match}</span>`;
    },
  );
}

/* ---- copy buttons ---- */

async function copyText(text, target) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Fallback for sandboxed iframes and contexts without the async clipboard:
    // select the source and copy via the legacy command on the click gesture.
    try {
      const range = document.createRange();
      range.selectNodeContents(target);
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
      const ok = document.execCommand('copy');
      sel.removeAllRanges();
      return ok;
    } catch {
      return false;
    }
  }
}

for (const btn of document.querySelectorAll('.copy-btn')) {
  btn.addEventListener('click', async () => {
    const target = document.getElementById(btn.dataset.copyTarget);
    if (!target) return;
    await copyText(target.textContent.trim(), target);
    btn.textContent = 'copied';
    btn.dataset.copied = 'true';
    setTimeout(() => {
      btn.textContent = 'copy';
      btn.removeAttribute('data-copied');
    }, 1300);
  });
}

function markEditorEditing() {
  document.querySelector('.cw-req')?.classList.add('is-editing');
  setEditorState('editing', 'editing');
}

$('reqBody').addEventListener('pointerdown', markEditorEditing);
$('reqBody').addEventListener('click', markEditorEditing);
$('reqBody').addEventListener('focus', markEditorEditing);

$('reqBody').addEventListener('blur', () => {
  document.querySelector('.cw-req')?.classList.remove('is-editing');
  if (runMode === 'ready') setEditorState('ready to run', 'ready');
});

$('reqBody').addEventListener('input', () => {
  resetCall();
  setEditorState('edited · run policy check', 'edited');
});

$('runBtn').addEventListener('click', () => withBusy(runAuthorize, 'checking'));

init().catch((error) => {
  $('engineState').textContent = `engine error: ${error.message}`;
  $('liveLabel').textContent = 'engine error';
});
