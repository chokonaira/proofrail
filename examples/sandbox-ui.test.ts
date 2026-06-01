import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const html = readFileSync(new URL('../site/index.html', import.meta.url), 'utf8');
const css = readFileSync(new URL('../site/styles.css', import.meta.url), 'utf8');
const js = readFileSync(new URL('../site/app.js', import.meta.url), 'utf8');

test('sandbox marks the request editor as intentionally editable', () => {
  assert.match(html, /id="requestHint"/);
  assert.match(html, /id="editorState"/);
  assert.match(html, /Edit this exact request/);
  assert.match(js, /addEventListener\('pointerdown', markEditorEditing\)/);
  assert.match(js, /addEventListener\('click', markEditorEditing\)/);
});

test('sandbox explains that preset chips are example scenarios', () => {
  assert.match(html, /Example requests/);
  assert.match(html, /Start with a scenario or paste any agent tool call/);
  assert.match(js, /label: 'Send invoice email'/);
  assert.match(js, /label: 'Create payment transfer'/);
  assert.match(js, /label: 'Delete database rows'/);
  assert.match(js, /label: 'Custom request'/);
  assert.match(js, /aria-pressed/);
});

test('sandbox dark controls are readable without hover', () => {
  const activeFlowRule = css.match(/\.flow-step\[data-state="active"\]\s*\{([^}]*)\}/)?.[1] ?? '';

  assert.match(css, /\.preset\s*\{[\s\S]*color:\s*var\(--d-text\)/);
  assert.match(css, /\.mcp-config > summary\s*\{[\s\S]*color:\s*#e6edf3/);
  assert.match(css, /\.request-guide\s*\{[\s\S]*border:\s*1px solid rgba\(88, 166, 255, 0\.48\)/);
  assert.match(activeFlowRule, /color:\s*var\(--ink\)/);
});

test('mobile sandbox editor prevents iOS input zoom', () => {
  assert.match(css, /@media \(max-width: 720px\)[\s\S]*\.code-editor\s*\{[\s\S]*font-size:\s*16px/);
});

test('sandbox cache-busts public assets for GitHub Pages updates', () => {
  assert.match(html, /styles\.css\?v=2026-06-02-scenarios/);
  assert.match(html, /app\.js\?v=2026-06-02-scenarios/);
});

test('sandbox guides the user through run, approval, and receipt states', () => {
  assert.match(js, /function setRunMode/);
  assert.match(js, /function focusStep/);
  assert.match(js, /prefers-reduced-motion: reduce/);
  assert.match(css, /@media \(prefers-reduced-motion: reduce\)/);
  assert.match(js, /setRunMode\('approval'\)/);
  assert.match(js, /focusStep\('approval'\)/);
  assert.match(js, /focusStep\('receipt'\)/);
});
