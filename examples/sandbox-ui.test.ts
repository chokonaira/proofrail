import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const html = readFileSync(new URL('../site/index.html', import.meta.url), 'utf8');
const css = readFileSync(new URL('../site/styles.css', import.meta.url), 'utf8');
const js = readFileSync(new URL('../site/app.js', import.meta.url), 'utf8');

test('sandbox marks the request editor as intentionally editable', () => {
  assert.match(html, /id="requestHint"/);
  assert.match(html, /id="editorState"/);
  assert.match(html, /Editable request/);
  assert.match(js, /addEventListener\('pointerdown', markEditorEditing\)/);
  assert.match(js, /addEventListener\('click', markEditorEditing\)/);
});

test('mobile sandbox editor prevents iOS input zoom', () => {
  assert.match(css, /@media \(max-width: 720px\)[\s\S]*\.code-editor\s*\{[\s\S]*font-size:\s*16px/);
});

test('sandbox cache-busts public assets for GitHub Pages updates', () => {
  assert.match(html, /styles\.css\?v=2026-06-01/);
  assert.match(html, /app\.js\?v=2026-06-01/);
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
