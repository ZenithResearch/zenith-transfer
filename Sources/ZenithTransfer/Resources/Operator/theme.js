/* Shared monitor appearance. Load synchronously in <head> before page styles. */
(function(root) {
  'use strict';
  if (root.DevgraphTheme) return;

  const document = root.document;
  const storageKey = 'devgraph.theme.v1';
  const modes = Object.freeze(['system', 'light', 'dark', 'aqua']);
  const boundPickers = new WeakSet();
  let storage = null, media = null, preference = 'system', theme = null;
  let persisted = true;

  const valid = value => typeof value === 'string' && modes.includes(value);
  try {
    storage = root.localStorage;
    if (!storage) persisted = false;
    else {
      const saved = storage.getItem(storageKey);
      if (valid(saved)) preference = saved;
    }
  } catch { persisted = false; }
  try { media = root.matchMedia('(prefers-color-scheme: dark)'); } catch { /* Light fallback. */ }

  function getState() { return {preference, theme, persisted}; }
  function statusText() {
    const title = value => value[0].toUpperCase() + value.slice(1);
    const label = preference === 'system' ? `System (${title(theme)})` : title(preference);
    return `Theme: ${label}${persisted ? '' : ' — only this visit (could not save preference).'}`;
  }
  function syncControls() {
    for (const picker of document.querySelectorAll('select[data-theme-picker]')) {
      if (picker.value !== preference) picker.value = preference;
    }
    for (const status of document.querySelectorAll('[data-theme-status]')) {
      status.setAttribute('role', 'status');
      status.setAttribute('aria-live', 'polite');
      status.setAttribute('aria-atomic', 'true');
      const message = statusText();
      if (status.textContent !== message) status.textContent = message;
    }
  }
  function apply(next, source) {
    const resolved = next === 'system' ? (media?.matches ? 'dark' : 'light') : next;
    const changed = preference !== next || theme !== resolved;
    preference = next;
    theme = resolved;
    document.documentElement.dataset.theme = theme;
    document.documentElement.dataset.themePreference = preference;
    syncControls();
    if (changed) root.dispatchEvent(new root.CustomEvent('devgraph:themechange', {
      detail: Object.freeze({preference, theme, source}),
    }));
  }
  function setPreference(next, source = 'api') {
    if (!valid(next)) { syncControls(); return false; }
    try {
      if (!storage) throw new Error('Storage unavailable');
      storage.setItem(storageKey, next);
      persisted = true;
    } catch { persisted = false; }
    apply(next, source);
    return true;
  }
  function bindPickers() {
    for (const picker of document.querySelectorAll('select[data-theme-picker]')) {
      if (boundPickers.has(picker)) continue;
      boundPickers.add(picker);
      picker.addEventListener('change', () => setPreference(picker.value, 'picker'));
    }
    syncControls();
  }

  root.DevgraphTheme = Object.freeze({
    modes, storageKey, getState, setPreference, bindPickers,
    get preference() { return preference; },
    get theme() { return theme; },
  });
  apply(preference, 'init');

  const onSystemChange = () => { if (preference === 'system') apply('system', 'system'); };
  if (media?.addEventListener) media.addEventListener('change', onSystemChange);
  else if (media?.addListener) media.addListener(onSystemChange);

  root.addEventListener('storage', event => {
    if (!storage || event.storageArea !== storage || (event.key !== storageKey && event.key !== null)) return;
    persisted = true;
    apply(valid(event.newValue) ? event.newValue : 'system', 'storage');
  });
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', bindPickers, {once: true});
  else bindPickers();
})(globalThis);
