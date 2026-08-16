// Weborn panel: aksi dengan modal progress + streaming SSE (install/update/uninstall)
(function () {
  const $ = (id) => document.getElementById(id);

  const THEME_KEY = 'weborn_theme';
  const THEME_ICONS = { system: '🌓', dark: '🌙', light: '☀️' };

  function applyTheme(mode) {
    const theme = mode === 'system'
      ? (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark')
      : mode;
    document.documentElement.setAttribute('data-theme', theme);
  }
  function themeLabel() {
    const cur = localStorage.getItem(THEME_KEY) || 'system';
    const btn = $('theme-toggle');
    if (btn) { btn.textContent = THEME_ICONS[cur] || '🌓'; btn.title = 'Tema: ' + cur; }
  }
  function initTheme() {
    applyTheme(localStorage.getItem(THEME_KEY) || 'system');
    themeLabel();
    try {
      window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', () => {
        if ((localStorage.getItem(THEME_KEY) || 'system') === 'system') applyTheme('system');
      });
    } catch (e) { /* browser lama */ }
  }
  function cycleTheme() {
    const order = ['system', 'dark', 'light'];
    const cur = localStorage.getItem(THEME_KEY) || 'system';
    const next = order[(order.indexOf(cur) + 1) % order.length];
    localStorage.setItem(THEME_KEY, next);
    applyTheme(next);
    themeLabel();
  }

  function showProgress(title) {
    $('progress-title').textContent = title;
    $('progress-step').textContent = 'Menyiapkan…';
    $('progress-output').textContent = '';
    $('progress-output').style.display = 'none';
    $('progress-close').style.display = 'none';
    $('progress-overlay').classList.add('visible');
    setProgress(0);
  }
  function setProgress(pct) {
    $('progress-fill').style.width = Math.max(2, Math.min(100, pct)) + '%';
  }
  function setStep(text) { $('progress-step').textContent = text; }
  function setOutput(text) {
    const el = $('progress-output');
    el.textContent = text;
    el.style.display = 'block';
  }
  function appendOutput(text) {
    const el = $('progress-output');
    const cur = el.textContent;
    el.textContent = cur ? cur + '\n\n' + text : text;
    el.style.display = 'block';
  }
  function showClose() {
    $('progress-close').style.display = 'inline-block';
    setProgress(100);
  }
  function hideProgress() { $('progress-overlay').classList.remove('visible'); }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g,
      (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  window.weborn = {
    showProgress, setProgress, setStep, setOutput, appendOutput, showClose, hideProgress,
    initTheme, cycleTheme,

    async simplePost(url, title, reload) {
      showProgress(title);
      setStep('Menjalankan…');
      try {
        const res = await fetch(url, { method: 'POST' });
        let data;
        try { data = await res.json(); } catch (e) { data = { output: await res.text() }; }
        setOutput(JSON.stringify(data, null, 2));
        setStep(res.ok ? 'Selesai ✓' : 'Gagal ✗');
        showClose();
        if (reload) setTimeout(() => location.reload(), 900);
      } catch (e) {
        setOutput('Gagal: ' + e.message);
        setStep('Gagal ✗');
        showClose();
      }
    },

    async formPost(url, form, title, reload) {
      showProgress(title);
      setStep('Menyimpan…');
      try {
        const res = await fetch(url, { method: 'POST', body: new FormData(form), redirect: 'follow' });
        if (res.redirected || (res.status >= 300 && res.status < 400)) {
          setStep('Selesai ✓');
          showClose();
          if (reload) setTimeout(() => location.reload(), 400);
          return;
        }
        const data = await res.json();
        setOutput(JSON.stringify(data, null, 2));
        setStep(res.ok ? 'Selesai ✓' : 'Gagal ✗');
        showClose();
        if (reload) setTimeout(() => location.reload(), 900);
      } catch (e) {
        setOutput('Gagal: ' + e.message);
        setStep('Gagal ✗');
        showClose();
      }
    },

    async streamPost(url, title, reload) {
      showProgress(title);
      let stepCount = 0;
      let outputBuf = '';
      try {
        const res = await fetch(url, { method: 'POST', headers: { 'Accept': 'text/event-stream' } });
        if (!res.ok || !res.body) throw new Error('HTTP ' + res.status);
        const reader = res.body.getReader();
        const dec = new TextDecoder();
        let buf = '';
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          buf += dec.decode(value, { stream: true });
          let idx;
          while ((idx = buf.indexOf('\n\n')) >= 0) {
            handleEvent(buf.slice(0, idx));
            buf = buf.slice(idx + 2);
          }
        }
        if (buf.trim()) handleEvent(buf);
      } catch (e) {
        setStep('Gagal ✗');
        setOutput(outputBuf || 'Gagal: ' + e.message);
        showClose();
      }

      function handleEvent(chunk) {
        let name = 'message', data = '';
        chunk.split('\n').forEach((line) => {
          if (line.startsWith('event:')) name = line.slice(6).trim();
          else if (line.startsWith('data:')) data += line.slice(5).trim();
        });
        let d = {};
        try { d = JSON.parse(data); } catch (e) { d = { output: data }; }
        if (name === 'step') {
          stepCount++;
          setStep(d.step || 'Langkah ' + stepCount);
          if (d.output) { outputBuf += (outputBuf ? '\n\n' : '') + d.output; setOutput(outputBuf); }
          setProgress(Math.min(12 + stepCount * 10, 92));
        } else if (name === 'done') {
          setStep('Selesai ✓');
          showClose();
          if (reload) setTimeout(() => location.reload(), 900);
        } else if (name === 'error') {
          setStep('Gagal ✗');
          setOutput(d.output || d.error || 'Operasi gagal');
          showClose();
        }
      }
    }
  };

  initTheme();
})();
