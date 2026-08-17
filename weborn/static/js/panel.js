// Weborn panel: aksi dengan modal progress + streaming SSE (install/update/uninstall)
// + browser navigation guard (cegah reload/tutup saat proses berjalan)
(function () {
  const $ = (id) => document.getElementById(id);

  // ── Navigation guard ──────────────────────────────────────────────────────
  // Mencegah browser reload / close / back / forward saat proses sedang berjalan.
  // Menggunakan beforeunload + event listener pada progress overlay.
  let _processRunning = false;
  let _navGuardReason = '';

  function enableNavGuard(reason) {
    _processRunning = true;
    _navGuardReason = reason || 'Proses sedang berjalan';
  }
  function disableNavGuard() {
    _processRunning = false;
    _navGuardReason = '';
  }

  // beforeunload: cegah tutup/reload tab
  window.addEventListener('beforeunload', function (e) {
    if (_processRunning) {
      e.preventDefault();
      e.returnValue = _navGuardReason;
      return e.returnValue;
    }
  });

  // popstate: cegah navigasi back/forward
  window.addEventListener('popstate', function (e) {
    if (_processRunning) {
      e.preventDefault();
      window.history.pushState(null, '', window.location.href);
      showToast(_navGuardReason);
    }
  });

  // Intercept semua link click (navigasi dalam tab)
  document.addEventListener('click', function (e) {
    if (!_processRunning) return;
    const a = e.target.closest('a[href]');
    if (!a) return;
    const href = a.getAttribute('href');
    // Abaikan hash-only, javascript:, dan anchor internal
    if (!href || href === '#' || href.startsWith('javascript:') || href.startsWith('#')) return;
    e.preventDefault();
    showToast(_navGuardReason);
  });

  // Intercept form submit
  document.addEventListener('submit', function (e) {
    if (_processRunning) {
      e.preventDefault();
      showToast(_navGuardReason);
    }
  });

  // Toast notification untuk guard
  function showToast(msg) {
    let t = document.getElementById('weborn-nav-guard-toast');
    if (!t) {
      t = document.createElement('div');
      t.id = 'weborn-nav-guard-toast';
      t.style.cssText = 'position:fixed;top:20px;left:50%;transform:translateX(-50%);z-index:100000;' +
        'background:#f59e0b;color:#000;padding:10px 24px;border-radius:8px;font-size:13px;font-weight:600;' +
        'box-shadow:0 4px 20px rgba(0,0,0,.3);transition:opacity .3s;pointer-events:none;';
      document.body.appendChild(t);
    }
    t.textContent = msg;
    t.style.opacity = '1';
    clearTimeout(t._hideTimer);
    t._hideTimer = setTimeout(() => { t.style.opacity = '0'; }, 3000);
  }

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
    enableNavGuard(title || 'Proses sedang berjalan');
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
  function hideProgress() {
    $('progress-overlay').classList.remove('visible');
    disableNavGuard();
  }
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
