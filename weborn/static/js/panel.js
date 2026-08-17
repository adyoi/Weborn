// Weborn panel — progress modal, SSE streaming, navigation guard
(function () {
  const $ = (id) => document.getElementById(id);

  // ── Navigation guard ──────────────────────────────────────────────────────
  let _processRunning = false;
  let _processFailed = false;
  let _navGuardReason = '';

  function enableNavGuard(reason) {
    _processRunning = true;
    _processFailed = false;
    _navGuardReason = reason || 'Proses sedang berjalan';
  }
  function markProcessFailed() { _processFailed = true; }
  function disableNavGuard() {
    _processRunning = false;
    _processFailed = false;
    _navGuardReason = '';
  }

  window.addEventListener('beforeunload', function (e) {
    if (_processRunning && !_processFailed) {
      e.preventDefault();
      e.returnValue = _navGuardReason;
      return e.returnValue;
    }
  });

  window.addEventListener('popstate', function (e) {
    if (_processRunning && !_processFailed) {
      e.preventDefault();
      window.history.pushState(null, '', window.location.href);
      showToast(_navGuardReason, 'warn');
    }
  });

  document.addEventListener('click', function (e) {
    if (!_processRunning || _processFailed) return;
    const a = e.target.closest('a[href]');
    if (!a) return;
    const href = a.getAttribute('href');
    if (!href || href === '#' || href.startsWith('javascript:') || href.startsWith('#')) return;
    e.preventDefault();
    showToast(_navGuardReason, 'warn');
  });

  document.addEventListener('submit', function (e) {
    if (_processRunning && !_processFailed) {
      e.preventDefault();
      showToast(_navGuardReason, 'warn');
    }
  });

  function showToast(msg, type) {
    let t = document.getElementById('weborn-nav-guard-toast');
    if (!t) {
      t = document.createElement('div');
      t.id = 'weborn-nav-guard-toast';
      t.style.cssText = 'position:fixed;top:20px;left:50%;transform:translateX(-50%);z-index:100000;' +
        'padding:8px 20px;border-radius:8px;font-size:12px;font-weight:600;' +
        'box-shadow:0 4px 20px rgba(0,0,0,.3);transition:opacity .3s;pointer-events:none;';
      document.body.appendChild(t);
    }
    t.textContent = msg;
    const colors = { warn: 'background:#f59e0b;color:#000', err: 'background:#ef4444;color:#fff',
                     ok: 'background:#10b981;color:#fff' };
    t.style.cssText += ';' + (colors[type] || colors.warn);
    t.style.opacity = '1';
    clearTimeout(t._hideTimer);
    t._hideTimer = setTimeout(() => { t.style.opacity = '0'; }, 3000);
  }

  // ── Theme ─────────────────────────────────────────────────────────────────
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
    } catch (e) {}
  }
  function cycleTheme() {
    const order = ['system', 'dark', 'light'];
    const cur = localStorage.getItem(THEME_KEY) || 'system';
    const next = order[(order.indexOf(cur) + 1) % order.length];
    localStorage.setItem(THEME_KEY, next);
    applyTheme(next);
    themeLabel();
  }

  // ── Progress modal ────────────────────────────────────────────────────────
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
  function showClose(success) {
    $('progress-close').style.display = 'inline-block';
    setProgress(100);
    if (success === false) {
      markProcessFailed();
      showToast('Proses gagal — Anda bisa menutup halaman', 'err');
    } else {
      disableNavGuard();
    }
  }
  function hideProgress() {
    $('progress-overlay').classList.remove('visible');
    disableNavGuard();
  }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g,
      (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  // Friendly error mapper
  const ERROR_MAP = [
    [/permission denied/i, 'Akses ditolak — jalankan sebagai root/sudo'],
    [/command not found/i, 'Perintah tidak ditemukan — install dulu package terkait'],
    [/no such file or directory/i, 'File atau direktori tidak ditemukan'],
    [/connection refused/i, 'Koneksi ditolak — service mungkin belum jalan'],
    [/unit .* not found/i, 'Service systemd tidak ditemukan'],
    [/could not resolve/i, 'DNS tidak bisa resolve — cek /etc/resolv.conf'],
    [/address already in use/i, 'Port sudah dipakai proses lain'],
    [/access denied/i, 'Akses ditolak oleh sistem'],
    [/timeout/i, 'Operasi timeout — server tidak merespon'],
    [/disk.*full|no space left/i, 'Disk penuh — tidak ada ruang tersisa'],
  ];

  function friendlyError(raw) {
    if (!raw) return 'Terjadi kesalahan tidak diketahui';
    for (const [re, msg] of ERROR_MAP) {
      if (re.test(raw)) return msg;
    }
    // Truncate very long errors
    const lines = String(raw).split('\n').filter(l => l.trim());
    if (lines.length > 8) return lines.slice(0, 5).join('\n') + '\n… (' + (lines.length - 5) + ' more lines)';
    return raw;
  }

  window.weborn = {
    showProgress, setProgress, setStep, setOutput, appendOutput, showClose, hideProgress,
    initTheme, cycleTheme,

    // ── Simple POST (JSON response) ──
    async simplePost(url, title, reload) {
      showProgress(title);
      setStep('Menjalankan…');
      try {
        const res = await fetch(url, { method: 'POST' });
        let data;
        try { data = await res.json(); } catch (e) { data = { output: await res.text() }; }
        if (data.ok === false || data.error) {
          setOutput(friendlyError(data.error || data.output || JSON.stringify(data, null, 2)));
          setStep('Gagal ✗');
          showClose(false);
          return;
        }
        setOutput(data.output || JSON.stringify(data, null, 2));
        setStep('Selesai ✓');
        showClose(true);
        if (reload) setTimeout(() => location.reload(), 900);
      } catch (e) {
        setOutput(friendlyError(e.message));
        setStep('Gagal ✗');
        showClose(false);
      }
    },

    // ── Form POST (follows redirect) ──
    async formPost(url, form, title, reload) {
      showProgress(title);
      setStep('Menyimpan…');
      try {
        const res = await fetch(url, { method: 'POST', body: new FormData(form), redirect: 'follow' });
        if (res.redirected || (res.status >= 300 && res.status < 400)) {
          setStep('Selesai ✓');
          showClose(true);
          if (reload) setTimeout(() => location.reload(), 400);
          return;
        }
        const data = await res.json();
        if (data.ok === false || data.error) {
          setOutput(friendlyError(data.error || data.output || JSON.stringify(data, null, 2)));
          setStep('Gagal ✗');
          showClose(false);
          return;
        }
        setOutput(JSON.stringify(data, null, 2));
        setStep('Selesai ✓');
        showClose(true);
        if (reload) setTimeout(() => location.reload(), 900);
      } catch (e) {
        setOutput(friendlyError(e.message));
        setStep('Gagal ✗');
        showClose(false);
      }
    },

    // ── SSE streaming POST ──
    async streamPost(url, title, reload, formData) {
      showProgress(title);
      let stepCount = 0;
      let outputBuf = '';
      try {
        const opts = { method: 'POST', headers: { 'Accept': 'text/event-stream' } };
        if (formData) opts.body = formData;
        const res = await fetch(url, opts);
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
        setOutput(friendlyError(outputBuf || e.message));
        showClose(false);
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
          showClose(true);
          if (reload) setTimeout(() => location.reload(), 900);
        } else if (name === 'error') {
          setStep('Gagal ✗');
          setOutput(friendlyError(d.output || d.error || 'Operasi gagal'));
          showClose(false);
        }
      }
    },

    // ── Confirm + action ──
    async confirmAction(url, title, reload, confirmMsg) {
      if (confirmMsg && !confirm(confirmMsg)) return;
      return this.simplePost(url, title, reload);
    },

    // ── Toast ──
    toast: showToast,
  };

  initTheme();
})();
