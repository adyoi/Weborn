# Weborn - A Python Webserver

Weborn (Web Hornet) adalah webserver Python yang ringan namun kuat dengan dukungan fitur-fitur canggih seperti .htaccess, SSL/TLS, caching, dan logging komprehensif.

## Fitur Utama

- 🔒 **Keamanan Tingkat Lanjut**
  - Dukungan SSL/TLS (HTTPS)
  - Header keamanan modern (CSP, XSS Protection, HSTS)
  - Pencegahan path traversal
  - Dukungan .htaccess untuk autentikasi dasar

- ⚡ **Optimasi Kinerja**
  - Kompresi GZIP untuk konten teks
  - Caching untuk aset statis (CSS, JS, gambar)
  - Threading untuk penanganan permintaan paralel

- 📝 **Logging Komprehensif**
  - Format log terstruktur dengan semua informasi penting
  - Rotasi log otomatis
  - Pemisahan log akses dan error
  - Mencatat: timestamp, IP klien, user agent, referer, dll

- 🔧 **Dukungan .htaccess**
  - Autentikasi dasar (AuthType, AuthName, AuthUserFile)
  - Pengalihan (Redirect, RedirectMatch)
  - Halaman error kustom (ErrorDocument)
  - Kontrol akses IP (Allow, Deny)
  - Penulisan ulang URL dasar (RewriteRule)

## Instalasi

1. Clone repository:
```bash
git clone https://github.com/username/Weborn.git
cd Weborn
```
