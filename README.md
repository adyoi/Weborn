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

2. Weborn tidak memerlukan dependensi eksternal (hanya Python standar)

## Penggunaan Dasar

Jalankan server untuk melayani direktori saat ini:

```bash
python server.py
```
Akses di browser: http://localhost:8000

Opsi Lanjutan

| Opsi	| Deskripsi	| Contoh |
| :-----: | :-----: | :-----: |
| --port	| Port server (default: 8000)	| --port 8080 |
| --directory	| Direktori yang dilayani (default: current)	| --directory /var/www |
| --access-log	| File log akses	| --access-log access.log |
| --error-log	File | log error	| --error-log errors.log
| --ssl-cert	| File sertifikat SSL	| --ssl-cert server.crt |
| --ssl-key	| File kunci privat SSL	| --ssl-key server.key |

## Contoh Penggunaan HTTPS

```bash
python server.py --port 443 --ssl-cert ssl/server.crt --ssl-key ssl/server.key
```

## Contoh Konfigurasi .htaccess

1. Autentikasi Dasar

protected/.htaccess:
```text
AuthType Basic
AuthName "Restricted Area"
AuthUserFile /path/to/.htpasswd
Require valid-user
```

2. Pengalihan

redirects/.htaccess:

```text
Redirect 301 /old-page.html /new-page.html
RedirectMatch 302 ^/products/(.*)$ https://store.example.com/$1
```

3. Halaman Error Kustom

errors/.htaccess:

```text
ErrorDocument 404 /errors/404.html
ErrorDocument 500 "Sorry, an error occurred"
```

4. Kontrol Akses IP
```text
Allow from 192.168.1.0/24
Deny from all
```

5. Penulisan Ulang URL
```text
RewriteEngine On
RewriteRule ^product/(\d+)$ product.php?id=$1 [L]
```

## Membuat Sertifikat SSL

1. Buat direktori ssl:

```bash
mkdir ssl
cd ssl
```
2. Generate sertifikat self-signed:

```bash
openssl req -x509 -newkey rsa:4096 -nodes -out server.crt -keyout server.key -days 365
```

3. Jalankan server dengan SSL:

```bash
python server.py --ssl-cert ssl/server.crt --ssl-key ssl/server.key
```
