import os
import sys
import re
import base64
import ipaddress
import time
import traceback
import gzip
import ssl
from io import BytesIO
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlparse
from logging.handlers import RotatingFileHandler

class SecureHTTPRequestHandler(SimpleHTTPRequestHandler):
    base_directory = None
    server_config = {}
    security_headers = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'SAMEORIGIN',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'",
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin'
    }
    
    # Cache untuk file statis (1 jam)
    static_cache = {
        '.css': 'max-age=3600, public',
        '.js': 'max-age=3600, public',
        '.jpg': 'max-age=86400, public',
        '.jpeg': 'max-age=86400, public',
        '.png': 'max-age=86400, public',
        '.gif': 'max-age=86400, public',
        '.svg': 'max-age=86400, public',
        '.woff': 'max-age=2592000, public',
        '.woff2': 'max-age=2592000, public'
    }
    
    def __init__(self, *args, **kwargs):
        self.htaccess_cache = {}
        self.authenticated = False
        self.authenticated_realm = ""
        self.start_time = time.time()
        self.log_data = {
            'status': 200,
            'bytes_sent': 0
        }
        self.gzip_enabled = False
        super().__init__(*args, **kwargs)
    
    def log_message(self, format, *args):
        # Disable default logging
        pass
    
    def init_gzip(self):
        """Periksa apakah klien mendukung GZIP"""
        accept_encoding = self.headers.get('Accept-Encoding', '')
        self.gzip_enabled = 'gzip' in accept_encoding and not self.path.endswith((
            '.jpg', '.jpeg', '.png', '.gif', '.zip', '.gz', '.mp3', '.mp4'
        ))
    
    def log_access(self):
        """Custom access logging dengan semua field yang diperlukan"""
        duration = int((time.time() - self.start_time) * 1000)  # in ms
        timestamp = self.log_date_time_string()
        
        # Sanitize dan ambil referer
        referer = self.headers.get('Referer', '-')
        referer = referer.replace('"', "'")  # Prevent log format breaking
        
        # Sanitize user agent
        user_agent = self.headers.get('User-Agent', '-').replace('"', "'")
        
        # Dapatkan request line
        request_line = f"{self.command} {self.path} HTTP/{self.request_version}"
        
        log_entry = (
            f"{timestamp} "
            f"{self.client_address[0]} "
            f"{self.client_address[1]} "
            f"\"{user_agent}\" "
            f"\"{referer}\" "
            f"\"{request_line}\" "
            f"{self.log_data['status']} "
            f"{self.log_data['bytes_sent']} "
            f"{duration}ms"
        )
        
        # Gunakan rotating file handler jika diaktifkan
        if self.server_config.get('access_logger'):
            self.server_config['access_logger'](log_entry)
        else:
            print(log_entry)
    
    def log_error_detail(self, error):
        """Log error detail ke error log"""
        timestamp = self.log_date_time_string()
        error_log = f"\n--- ERROR [{timestamp}] ---\n"
        error_log += f"Request: {self.command} {self.path}\n"
        error_log += f"Client: {self.client_address[0]}:{self.client_address[1]}\n"
        error_log += f"Traceback:\n{traceback.format_exc()}\n"
        error_log += "----------------------------\n"
        
        # Selalu tampilkan di console
        sys.stderr.write(error_log)
        
        # Log ke file error
        if self.server_config.get('error_logger'):
            self.server_config['error_logger'](error_log)
    
    def load_htaccess(self, path):
        """Muat dan cache file .htaccess dengan parsing"""
        # Cek cache dulu
        if path in self.htaccess_cache:
            return self.htaccess_cache[path]
        
        htaccess_path = os.path.join(path, '.htaccess')
        rules = {
            'auth': {},
            'redirects': [],
            'rewrites': [],
            'error_pages': {},
            'deny': [],
            'allow': [],
            'requires': [],
            'custom': {},
            'headers': {}
        }
        
        if os.path.isfile(htaccess_path):
            try:
                with open(htaccess_path, 'r') as f:
                    current_section = None
                    
                    for line in f:
                        line = line.strip()
                        
                        # Lewati komentar dan baris kosong
                        if not line or line.startswith('#'):
                            continue
                            
                        # Header section
                        if line.startswith('<'):
                            if line.startswith('<IfModule'):
                                current_section = 'module'
                            elif line.startswith('<Directory'):
                                current_section = 'directory'
                            elif line.startswith('<Files'):
                                current_section = 'files'
                            elif line.startswith('<Limit'):
                                current_section = 'limit'
                            continue
                        
                        # Arahan autentikasi
                        if line.startswith('AuthType'):
                            rules['auth']['type'] = line.split()[1].strip()
                        elif line.startswith('AuthName'):
                            rules['auth']['name'] = ' '.join(line.split()[1:]).strip('"')
                        elif line.startswith('AuthUserFile'):
                            rules['auth']['userfile'] = line.split()[1].strip()
                        elif line.startswith('Require'):
                            rules['requires'] = [r.strip() for r in line.split()[1:]]
                        
                        # Redirect
                        elif line.startswith('Redirect'):
                            parts = line.split()
                            if len(parts) >= 3:
                                rules['redirects'].append({
                                    'status': int(parts[1]) if parts[1].isdigit() else 301,
                                    'from': parts[2],
                                    'to': ' '.join(parts[3:])
                                })
                        elif line.startswith('RedirectMatch'):
                            parts = line.split()
                            if len(parts) >= 3:
                                rules['redirects'].append({
                                    'status': int(parts[1]) if parts[1].isdigit() else 301,
                                    'regex': parts[2],
                                    'to': ' '.join(parts[3:])
                                })
                        
                        # Rewrite rules
                        elif line.startswith('RewriteEngine'):
                            rules['rewrite_enabled'] = line.split()[1].strip().lower() == 'on'
                        elif line.startswith('RewriteRule'):
                            parts = line.split()
                            if len(parts) >= 3:
                                rules['rewrites'].append({
                                    'pattern': parts[1],
                                    'substitution': parts[2],
                                    'flags': ' '.join(parts[3:]) if len(parts) > 3 else ''
                                })
                        
                        # Error documents
                        elif line.startswith('ErrorDocument'):
                            parts = line.split(None, 2)
                            if len(parts) >= 3:
                                rules['error_pages'][int(parts[1])] = parts[2].strip()
                        
                        # Kontrol akses
                        elif line.startswith('Deny from'):
                            rules['deny'].extend(ip.strip() for ip in line.split()[2:])
                        elif line.startswith('Allow from'):
                            rules['allow'].extend(ip.strip() for ip in line.split()[2:])
                        
                        # Custom headers
                        elif line.startswith('Header set'):
                            parts = line.split(maxsplit=3)
                            if len(parts) >= 4:
                                rules['headers'][parts[2]] = parts[3].strip('"')
                        
                        # Custom rules
                        elif ' ' in line:
                            key, value = line.split(None, 1)
                            rules['custom'][key] = value.strip()
            
            except Exception as e:
                self.log_error_detail(f"Error parsing .htaccess: {htaccess_path}")
        
        # Cache dan kembalikan
        self.htaccess_cache[path] = rules
        return rules
    
    def verify_path(self, path):
        """Verifikasi path yang diminta berada dalam direktori dasar"""
        real_base = self.base_directory
        real_path = os.path.realpath(path)
        
        if real_path == real_base:
            return True
        if real_path.startswith(real_base + os.sep):
            return True
        return False
    
    def translate_path(self, path):
        """Konversi path URL ke path filesystem dengan pemeriksaan keamanan"""
        try:
            # Dapatkan path yang diterjemahkan dari kelas induk
            translated = super().translate_path(path)
            
            # Verifikasi path berada dalam basis aman kami
            if not self.verify_path(translated):
                self.log_data['status'] = 403
                self.send_error(403, "Forbidden: Path outside server root")
                return None
            
            return translated
        except Exception as e:
            self.log_error_detail("Path translation error")
            self.log_data['status'] = 500
            self.send_generic_error(500)
            return None
    
    def check_ip_access(self, client_ip, rules):
        """Periksa apakah IP klien diizinkan berdasarkan aturan .htaccess"""
        try:
            # Konversi ke objek ipaddress
            ip = ipaddress.ip_address(client_ip)
            
            # Default ke izinkan jika tidak ada aturan
            if not rules['allow'] and not rules['deny']:
                return True
            
            # Urutan evaluasi: Tolak lalu Izinkan
            for deny_ip in rules['deny']:
                if deny_ip == 'all':
                    return False
                if '/' in deny_ip:
                    if ip in ipaddress.ip_network(deny_ip, strict=False):
                        return False
                else:
                    if ip == ipaddress.ip_address(deny_ip):
                        return False
            
            # Periksa aturan izinkan
            allowed = False
            for allow_ip in rules['allow']:
                if allow_ip == 'all':
                    allowed = True
                elif '/' in allow_ip:
                    if ip in ipaddress.ip_network(allow_ip, strict=False):
                        allowed = True
                else:
                    if ip == ipaddress.ip_address(allow_ip):
                        allowed = True
            
            return allowed
        except Exception as e:
            self.log_error_detail("IP access check error")
            return False
    
    def check_auth(self, path, rules):
        """Menangani HTTP Basic Authentication"""
        try:
            # Lewati jika tidak ada auth yang dikonfigurasi
            if not rules['auth'] or not rules['requires']:
                return True
            
            # Periksa apakah sudah terautentikasi di realm ini
            if self.authenticated and self.authenticated_realm == rules['auth'].get('name', ''):
                return True
            
            # Verifikasi kredensial
            auth_header = self.headers.get('Authorization', '')
            if auth_header.startswith('Basic '):
                try:
                    auth_decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
                    username, password = auth_decoded.split(':', 1)
                    
                    # Validasi terhadap file pengguna
                    userfile = rules['auth'].get('userfile')
                    if userfile and os.path.isfile(userfile):
                        with open(userfile, 'r') as f:
                            for line in f:
                                if ':' in line:
                                    file_user, file_pass = line.strip().split(':', 1)
                                    if file_user == username and file_pass == password:
                                        self.authenticated = True
                                        self.authenticated_realm = rules['auth'].get('name', '')
                                        return True
                except:
                    pass
            
            # Tidak terautentikasi - kirim tantangan
            self.log_data['status'] = 401
            self.send_response(401)
            self.send_header('WWW-Authenticate', 
                            f'Basic realm="{rules["auth"].get("name", "Restricted Area")}"')
            self.end_headers()
            self.wfile.write(b'Authentication required')
            return False
        except Exception as e:
            self.log_error_detail("Authentication error")
            self.log_data['status'] = 500
            self.send_generic_error(500)
            return False
    
    def apply_rewrites(self, rules):
        """Terapkan aturan penulisan ulang URL"""
        try:
            if not rules.get('rewrite_enabled', False):
                return False
                
            path = unquote(self.path)
            
            for rewrite in rules['rewrites']:
                try:
                    # Terapkan pola rewrite
                    if re.match(rewrite['pattern'], path):
                        new_path = re.sub(rewrite['pattern'], rewrite['substitution'], path)
                        
                        # Tangani flag [L] untuk last rule
                        if 'L' in rewrite.get('flags', ''):
                            self.path = new_path
                            return True
                            
                        # Tangani redirect [R]
                        if 'R' in rewrite.get('flags', ''):
                            status = 302
                            if 'R=301' in rewrite['flags']:
                                status = 301
                            self.log_data['status'] = status
                            self.send_response(status)
                            self.send_header('Location', new_path)
                            self.end_headers()
                            return True
                except re.error:
                    continue
            return False
        except Exception as e:
            self.log_error_detail("Rewrite processing error")
            return False
    
    def apply_redirects(self, rules):
        """Terapkan aturan pengalihan"""
        try:
            path = unquote(self.path)
            
            for redirect in rules['redirects']:
                # Regex redirect
                if 'regex' in redirect:
                    try:
                        if re.match(redirect['regex'], path):
                            self.log_data['status'] = redirect['status']
                            self.send_response(redirect['status'])
                            self.send_header('Location', redirect['to'])
                            self.end_headers()
                            return True
                    except re.error:
                        continue
                
                # Simple redirect
                elif redirect['from'] == path:
                    self.log_data['status'] = redirect['status']
                    self.send_response(redirect['status'])
                    self.send_header('Location', redirect['to'])
                    self.end_headers()
                    return True
            
            return False
        except Exception as e:
            self.log_error_detail("Redirect processing error")
            return False
    
    def send_generic_error(self, code):
        """Kirim error generik tanpa detail"""
        self.send_response(code)
        self.send_header('Content-type', 'text/html')
        
        # Tambahkan header keamanan
        for header, value in self.security_headers.items():
            self.send_header(header, value)
            
        self.end_headers()
        if code == 500:
            self.wfile.write(b"<h1>Script Python Error</h1>")
        else:
            self.wfile.write(f"<h1>{code} Error</h1>".encode())
    
    def handle_error_page(self, code, message=None):
        """Tangani halaman error kustom"""
        try:
            # Rekam status untuk logging
            self.log_data['status'] = code
            
            # Temukan .htaccess terdalam dengan definisi halaman error
            path = self.translate_path(self.path)
            if not path:
                self.send_generic_error(code)
                return
            
            current_path = os.path.dirname(path)
            error_page = None
            
            while current_path.startswith(self.base_directory):
                rules = self.load_htaccess(current_path)
                if code in rules['error_pages']:
                    error_page = rules['error_pages'][code]
                    break
                parent = os.path.dirname(current_path)
                if parent == current_path:
                    break
                current_path = parent
            
            # Jika kami menemukan halaman error kustom
            if error_page:
                if error_page.startswith('/'):
                    # Pengalihan internal
                    self.path = error_page
                    self.log_data['status'] = 200
                    self.handle_request()
                    return
                else:
                    # Pengalihan eksternal
                    self.send_response(302 if code < 400 else code)
                    self.send_header('Location', error_page)
                    self.end_headers()
                    return
            
            # Kembali ke penanganan error generik
            self.send_generic_error(code)
        except Exception as e:
            self.log_error_detail("Error page handling failed")
            self.send_generic_error(500)
    
    def send_error(self, code, message=None, explain=None):
        """Timpa untuk menggunakan halaman error kustom"""
        self.handle_error_page(code, message)
    
    def apply_caching(self, path):
        """Terapkan kebijakan caching untuk file statis"""
        # Dapatkan ekstensi file
        _, ext = os.path.splitext(path)
        ext = ext.lower()
        
        # Periksa apakah kita memiliki kebijakan cache untuk ekstensi ini
        if ext in self.static_cache:
            cache_policy = self.static_cache[ext]
            self.send_header('Cache-Control', cache_policy)
    
    def apply_custom_headers(self, rules):
        """Terapkan header kustom dari .htaccess"""
        for header, value in rules.get('headers', {}).items():
            self.send_header(header, value)
    
    def compress_content(self, content):
        """Kompres konten dengan GZIP jika diaktifkan"""
        if self.gzip_enabled:
            buf = BytesIO()
            with gzip.GzipFile(fileobj=buf, mode='wb') as f:
                f.write(content)
            return buf.getvalue()
        return content
    
    def end_headers(self):
        """Timpa untuk menambahkan header keamanan dan caching"""
        # Tambahkan header keamanan default
        for header, value in self.security_headers.items():
            if header not in self.headers:
                self.send_header(header, value)
                
        # Tambahkan header GZIP jika diaktifkan
        if self.gzip_enabled:
            self.send_header('Content-Encoding', 'gzip')
        
        # Tangkap panjang konten untuk logging
        if self.path != '/favicon.ico':
            self.log_data['bytes_sent'] = self.headers.get('Content-Length', 0)
            
        super().end_headers()
    
    def handle_request(self):
        """Penangan permintaan utama dengan integrasi .htaccess"""
        try:
            # Inisialisasi GZIP
            self.init_gzip()
            
            # Resolve path dan muat aturan
            path = self.translate_path(self.path)
            if not path:
                return  # Sudah menangani error keamanan
            
            # Dapatkan direktori file yang diminta
            dir_path = os.path.dirname(path) if not os.path.isdir(path) else path
            rules = self.load_htaccess(dir_path)
            
            # 1. Periksa pembatasan IP
            client_ip = self.client_address[0]
            if not self.check_ip_access(client_ip, rules):
                self.log_data['status'] = 403
                self.handle_error_page(403, "Forbidden: IP restricted")
                return
            
            # 2. Periksa autentikasi
            if not self.check_auth(path, rules):
                return  # Tantangan autentikasi terkirim
            
            # 3. Terapkan penulisan ulang URL
            if self.apply_rewrites(rules):
                return  # Penulisan ulang URL berhasil
            
            # 4. Terapkan pengalihan
            if self.apply_redirects(rules):
                return  # Pengalihan berhasil
            
            # 5. Terapkan aturan kustom
            if 'Options' in rules['custom']:
                # Tangani daftar direktori
                if '-Indexes' in rules['custom']['Options'] and os.path.isdir(path):
                    self.log_data['status'] = 403
                    self.handle_error_page(403, "Directory listing disabled")
                    return
            
            # 6. Proses permintaan secara normal
            if os.path.isdir(path):
                # Periksa file indeks
                for index in ['index.html', 'index.htm', 'index.php']:
                    index_path = os.path.join(path, index)
                    if os.path.isfile(index_path):
                        self.path = self.path.rstrip('/') + '/' + index
                        return super().do_GET()
                
                # Tidak ada file indeks - tampilkan daftar direktori atau error
                if 'Options' in rules['custom'] and '+Indexes' in rules['custom']['Options']:
                    self.log_data['status'] = 200
                    return super().list_directory(path)
                else:
                    self.log_data['status'] = 403
                    self.handle_error_page(403, "Directory listing disabled")
                    return
            else:
                return super().do_GET()
        except Exception as e:
            self.log_data['status'] = 500
            self.log_error_detail("Request processing error")
            self.send_generic_error(500)
        finally:
            # Log setelah pemrosesan
            self.log_access()
    
    def do_GET(self):
        self.handle_request()
    
    def do_HEAD(self):
        self.handle_request()
    
    def list_directory(self, path):
        """Timpa daftar direktori"""
        try:
            self.log_data['status'] = 403
            self.handle_error_page(403, "Directory listing disabled")
        except Exception as e:
            self.log_data['status'] = 500
            self.log_error_detail("Directory listing error")
            self.send_generic_error(500)
    
    def guess_type(self, path):
        """Timpa untuk menambahkan tipe MIME modern"""
        base, ext = os.path.splitext(path)
        if ext == '.js':
            return 'application/javascript'
        if ext == '.css':
            return 'text/css'
        if ext == '.svg':
            return 'image/svg+xml'
        if ext == '.json':
            return 'application/json'
        return super().guess_type(path)
    
    def send_head(self):
        """Timpa untuk menambahkan caching dan kompresi"""
        path = self.translate_path(self.path)
        if not path:
            return None
            
        # Dapatkan direktori file yang diminta
        dir_path = os.path.dirname(path) if not os.path.isdir(path) else path
        rules = self.load_htaccess(dir_path)
        
        # Terapkan header kustom
        self.apply_custom_headers(rules)
        
        # Tangani file
        if os.path.isdir(path):
            return super().send_head()
            
        try:
            with open(path, 'rb') as f:
                content = f.read()
                
            # Terapkan caching untuk file statis
            self.apply_caching(path)
                
            # Kompres konten
            compressed = self.compress_content(content)
            
            # Tentukan tipe konten
            ctype = self.guess_type(path)
            self.send_response(200)
            self.send_header("Content-type", ctype)
            self.send_header("Content-Length", str(len(compressed)))
            return BytesIO(compressed)
                
        except IOError:
            self.send_error(404, "File not found")
            return None

def setup_logging(access_log, error_log):
    """Siapkan logging dengan rotasi file"""
    access_logger = None
    error_logger = None
    
    def create_logger(filename, max_bytes, backup_count):
        handler = RotatingFileHandler(
            filename, maxBytes=max_bytes, backupCount=backup_count
        )
        return lambda msg: handler.stream.write(msg + '\n')
    
    if access_log:
        # 10MB per file, simpan 5 backup
        access_logger = create_logger(access_log, 10*1024*1024, 5)
    
    if error_log:
        # 5MB per file, simpan 3 backup
        error_logger = create_logger(error_log, 5*1024*1024, 3)
    
    return access_logger, error_logger

def run_server(port=8000, directory=os.getcwd(), 
              access_log=None, error_log=None,
              ssl_cert=None, ssl_key=None):
    # Verifikasi dan siapkan direktori
    directory = os.path.abspath(directory)
    if not os.path.isdir(directory):
        print(f"Error: Directory '{directory}' does not exist", file=sys.stderr)
        sys.exit(1)
    
    # Siapkan logging
    access_logger, error_logger = setup_logging(access_log, error_log)
    
    # Set basis direktori untuk pemeriksaan keamanan
    real_base = os.path.realpath(directory)
    SecureHTTPRequestHandler.base_directory = real_base
    
    # Set konfigurasi server di kelas handler
    SecureHTTPRequestHandler.server_config = {
        'access_logger': access_logger,
        'error_logger': error_logger
    }
    
    # Ubah direktori kerja ke target
    os.chdir(directory)
    
    # Buat instance server
    server_address = ('', port)
    httpd = ThreadingHTTPServer(server_address, SecureHTTPRequestHandler)
    
    # Aktifkan HTTPS jika sertifikat disediakan
    if ssl_cert:
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=ssl_cert, keyfile=ssl_key)
        httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True)
        print(f"SSL enabled with certificate: {ssl_cert}")
    
    print(f"Serving directory: {directory}")
    print(f"Resolved base path: {real_base}")
    print(f"Access at: {'https' if ssl_cert else 'http'}://localhost:{port}")
    if access_log:
        print(f"Access log: {access_log} (10MB rotation)")
    if error_log:
        print(f"Error log: {error_log} (5MB rotation)")
    print("Press Ctrl+C to stop...")
    print("\nEnhanced Features:")
    print("  - SSL/TLS Encryption: " + ("Enabled" if ssl_cert else "Disabled"))
    print("  - Security Headers: XSS protection, CSP, no-sniff")
    print("  - Static File Caching: CSS/JS (1h), images (24h)")
    print("  - GZIP Compression: Enabled for text content")
    print("  - RewriteEngine Support: Basic RewriteRule implementation")
    print("\nAccess Log Format:")
    print("  [timestamp] [client_ip] [client_port] \"[user_agent]\" \"[referer]\" \"[request]\" [status] [bytes_sent] [duration]")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped")
        httpd.server_close()

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Enhanced Python HTTP Server with Security and Performance Features')
    parser.add_argument('--port', type=int, default=8000, help='Port to listen on (default: 8000)')
    parser.add_argument('--directory', default=os.getcwd(), help='Directory to serve (default: current)')
    parser.add_argument('--access-log', help='Access log file path')
    parser.add_argument('--error-log', help='Error log file path')
    parser.add_argument('--ssl-cert', help='SSL certificate file path')
    parser.add_argument('--ssl-key', help='SSL private key file path')
    args = parser.parse_args()
    
    # Validasi SSL
    if args.ssl_cert and not os.path.exists(args.ssl_cert):
        print(f"SSL certificate not found: {args.ssl_cert}", file=sys.stderr)
        sys.exit(1)
        
    if args.ssl_key and not os.path.exists(args.ssl_key):
        print(f"SSL key not found: {args.ssl_key}", file=sys.stderr)
        sys.exit(1)
    
    run_server(
        port=args.port,
        directory=args.directory,
        access_log=args.access_log,
        error_log=args.error_log,
        ssl_cert=args.ssl_cert,
        ssl_key=args.ssl_key
    )
