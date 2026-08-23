import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from weborn.routers.apps import (
    _is_config_path_allowed,
    _resolve_config_path,
    WORKER_CLASSES,
)


class TestConfigPathWhitelist:
    def test_nginx_valid(self):
        assert _is_config_path_allowed("/etc/nginx/nginx.conf") is True

    def test_nginx_with_subdir_invalid(self):
        assert _is_config_path_allowed("/etc/nginx/sites-enabled/default") is False

    def test_php_ini_valid(self):
        assert _is_config_path_allowed("/etc/php/8.2/fpm/php.ini") is True

    def test_php_pool_valid(self):
        assert _is_config_path_allowed("/etc/php/8.2/fpm/pool.d/www.conf") is True

    def test_php_traversal_rejected(self):
        assert _is_config_path_allowed("/etc/php/8.2/fpm/../../etc/shadow") is False

    def test_double_dot_anywhere_rejected(self):
        assert _is_config_path_allowed("/etc/nginx/../etc/shadow") is False

    def test_app_dir_valid(self):
        assert _is_config_path_allowed("/var/www/myapp/app.py") is True

    def test_app_dir_traversal_rejected(self):
        assert _is_config_path_allowed("/var/www/../etc/shadow") is False

    def test_empty_rejected(self):
        assert _is_config_path_allowed("") is False

    def test_random_path_rejected(self):
        assert _is_config_path_allowed("/etc/shadow") is False

    def test_whitespace_stripped(self):
        assert _is_config_path_allowed("  /etc/nginx/nginx.conf  ") is True


class TestResolveConfigPath:
    def test_nginx(self):
        r = _resolve_config_path("nginx", "nginx.conf")
        assert r == "/etc/nginx/nginx.conf"

    def test_php_ini(self):
        r = _resolve_config_path("php-fpm", "php.ini")
        assert "/php.ini" in r

    def test_php_www_conf(self):
        r = _resolve_config_path("php-fpm", "www.conf")
        assert "/pool.d/www.conf" in r

    def test_node(self):
        r = _resolve_config_path("node", "package.json", "myapp")
        assert r == "/var/www/myapp/package.json"

    def test_node_sanitizes_name(self):
        r = _resolve_config_path("node", "file.txt", "../../etc")
        assert "../" not in r

    def test_unknown_type_empty(self):
        r = _resolve_config_path("unknown", "file.txt")
        assert r == ""


class TestWorkerClasses:
    def test_empty_allowed(self):
        assert "" in WORKER_CLASSES

    def test_sync_allowed(self):
        assert "sync" in WORKER_CLASSES

    def test_gunicorn_invalid(self):
        assert "gunicorn" not in WORKER_CLASSES

    def test_arbitrary_rejected(self):
        assert "os.system('rm -rf /')" not in WORKER_CLASSES
