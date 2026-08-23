import asyncio
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from weborn.executors import DryRunExecutor, ExecResult


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class TestExecResult:
    def test_output_property(self):
        r = ExecResult(ok=True, returncode=0, stdout="out", stderr="err")
        assert r.output == "out\nerr"

    def test_output_empty(self):
        r = ExecResult(ok=True, returncode=0, stdout="", stderr="")
        assert r.output == ""


class TestDryRunExecutor:
    def test_mode(self):
        ex = DryRunExecutor()
        assert ex.mode == "dry-run"

    def test_run_returns_ok(self):
        ex = DryRunExecutor()
        r = _run(ex.run("echo", "hello"))
        assert r.ok is True
        assert r.returncode == 0
        assert "[dry-run]" in r.stdout
        assert "echo hello" in r.stdout

    def test_run_multiple_args(self):
        ex = DryRunExecutor()
        r = _run(ex.run("systemctl", "restart", "nginx"))
        assert r.ok is True
        assert "systemctl restart nginx" in r.stdout

    def test_write_file_returns_ok(self):
        ex = DryRunExecutor()
        r = _run(ex.write_file("/etc/test", "content"))
        assert r.ok is True
        assert "[dry-run]" in r.stdout

    def test_write_file_does_not_touch_disk(self):
        test_path = "/tmp/weborn_dryrun_test_file_that_should_not_exist"
        ex = DryRunExecutor()
        _run(ex.write_file(test_path, "data"))
        assert not os.path.exists(test_path)

    def test_read_file_returns_ok(self):
        ex = DryRunExecutor()
        r = _run(ex.read_file("/etc/passwd"))
        assert r.ok is True
        assert "[dry-run]" in r.stdout

    def test_systemctl_does_not_execute(self):
        ex = DryRunExecutor()
        r = _run(ex.systemctl("start", "nginx"))
        assert r.ok is True
        assert "systemctl start nginx" in r.stdout
