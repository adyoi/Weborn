#!/usr/bin/env python3
"""Run unit tests (no external deps needed — stdlib only).

Usage:  python test/run_tests.py          (from project root)
        .venv/bin/python test/run_tests.py  (on server)

Integration test (needs running panel):  sudo .venv/bin/python test/test_apps_integration.py
"""
import sys, os, traceback

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

passed = 0
failed = 0
errors = []


def run_test(cls):
    global passed, failed
    obj = cls()
    for name in sorted(dir(obj)):
        if not name.startswith("test_"):
            continue
        try:
            getattr(obj, name)()
            passed += 1
            print(f"  PASS  {cls.__name__}.{name}")
        except Exception as e:
            failed += 1
            tb = traceback.format_exc().strip().splitlines()[-1]
            print(f"  FAIL  {cls.__name__}.{name}: {tb}")
            errors.append((f"{cls.__name__}.{name}", e))


print("=" * 60)

from test_csrf import TestCSRF
print("\n[CSRF]")
run_test(TestCSRF)

from test_ratelimit import TestRateLimiter
print("\n[RateLimiter]")
run_test(TestRateLimiter)

from test_auth import TestJWT, TestIdleLock
print("\n[JWT]")
run_test(TestJWT)
print("\n[IdleLock]")
run_test(TestIdleLock)

from test_executors import TestDryRunExecutor, TestExecResult
print("\n[ExecResult]")
run_test(TestExecResult)
print("\n[DryRunExecutor]")
run_test(TestDryRunExecutor)

from test_apps_security import TestConfigPathWhitelist, TestResolveConfigPath, TestWorkerClasses
from test_webmail import TestRoundcubeAutoLogin
print("\n[ConfigPathWhitelist]")
run_test(TestConfigPathWhitelist)
print("\n[ResolveConfigPath]")
run_test(TestResolveConfigPath)
print("\n[WorkerClasses]")
run_test(TestWorkerClasses)
print("\n[RoundcubeAutoLogin]")
run_test(TestRoundcubeAutoLogin)

print("\n" + "=" * 60)
print(f"Results: {passed} passed, {failed} failed, {passed + failed} total")
if errors:
    sys.exit(1)
