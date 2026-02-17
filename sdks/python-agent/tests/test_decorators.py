"""Tests for @restricted and @sandboxed decorators."""

from __future__ import annotations

import asyncio
import pytest

from clawdefender.agent.decorators import restricted, sandboxed


class TestRestrictedDecorator:
    """Tests for the @restricted decorator."""

    def test_sync_function_runs(self):
        @restricted(allowed_paths=["/tmp/*"], shell="deny")
        def my_func():
            return 42

        assert my_func() == 42

    def test_sync_function_preserves_name(self):
        @restricted(allowed_paths=["/tmp/*"])
        def my_func():
            return 42

        assert my_func.__name__ == "my_func"

    def test_sync_function_with_args(self):
        @restricted(allowed_paths=["/tmp/*"])
        def add(a, b):
            return a + b

        assert add(3, 4) == 7

    @pytest.mark.asyncio
    async def test_async_function_runs(self):
        @restricted(allowed_paths=["/tmp/*"], shell="deny")
        async def my_async_func():
            return 99

        result = await my_async_func()
        assert result == 99

    @pytest.mark.asyncio
    async def test_async_function_preserves_name(self):
        @restricted(allowed_paths=["/tmp/*"])
        async def my_async_func():
            return 99

        assert my_async_func.__name__ == "my_async_func"

    def test_network_deny(self):
        @restricted(network="deny")
        def net_func():
            return "done"

        assert net_func() == "done"

    def test_decorator_with_kwargs(self):
        @restricted(
            allowed_paths=["/tmp/*"],
            blocked_paths=["/tmp/secret/*"],
            shell="allowlist",
            allowed_commands=["ls"],
            max_files_per_minute=100,
        )
        def complex_func(x):
            return x * 2

        assert complex_func(5) == 10

    def test_decorator_exception_still_deactivates(self):
        @restricted(allowed_paths=["/tmp/*"])
        def failing_func():
            raise ValueError("test error")

        with pytest.raises(ValueError, match="test error"):
            failing_func()


class TestSandboxedDecorator:
    """Tests for the @sandboxed decorator."""

    def test_sync_sandboxed(self):
        @sandboxed(timeout=5)
        def pure_func():
            return 2 + 2

        assert pure_func() == 4

    def test_sync_sandboxed_preserves_name(self):
        @sandboxed(timeout=5)
        def pure_func():
            return 1

        assert pure_func.__name__ == "pure_func"

    @pytest.mark.asyncio
    async def test_async_sandboxed(self):
        @sandboxed(timeout=5)
        async def pure_async():
            return 3 + 3

        assert await pure_async() == 6

    @pytest.mark.asyncio
    async def test_async_sandboxed_timeout(self):
        @sandboxed(timeout=1)
        async def slow_func():
            await asyncio.sleep(10)
            return "done"

        with pytest.raises(asyncio.TimeoutError):
            await slow_func()
