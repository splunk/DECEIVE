from __future__ import annotations

from typing import Protocol

from deceive.runtime import DeceiveRuntime, ProtocolInstanceConfig


class ProtocolAdapter(Protocol):
    name: str

    async def start_instance(
        self, runtime: DeceiveRuntime, instance: ProtocolInstanceConfig
    ):
        """Start one configured protocol instance and return a server handle."""

