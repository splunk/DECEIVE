from __future__ import annotations

from deceive.protocols.http import HTTPProtocolAdapter
from deceive.protocols.ssh import SSHProtocolAdapter


def get_protocol_registry():
    return {
        "ssh": SSHProtocolAdapter(),
        "http": HTTPProtocolAdapter("http"),
        "https": HTTPProtocolAdapter("https"),
    }


def get_protocol_adapter(protocol: str):
    registry = get_protocol_registry()
    try:
        return registry[protocol]
    except KeyError as exc:
        available = ", ".join(sorted(registry))
        raise ValueError(
            f"Unknown protocol '{protocol}'. Available protocols: {available}."
        ) from exc
