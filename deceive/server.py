from __future__ import annotations

import argparse
import asyncio
import os
import sys
import traceback
from dataclasses import dataclass
from typing import Optional

from deceive.config import apply_args_to_config, discover_protocol_instances, load_config
from deceive.registry import get_protocol_adapter
from deceive.runtime import DeceiveRuntime, ProtocolInstanceConfig


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
runtime: DeceiveRuntime | None = None


@dataclass
class RunningProtocolInstance:
    instance: ProtocolInstanceConfig
    server: object


class ServerGroup:
    def __init__(self, servers: list[RunningProtocolInstance]):
        self.servers = servers

    def close(self):
        for running in self.servers:
            close = getattr(running.server, "close", None)
            if close is not None:
                close()

    async def wait_closed(self):
        for running in self.servers:
            wait_closed = getattr(running.server, "wait_closed", None)
            if wait_closed is not None:
                result = wait_closed()
                if hasattr(result, "__await__"):
                    await result

    def get_port(self, protocol: Optional[str] = None, name: Optional[str] = None):
        matches = self._matching_servers(protocol, name)
        if len(matches) != 1:
            raise ValueError(
                "get_port() requires protocol/name when multiple protocol instances are running."
            )
        server = matches[0].server
        get_port = getattr(server, "get_port", None)
        if get_port is None:
            raise ValueError(f"Protocol instance {matches[0].instance.full_name} has no port.")
        return get_port()

    def _matching_servers(
        self, protocol: Optional[str], name: Optional[str]
    ) -> list[RunningProtocolInstance]:
        matches = self.servers
        if protocol is not None:
            matches = [
                running for running in matches if running.instance.protocol == protocol
            ]
        if name is not None:
            matches = [running for running in matches if running.instance.name == name]
        return matches


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Start the DECEIVE honeypot server.")
    parser.add_argument("-c", "--config", type=str, default=None, help="Path to the configuration file")
    parser.add_argument("-p", "--prompt", type=str, help="Fallback prompt text for enabled protocol instances")
    parser.add_argument("-f", "--prompt-file", type=str, help="Fallback prompt file for enabled protocol instances")
    parser.add_argument("-l", "--llm-provider", type=str, help="The LLM provider to use")
    parser.add_argument("-m", "--model-name", type=str, help="The model name to use")
    parser.add_argument("-t", "--trimmer-max-tokens", type=int, help="The maximum number of tokens to send to the LLM backend in a single request")
    parser.add_argument("-s", "--system-prompt", type=str, help="System prompt for the LLM")
    parser.add_argument("-r", "--temperature", type=float, help="Temperature parameter for controlling randomness in LLM responses (0.0-2.0)")
    parser.add_argument("--disable-llm-tls-verify", action="store_true", help="Disable TLS certificate verification for supported outbound LLM clients")
    parser.add_argument("--protocol", choices=["ssh", "http", "https"], help="Create and enable one protocol instance from CLI options")
    parser.add_argument("--protocol-instance", default="main", help="Instance name to use with --protocol")
    parser.add_argument("--listen-host", help="Listener bind address for the CLI protocol instance")
    parser.add_argument("-P", "--port", type=int, help="Listener port override")
    parser.add_argument("-k", "--host-priv-key", type=str, help="Legacy SSH host key override")
    parser.add_argument("-v", "--server-version-string", type=str, help="Legacy SSH server version string override")
    parser.add_argument("--cert-file", type=str, help="HTTPS certificate file for the CLI protocol instance")
    parser.add_argument("--key-file", type=str, help="HTTPS private key file for the CLI protocol instance")
    parser.add_argument("--content-type", type=str, help="HTTP/HTTPS response content type for the CLI protocol instance")
    parser.add_argument("--default-status", type=int, help="HTTP/HTTPS response status for the CLI protocol instance")
    parser.add_argument("--session-cookie-name", type=str, help="HTTP/HTTPS session cookie name for the CLI protocol instance")
    parser.add_argument("-L", "--log-file", type=str, help="The name of the file you wish to write the honeypot log to")
    parser.add_argument("-S", "--sensor-name", type=str, help="The name of the sensor, used to identify this honeypot in the logs")
    parser.add_argument("-u", "--user-account", action="append", help="User account in the form username=password. Can be repeated.")
    return parser.parse_args(argv)


def configure_runtime(args, message_history=None) -> DeceiveRuntime:
    global runtime

    config, config_base_dir = load_config(args, script_dir=REPO_ROOT)
    apply_args_to_config(config, args)
    instances = discover_protocol_instances(config)
    runtime = DeceiveRuntime(
        config,
        config_base_dir,
        instances,
        script_dir=REPO_ROOT,
        prompt=args.prompt,
        prompt_file=args.prompt_file,
        message_history=message_history,
    )
    if message_history is None:
        for instance in runtime.enabled_instances():
            runtime.get_message_history(instance)
    return runtime


async def start_server(runtime_override: DeceiveRuntime | None = None) -> ServerGroup:
    active_runtime = runtime_override or runtime
    if active_runtime is None:
        raise RuntimeError("DECEIVE runtime is not configured.")

    enabled_instances = active_runtime.enabled_instances()
    if not enabled_instances:
        raise ValueError("No enabled protocol instances found in configuration.")

    servers = []
    for instance in enabled_instances:
        adapter = get_protocol_adapter(instance.protocol)
        server = await adapter.start_instance(active_runtime, instance)
        servers.append(RunningProtocolInstance(instance, server))

    return ServerGroup(servers)


def main(argv=None) -> int:
    try:
        args = parse_args(argv)
        configure_runtime(args)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        server_group = loop.run_until_complete(start_server())
        loop.set_exception_handler(
            lambda _loop, context: print(
                f"Async error: {context.get('message')}", file=sys.stderr
            )
        )
        loop.run_forever()
        server_group.close()
        loop.run_until_complete(server_group.wait_closed())
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
