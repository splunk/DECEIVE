from __future__ import annotations

from configparser import ConfigParser
import os
import re
import socket
import sys

from deceive.runtime import ProtocolInstanceConfig


PROTOCOL_SECTION_RE = re.compile(r"^protocol:([^:]+):([^:]+)$")


def load_config(args, *, script_dir: str) -> tuple[ConfigParser, str]:
    loaded_config = ConfigParser()
    if args.config is not None:
        if not os.path.exists(args.config):
            print(
                f"Error: The specified config file '{args.config}' does not exist.",
                file=sys.stderr,
            )
            sys.exit(1)
        loaded_config.read(args.config)
        config_base_dir = os.path.dirname(os.path.abspath(args.config))
    else:
        default_config = resolve_runtime_path("config.ini", script_dir, script_dir)
        if os.path.exists(default_config):
            loaded_config.read(default_config)
            config_base_dir = os.path.dirname(os.path.abspath(default_config))
        else:
            loaded_config["honeypot"] = {
                "log_file": "deceive.log" if args.protocol else "ssh_log.log",
                "sensor_name": socket.gethostname(),
            }
            if not args.protocol:
                loaded_config["ssh"] = {
                    "port": "8022",
                    "host_priv_key": "ssh_host_key",
                    "server_version_string": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3",
                    "prompt_file": "SSH/prompt.txt",
                }
            loaded_config["llm"] = {
                "llm_provider": "openai",
                "model_name": "gpt-3.5-turbo",
                "trimmer_max_tokens": "64000",
                "temperature": "0.7",
                "system_prompt": "",
            }
            loaded_config["user_accounts"] = {}
            config_base_dir = script_dir

    ensure_required_sections(loaded_config)
    return loaded_config, config_base_dir


def resolve_runtime_path(path: str, config_base_dir: str, script_dir: str) -> str:
    if os.path.isabs(path) or os.path.exists(path):
        return path

    for base_dir in (config_base_dir, script_dir):
        candidate = os.path.join(base_dir, path)
        if os.path.exists(candidate):
            return candidate

    return path


def ensure_required_sections(config: ConfigParser) -> None:
    if "honeypot" not in config:
        config["honeypot"] = {
            "log_file": "deceive.log",
            "sensor_name": socket.gethostname(),
        }
    if "llm" not in config:
        config["llm"] = {
            "llm_provider": "openai",
            "model_name": "gpt-4o-mini",
            "trimmer_max_tokens": "64000",
            "temperature": "0.2",
            "system_prompt": "",
        }


def apply_args_to_config(config: ConfigParser, args) -> None:
    if args.llm_provider:
        config["llm"]["llm_provider"] = args.llm_provider
    if args.model_name:
        config["llm"]["model_name"] = args.model_name
    if args.trimmer_max_tokens:
        config["llm"]["trimmer_max_tokens"] = str(args.trimmer_max_tokens)
    if args.system_prompt:
        config["llm"]["system_prompt"] = args.system_prompt
    if args.temperature is not None:
        config["llm"]["temperature"] = str(args.temperature)
    if args.disable_llm_tls_verify:
        config["llm"]["tls_verify"] = "false"
    if args.log_file:
        config["honeypot"]["log_file"] = args.log_file
    if args.sensor_name:
        config["honeypot"]["sensor_name"] = args.sensor_name

    if args.user_account:
        if "user_accounts" not in config:
            config["user_accounts"] = {}
        for account in args.user_account:
            if "=" in account:
                key, value = account.split("=", 1)
                config["user_accounts"][key.strip()] = value.strip()
            else:
                config["user_accounts"][account.strip()] = ""

    if args.protocol:
        apply_cli_protocol_instance(config, args)
        return

    if any([args.port is not None, args.host_priv_key, args.server_version_string]):
        if "ssh" not in config:
            config["ssh"] = {}
        if args.port is not None:
            config["ssh"]["port"] = str(args.port)
        if args.host_priv_key:
            config["ssh"]["host_priv_key"] = args.host_priv_key
        if args.server_version_string:
            config["ssh"]["server_version_string"] = args.server_version_string


def apply_cli_protocol_instance(config: ConfigParser, args) -> None:
    protocol = args.protocol.lower()
    section = f"protocol:{protocol}:{args.protocol_instance}"
    if section not in config:
        config[section] = {}

    instance_config = config[section]
    instance_config["enabled"] = "true"

    if args.listen_host is not None:
        instance_config["listen_host"] = args.listen_host
    if args.port is not None:
        instance_config["port"] = str(args.port)
    if args.prompt is not None:
        instance_config["prompt"] = args.prompt
    if args.prompt_file is not None:
        instance_config["prompt_file"] = args.prompt_file

    if protocol == "ssh":
        if args.host_priv_key is not None:
            instance_config["host_priv_key"] = args.host_priv_key
        if args.server_version_string is not None:
            instance_config["server_version_string"] = args.server_version_string

    if protocol in {"http", "https"}:
        if args.content_type is not None:
            instance_config["content_type"] = args.content_type
        if args.default_status is not None:
            instance_config["default_status"] = str(args.default_status)
        if args.session_cookie_name is not None:
            instance_config["session_cookie_name"] = args.session_cookie_name

    if protocol == "https":
        if args.cert_file is not None:
            instance_config["cert_file"] = args.cert_file
        if args.key_file is not None:
            instance_config["key_file"] = args.key_file


def discover_protocol_instances(config: ConfigParser) -> list[ProtocolInstanceConfig]:
    protocol_sections = []
    for section in config.sections():
        match = PROTOCOL_SECTION_RE.match(section)
        if match:
            protocol_sections.append((section, match.group(1).lower(), match.group(2)))

    if protocol_sections:
        return [
            ProtocolInstanceConfig(
                protocol=protocol,
                name=name,
                section=section,
                options=dict(config.items(section)),
            )
            for section, protocol, name in protocol_sections
        ]

    if "ssh" in config:
        options = dict(config.items("ssh"))
        options["enabled"] = "true"
        return [
            ProtocolInstanceConfig(
                protocol="ssh",
                name="main",
                section="ssh",
                options=options,
                legacy=True,
            )
        ]

    return []
