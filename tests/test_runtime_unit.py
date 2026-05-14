import asyncio
from configparser import ConfigParser
import json
import logging
from pathlib import Path

import httpx
import pytest

import deceive.runtime as runtime_module
from deceive.config import discover_protocol_instances
from deceive.registry import get_protocol_adapter
from deceive.runtime import (
    ContextFilter,
    DeceiveRuntime,
    JSONFormatter,
    ProtocolInstanceConfig,
    SessionSummaryState,
    get_connection_log_extra,
    get_session_id,
    merge_log_extra,
    new_session_id,
)
from deceive import server
from deceive.protocols.ssh import MySSHServer
from conftest import FakeLLMResponse


def _write_legacy_config(path, log_file="ssh_log.log"):
    path.write_text(
        f"""
[honeypot]
log_file = {log_file}
sensor_name = template-sensor

[ssh]
port = 8022
host_priv_key = ssh_host_key
server_version_string = OpenSSH_Template

[llm]
llm_provider = openai
model_name = gpt-4o
trimmer_max_tokens = 64000
temperature = 0.2
system_prompt = template system

[user_accounts]
old = oldpw
""".lstrip()
    )


def test_configure_runtime_loads_legacy_config_and_applies_cli_overrides(tmp_path):
    config_file = tmp_path / "config.ini"
    log_file = tmp_path / "override.log"
    _write_legacy_config(config_file)

    fake_history = object()
    args = server.parse_args(
        [
            "--config",
            str(config_file),
            "--llm-provider",
            "ollama",
            "--model-name",
            "llama3.3",
            "--trimmer-max-tokens",
            "123",
            "--system-prompt",
            "system override",
            "--temperature",
            "0.4",
            "--disable-llm-tls-verify",
            "--port",
            "2222",
            "--host-priv-key",
            "custom_host_key",
            "--server-version-string",
            "OpenSSH_Test",
            "--log-file",
            str(log_file),
            "--sensor-name",
            "sensor-override",
            "--user-account",
            "guest=",
            "--user-account",
            "root=*",
            "--user-account",
            "analyst",
        ]
    )

    runtime = server.configure_runtime(args, message_history=fake_history)

    assert runtime.config_base_dir == str(tmp_path)
    assert runtime.message_history_override is fake_history
    assert runtime.config["llm"]["llm_provider"] == "ollama"
    assert runtime.config["llm"]["model_name"] == "llama3.3"
    assert runtime.config["llm"]["trimmer_max_tokens"] == "123"
    assert runtime.config["llm"]["system_prompt"] == "system override"
    assert runtime.config["llm"]["temperature"] == "0.4"
    assert runtime.config["llm"]["tls_verify"] == "false"
    assert runtime.config["ssh"]["port"] == "2222"
    assert runtime.config["ssh"]["host_priv_key"] == "custom_host_key"
    assert runtime.config["ssh"]["server_version_string"] == "OpenSSH_Test"
    assert runtime.config["honeypot"]["log_file"] == str(log_file)
    assert runtime.config["honeypot"]["sensor_name"] == "sensor-override"
    assert runtime.accounts["old"] == "oldpw"
    assert runtime.accounts["guest"] == ""
    assert runtime.accounts["root"] == "*"
    assert runtime.accounts["analyst"] == ""
    assert len(runtime.protocol_instances) == 1
    instance = runtime.protocol_instances[0]
    assert instance.protocol == "ssh"
    assert instance.name == "main"
    assert instance.enabled is True
    assert instance.legacy is True


def test_load_config_exits_when_explicit_config_is_missing(tmp_path, capsys):
    missing_config = tmp_path / "missing.ini"
    args = server.parse_args(["--config", str(missing_config)])

    with pytest.raises(SystemExit) as exc_info:
        server.configure_runtime(args, message_history=object())

    assert exc_info.value.code == 1
    assert f"specified config file '{missing_config}' does not exist" in capsys.readouterr().err


def test_runtime_path_resolution_prefers_config_directory_then_script_directory(
    tmp_path, minimal_config
):
    config_dir = tmp_path / "configured"
    script_dir = tmp_path / "script"
    config_dir.mkdir()
    script_dir.mkdir()
    config_file = config_dir / "asset.txt"
    script_file = script_dir / "script-only.txt"
    absolute_file = tmp_path / "absolute.txt"
    config_file.write_text("from config")
    script_file.write_text("from script")
    absolute_file.write_text("absolute")

    runtime = DeceiveRuntime(
        minimal_config,
        str(config_dir),
        [],
        script_dir=str(script_dir),
        prompt="fallback prompt",
        message_history=object(),
    )

    assert runtime.resolve_runtime_path("asset.txt") == str(config_file)
    assert runtime.resolve_runtime_path("script-only.txt") == str(script_file)
    assert runtime.resolve_runtime_path(str(absolute_file)) == str(absolute_file)
    assert runtime.resolve_runtime_path("missing.txt") == "missing.txt"
    assert runtime.resolve_config_output_path("out.log") == str(config_dir / "out.log")


def test_get_prompts_honors_inline_prompt_and_config_relative_prompt_file(
    tmp_path, minimal_config, capsys
):
    prompt_file = tmp_path / "prompt.txt"
    prompt_file.write_text("file prompt")
    runtime = DeceiveRuntime(
        minimal_config,
        str(tmp_path),
        [],
        script_dir=str(tmp_path),
        prompt="fallback prompt",
        message_history=object(),
    )

    inline_instance = ProtocolInstanceConfig(
        "http", "inline", "protocol:http:inline", {"prompt": "inline prompt"}
    )
    file_instance = ProtocolInstanceConfig(
        "http", "file", "protocol:http:file", {"prompt_file": "prompt.txt"}
    )
    blank_instance = ProtocolInstanceConfig(
        "http", "blank", "protocol:http:blank", {"prompt": "   "}
    )
    missing_instance = ProtocolInstanceConfig(
        "http", "missing", "protocol:http:missing", {"prompt_file": "missing.txt"}
    )

    assert runtime.get_prompts(inline_instance)["user_prompt"] == "inline prompt"
    assert runtime.get_prompts(file_instance)["user_prompt"] == "file prompt"

    with pytest.raises(SystemExit) as blank_exit:
        runtime.get_prompts(blank_instance)
    assert blank_exit.value.code == 1
    assert "prompt text cannot be empty" in capsys.readouterr().err

    with pytest.raises(SystemExit) as missing_exit:
        runtime.get_prompts(missing_instance)
    assert missing_exit.value.code == 1
    assert "specified prompt file" in capsys.readouterr().err


def test_protocol_instances_default_disabled_and_legacy_is_ignored_when_present():
    config = ConfigParser()
    config["ssh"] = {"port": "8022"}
    config["protocol:http:marketing"] = {"port": "8080"}
    config["protocol:http:api"] = {"enabled": "true", "port": "8081"}

    instances = discover_protocol_instances(config)

    assert [(instance.protocol, instance.name) for instance in instances] == [
        ("http", "marketing"),
        ("http", "api"),
    ]
    assert instances[0].enabled is False
    assert instances[1].enabled is True
    assert all(not instance.legacy for instance in instances)


def test_cli_protocol_creates_enabled_http_instance_without_config(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "REPO_ROOT", str(tmp_path))
    log_file = tmp_path / "http.log"
    args = server.parse_args(
        [
            "--protocol",
            "http",
            "--protocol-instance",
            "marketing",
            "--listen-host",
            "127.0.0.1",
            "--port",
            "8080",
            "--prompt",
            "Simulate a website.",
            "--content-type",
            "text/html",
            "--default-status",
            "201",
            "--session-cookie-name",
            "site_session",
            "--log-file",
            str(log_file),
        ]
    )

    runtime = server.configure_runtime(args, message_history=object())

    assert runtime.config_base_dir == str(tmp_path)
    assert runtime.config["honeypot"]["log_file"] == str(log_file)
    assert "ssh" not in runtime.config
    assert len(runtime.protocol_instances) == 1
    instance = runtime.protocol_instances[0]
    assert instance.full_name == "http:marketing"
    assert instance.enabled is True
    assert instance.options["listen_host"] == "127.0.0.1"
    assert instance.options["port"] == "8080"
    assert instance.options["prompt"] == "Simulate a website."
    assert instance.options["content_type"] == "text/html"
    assert instance.options["default_status"] == "201"
    assert instance.options["session_cookie_name"] == "site_session"


def test_cli_protocol_creates_enabled_https_instance_with_tls_options(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(server, "REPO_ROOT", str(tmp_path))
    args = server.parse_args(
        [
            "--protocol",
            "https",
            "--port",
            "8443",
            "--prompt",
            "Simulate a secure website.",
            "--cert-file",
            "cert.pem",
            "--key-file",
            "key.pem",
        ]
    )

    runtime = server.configure_runtime(args, message_history=object())

    instance = runtime.protocol_instances[0]
    assert instance.full_name == "https:main"
    assert instance.enabled is True
    assert instance.options["port"] == "8443"
    assert instance.options["cert_file"] == "cert.pem"
    assert instance.options["key_file"] == "key.pem"


def test_registry_resolves_known_protocols_and_rejects_unknown():
    assert get_protocol_adapter("ssh").name == "ssh"
    assert get_protocol_adapter("http").name == "http"
    assert get_protocol_adapter("https").name == "https"

    with pytest.raises(ValueError, match="Unknown protocol 'smtp'"):
        get_protocol_adapter("smtp")


def test_get_user_accounts_requires_accounts_only_when_requested(minimal_config):
    runtime = DeceiveRuntime(
        minimal_config,
        "/tmp",
        [],
        script_dir="/tmp",
        prompt="fallback prompt",
        message_history=object(),
    )

    assert runtime.get_user_accounts(required=False) == {}
    with pytest.raises(ValueError, match="No user accounts"):
        runtime.get_user_accounts(required=True)


def test_json_formatter_emits_unified_log_shape():
    formatter = JSONFormatter("sensor-a")
    record = logging.LogRecord(
        name="deceive",
        level=logging.INFO,
        pathname="runtime.py",
        lineno=123,
        msg="hello %s",
        args=("world",),
        exc_info=None,
    )
    record.task_name = "session-1"
    record.sensor_protocol = "http"
    record.protocol_instance = "http:marketing"
    record.src_ip = "192.0.2.10"
    record.src_port = 5555
    record.dst_ip = "198.51.100.20"
    record.dst_port = 80
    record.interactive = False
    record.details = "R0VUIC8="
    record.http_method = "GET"
    record.http_path = "/"

    data = json.loads(formatter.format(record))

    assert data["timestamp"].endswith("+00:00")
    assert data["level"] == "INFO"
    assert data["task_name"] == "session-1"
    assert data["sensor_name"] == "sensor-a"
    assert data["sensor_protocol"] == "http"
    assert data["protocol_instance"] == "http:marketing"
    assert data["src_ip"] == "192.0.2.10"
    assert data["src_port"] == 5555
    assert data["dst_ip"] == "198.51.100.20"
    assert data["dst_port"] == 80
    assert data["message"] == "hello world"
    assert data["details"] == "R0VUIC8="
    assert data["interactive"] is False
    assert data["http_method"] == "GET"
    assert data["http_path"] == "/"
    assert "pathname" not in data


class FakeExtraInfoSource:
    def __init__(self, peername=None, sockname=None, deceive_session_id=None):
        self._extra_info = {
            "peername": peername,
            "sockname": sockname,
            "deceive_session_id": deceive_session_id,
        }

    def get_extra_info(self, name, default=None):
        return self._extra_info.get(name, default)


def test_session_and_connection_helpers():
    source = FakeExtraInfoSource(
        peername=("192.0.2.10", 4444),
        sockname=("198.51.100.20", 22),
        deceive_session_id="session-test",
    )

    assert new_session_id().startswith("session-")
    assert get_session_id(source) == "session-test"
    assert get_session_id(None, fallback="session-fallback") == "session-fallback"
    assert get_connection_log_extra(source) == {
        "src_ip": "192.0.2.10",
        "src_port": 4444,
        "dst_ip": "198.51.100.20",
        "dst_port": 22,
    }
    assert merge_log_extra({"a": 1}, b=2) == {"a": 1, "b": 2}


def test_get_connection_log_extra_defaults_missing_endpoints():
    assert get_connection_log_extra(FakeExtraInfoSource(sockname=("198.51.100.20", 22))) == {
        "src_ip": "-",
        "src_port": "-",
        "dst_ip": "198.51.100.20",
        "dst_port": 22,
    }
    assert get_connection_log_extra(FakeExtraInfoSource(peername=("192.0.2.10", 4444))) == {
        "src_ip": "192.0.2.10",
        "src_port": 4444,
        "dst_ip": "-",
        "dst_port": "-",
    }


@pytest.mark.asyncio
async def test_context_filter_adds_async_task_context():
    asyncio.current_task().set_name("session-test")
    record = logging.LogRecord("deceive", logging.INFO, "runtime.py", 1, "msg", (), None)

    assert ContextFilter().filter(record) is True
    assert record.task_name == "session-test"
    assert record.sensor_protocol == "-"
    assert record.protocol_instance == "-"


@pytest.mark.asyncio
async def test_context_filter_preserves_explicit_task_name():
    asyncio.current_task().set_name("asyncio-task")
    record = logging.LogRecord("deceive", logging.INFO, "runtime.py", 1, "msg", (), None)
    record.task_name = "session-explicit"

    assert ContextFilter().filter(record) is True
    assert record.task_name == "session-explicit"


def test_llm_session_history_is_created_once_per_session_id(minimal_config, make_runtime):
    runtime = make_runtime(minimal_config, [])

    first = runtime.llm_get_session_history("session-a")
    second = runtime.llm_get_session_history("session-a")
    other = runtime.llm_get_session_history("session-b")

    assert first is second
    assert other is not first


def test_choose_llm_instantiates_supported_providers_with_configured_options(
    monkeypatch, minimal_config, make_runtime
):
    def fake_model(provider_name):
        class FakeModel:
            def __init__(self, **kwargs):
                self.provider_name = provider_name
                self.kwargs = kwargs

        return FakeModel

    monkeypatch.setattr(runtime_module, "ChatOpenAI", fake_model("openai"))
    monkeypatch.setattr(runtime_module, "AzureChatOpenAI", fake_model("azure"))
    monkeypatch.setattr(runtime_module, "ChatOllama", fake_model("ollama"))
    monkeypatch.setattr(runtime_module, "ChatBedrockConverse", fake_model("aws"))
    monkeypatch.setattr(runtime_module, "ChatGoogleGenerativeAI", fake_model("gemini"))

    minimal_config["llm"] = {
        "llm_provider": "openai",
        "model_name": "configured-model",
        "temperature": "0.3",
        "azure_deployment": "deployment-name",
        "azure_endpoint": "https://azure.example",
        "azure_api_version": "2025-01-01-preview",
        "aws_region": "us-west-2",
        "aws_credentials_profile": "deceive-profile",
    }
    runtime = make_runtime(minimal_config, [])

    openai = runtime.choose_llm("OpenAI", "model-x")
    assert openai.provider_name == "openai"
    assert openai.kwargs == {"model": "model-x", "temperature": 0.3}

    ollama = runtime.choose_llm("ollama", "model-x")
    assert ollama.provider_name == "ollama"
    assert ollama.kwargs == {"model": "model-x", "temperature": 0.3}

    aws = runtime.choose_llm("AWS", "model-x")
    assert aws.provider_name == "aws"
    assert aws.kwargs == {
        "model": "model-x",
        "region_name": "us-west-2",
        "credentials_profile_name": "deceive-profile",
        "temperature": 0.3,
    }

    gemini = runtime.choose_llm("gemini", "model-x")
    assert gemini.provider_name == "gemini"
    assert gemini.kwargs == {"model": "model-x", "temperature": 0.3}

    azure = runtime.choose_llm("azure")
    assert azure.provider_name == "azure"
    assert azure.kwargs == {
        "azure_deployment": "deployment-name",
        "azure_endpoint": "https://azure.example",
        "api_version": "2025-01-01-preview",
        "model": "configured-model",
        "temperature": 0.3,
    }


def test_choose_llm_rejects_unknown_provider(minimal_config, make_runtime):
    runtime = make_runtime(minimal_config, [])

    with pytest.raises(ValueError, match="Invalid LLM provider"):
        runtime.choose_llm("bogus")


def test_disable_llm_tls_verify_passes_httpx_clients_to_openai(
    monkeypatch, minimal_config, make_runtime
):
    class FakeOpenAI:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    monkeypatch.setattr(runtime_module, "ChatOpenAI", FakeOpenAI)
    minimal_config["llm"]["tls_verify"] = "false"
    runtime = make_runtime(minimal_config, [])

    model = runtime.choose_llm("openai", "model-x")

    assert model.kwargs["model"] == "model-x"
    assert model.kwargs["temperature"] == 0.0
    assert isinstance(model.kwargs["http_client"], httpx.Client)
    assert isinstance(model.kwargs["http_async_client"], httpx.AsyncClient)


def test_disable_llm_tls_verify_passes_verify_false_to_ollama(
    monkeypatch, minimal_config, make_runtime
):
    class FakeOllama:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    monkeypatch.setattr(runtime_module, "ChatOllama", FakeOllama)
    minimal_config["llm"]["tls_verify"] = "false"
    runtime = make_runtime(minimal_config, [])

    model = runtime.choose_llm("ollama", "model-x")

    assert model.kwargs["client_kwargs"] == {"verify": False}
    assert model.kwargs["async_client_kwargs"] == {"verify": False}
    assert model.kwargs["sync_client_kwargs"] == {"verify": False}


def test_ssh_authentication_contracts_for_honeypot_login_modes(
    minimal_config, make_runtime
):
    minimal_config["user_accounts"] = {
        "guest": "",
        "user1": "secretpw",
        "root": "*",
    }
    instance = ProtocolInstanceConfig(
        "ssh", "main", "protocol:ssh:main", {"enabled": "true"}
    )
    runtime = make_runtime(minimal_config, [instance])
    ssh_server = MySSHServer(runtime, instance)

    assert ssh_server.password_auth_supported() is True
    assert ssh_server.host_based_auth_supported() is False
    assert ssh_server.public_key_auth_supported() is False
    assert ssh_server.kbdinit_auth_supported() is False

    assert ssh_server.begin_auth("guest") is False
    assert ssh_server.begin_auth("user1") is True
    assert ssh_server.begin_auth("root") is True
    assert ssh_server.begin_auth("intruder") is True

    assert ssh_server.validate_password("user1", "secretpw") is True
    assert ssh_server.validate_password("user1", "wrong") is False
    assert ssh_server.validate_password("root", "") is True
    assert ssh_server.validate_password("root", "anything") is True
    assert ssh_server.validate_password("intruder", "") is True
    assert ssh_server.validate_password("intruder", "anything") is True


@pytest.mark.asyncio
async def test_session_summary_logs_judgement_once(minimal_config, make_runtime):
    class SummaryMessageHistory:
        def __init__(self):
            self.calls = []

        async def ainvoke(self, payload, config=None):
            self.calls.append((payload, config))
            return FakeLLMResponse(
                "The user attempted post-foothold reconnaissance.\n\nJudgement: MALICIOUS"
            )

    instance = ProtocolInstanceConfig(
        "ssh", "main", "protocol:ssh:main", {"enabled": "true"}
    )
    session = SummaryMessageHistory()
    runtime = make_runtime(minimal_config, [instance], message_history=session)
    log_extra = {
        "src_ip": "192.0.2.10",
        "src_port": 4444,
        "dst_ip": "198.51.100.20",
        "dst_port": 22,
        "task_name": "session-a",
        "sensor_protocol": "ssh",
        "protocol_instance": "ssh:main",
    }
    summary_state = SessionSummaryState()

    await runtime.summarize_session(
        summary_state, instance, "session-a", username="guest", log_extra=log_extra
    )
    await runtime.summarize_session(
        summary_state, instance, "session-a", username="guest", log_extra=log_extra
    )

    assert len(session.calls) == 1
    payload, config = session.calls[0]
    assert payload["username"] == "guest"
    assert payload["interactive"] is True
    assert "Examine the list of all the SSH commands" in payload["messages"][0].content
    assert config == {"configurable": {"session_id": "session-a"}}
    assert summary_state.summary_generated is True

    for handler in runtime.logger.handlers:
        handler.flush()
    records = [
        json.loads(line)
        for line in Path(minimal_config["honeypot"]["log_file"]).read_text().splitlines()
    ]
    assert len(records) == 1
    assert records[0]["message"] == "Session summary"
    assert records[0]["sensor_protocol"] == "ssh"
    assert records[0]["protocol_instance"] == "ssh:main"
    assert records[0]["details"].endswith("Judgement: MALICIOUS")
    assert records[0]["judgement"] == "MALICIOUS"
