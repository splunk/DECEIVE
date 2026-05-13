import asyncio
from configparser import ConfigParser
import json
import logging
from types import SimpleNamespace

import pytest


def _write_config(path, log_file="ssh_log.log"):
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


def _configure_minimal_logging(ssh_server, log_file):
    ssh_server.config = ConfigParser()
    ssh_server.config["honeypot"] = {
        "log_file": str(log_file),
        "sensor_name": "unit-test",
    }
    ssh_server.configure_logging()


def test_configure_runtime_loads_config_and_applies_cli_overrides(tmp_path, ssh_module):
    config_file = tmp_path / "config.ini"
    log_file = tmp_path / "override.log"
    _write_config(config_file)

    fake_history = object()
    args = ssh_module.parse_args(
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

    ssh_module.configure_runtime(args, message_history=fake_history)

    assert ssh_module.config_base_dir == str(tmp_path)
    assert ssh_module.with_message_history is fake_history
    assert ssh_module.config["llm"]["llm_provider"] == "ollama"
    assert ssh_module.config["llm"]["model_name"] == "llama3.3"
    assert ssh_module.config["llm"]["trimmer_max_tokens"] == "123"
    assert ssh_module.config["llm"]["system_prompt"] == "system override"
    assert ssh_module.config["llm"]["temperature"] == "0.4"
    assert ssh_module.config["ssh"]["port"] == "2222"
    assert ssh_module.config["ssh"]["host_priv_key"] == "custom_host_key"
    assert ssh_module.config["ssh"]["server_version_string"] == "OpenSSH_Test"
    assert ssh_module.config["honeypot"]["log_file"] == str(log_file)
    assert ssh_module.config["honeypot"]["sensor_name"] == "sensor-override"
    assert ssh_module.accounts["old"] == "oldpw"
    assert ssh_module.accounts["guest"] == ""
    assert ssh_module.accounts["root"] == "*"
    assert ssh_module.accounts["analyst"] == ""


def test_load_config_exits_when_explicit_config_is_missing(tmp_path, capsys, ssh_module):
    missing_config = tmp_path / "missing.ini"
    args = ssh_module.parse_args(["--config", str(missing_config)])

    with pytest.raises(SystemExit) as exc_info:
        ssh_module.load_config(args)

    assert exc_info.value.code == 1
    assert f"specified config file '{missing_config}' does not exist" in capsys.readouterr().err


def test_resolve_runtime_path_prefers_config_directory_then_script_directory(
    tmp_path, monkeypatch, ssh_module
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

    monkeypatch.setattr(ssh_module, "config_base_dir", str(config_dir))
    monkeypatch.setattr(ssh_module, "SCRIPT_DIR", str(script_dir))

    assert ssh_module.resolve_runtime_path("asset.txt") == str(config_file)
    assert ssh_module.resolve_runtime_path("script-only.txt") == str(script_file)
    assert ssh_module.resolve_runtime_path(str(absolute_file)) == str(absolute_file)
    assert ssh_module.resolve_runtime_path("missing.txt") == "missing.txt"


def test_get_prompts_honors_inline_prompt_and_config_relative_prompt_file(
    tmp_path, monkeypatch, capsys, ssh_module
):
    prompt_file = tmp_path / "prompt.txt"
    prompt_file.write_text("file prompt")
    ssh_module.config = ConfigParser()
    ssh_module.config["llm"] = {"system_prompt": "system prompt"}
    monkeypatch.setattr(ssh_module, "config_base_dir", str(tmp_path))

    assert ssh_module.get_prompts("inline prompt", "prompt.txt") == {
        "system_prompt": "system prompt",
        "user_prompt": "inline prompt",
    }
    assert ssh_module.get_prompts(None, "prompt.txt") == {
        "system_prompt": "system prompt",
        "user_prompt": "file prompt",
    }

    with pytest.raises(SystemExit) as blank_exit:
        ssh_module.get_prompts("   ", None)
    assert blank_exit.value.code == 1
    assert "prompt text cannot be empty" in capsys.readouterr().err

    with pytest.raises(SystemExit) as missing_exit:
        ssh_module.get_prompts(None, "does-not-exist.txt")
    assert missing_exit.value.code == 1
    assert "specified prompt file" in capsys.readouterr().err


def test_get_user_accounts_requires_at_least_one_configured_account(ssh_module):
    ssh_module.config = ConfigParser()
    with pytest.raises(ValueError, match="No user accounts"):
        ssh_module.get_user_accounts()

    ssh_module.config["user_accounts"] = {}
    with pytest.raises(ValueError, match="No user accounts"):
        ssh_module.get_user_accounts()


def test_authentication_contracts_for_honeypot_login_modes(ssh_module):
    ssh_module.accounts = {
        "guest": "",
        "user1": "secretpw",
        "root": "*",
    }
    server = ssh_module.MySSHServer()

    assert server.password_auth_supported() is True
    assert server.host_based_auth_supported() is False
    assert server.public_key_auth_supported() is False
    assert server.kbdinit_auth_supported() is False

    assert server.begin_auth("guest") is False
    assert server.begin_auth("user1") is True
    assert server.begin_auth("root") is True
    assert server.begin_auth("intruder") is True

    assert server.validate_password("user1", "secretpw") is True
    assert server.validate_password("user1", "wrong") is False
    assert server.validate_password("root", "") is True
    assert server.validate_password("root", "anything") is True
    assert server.validate_password("intruder", "") is True
    assert server.validate_password("intruder", "anything") is True


def test_json_formatter_emits_documented_log_shape(ssh_module):
    formatter = ssh_module.JSONFormatter("sensor-a")
    record = logging.LogRecord(
        name="ssh_server",
        level=logging.INFO,
        pathname="ssh_server.py",
        lineno=123,
        msg="hello %s",
        args=("world",),
        exc_info=None,
    )
    record.task_name = "session-1"
    record.src_ip = "192.0.2.10"
    record.src_port = 5555
    record.dst_ip = "198.51.100.20"
    record.dst_port = 22
    record.interactive = False
    record.details = "cHdk"

    data = json.loads(formatter.format(record))

    assert data["timestamp"].endswith("+00:00")
    assert data["level"] == "INFO"
    assert data["task_name"] == "session-1"
    assert data["src_ip"] == "192.0.2.10"
    assert data["src_port"] == 5555
    assert data["dst_ip"] == "198.51.100.20"
    assert data["dst_port"] == 22
    assert data["message"] == "hello world"
    assert data["sensor_name"] == "sensor-a"
    assert data["sensor_protocol"] == "ssh"
    assert data["interactive"] is False
    assert data["details"] == "cHdk"


@pytest.mark.asyncio
async def test_context_filter_adds_async_task_and_connection_metadata(ssh_module):
    ssh_module.thread_local.src_ip = "192.0.2.10"
    ssh_module.thread_local.src_port = 4444
    ssh_module.thread_local.dst_ip = "198.51.100.20"
    ssh_module.thread_local.dst_port = 22
    asyncio.current_task().set_name("session-test")
    record = logging.LogRecord("ssh_server", logging.INFO, "ssh_server.py", 1, "msg", (), None)

    assert ssh_module.ContextFilter().filter(record) is True
    assert record.task_name == "session-test"
    assert record.src_ip == "192.0.2.10"
    assert record.src_port == 4444
    assert record.dst_ip == "198.51.100.20"
    assert record.dst_port == 22


def test_llm_session_history_is_created_once_per_session_id(ssh_module):
    first = ssh_module.llm_get_session_history("session-a")
    second = ssh_module.llm_get_session_history("session-a")
    other = ssh_module.llm_get_session_history("session-b")

    assert first is second
    assert other is not first


def test_choose_llm_instantiates_supported_providers_with_configured_options(
    monkeypatch, ssh_module
):
    def fake_model(provider_name):
        class FakeModel:
            def __init__(self, **kwargs):
                self.provider_name = provider_name
                self.kwargs = kwargs

        return FakeModel

    monkeypatch.setattr(ssh_module, "ChatOpenAI", fake_model("openai"))
    monkeypatch.setattr(ssh_module, "AzureChatOpenAI", fake_model("azure"))
    monkeypatch.setattr(ssh_module, "ChatOllama", fake_model("ollama"))
    monkeypatch.setattr(ssh_module, "ChatBedrockConverse", fake_model("aws"))
    monkeypatch.setattr(ssh_module, "ChatGoogleGenerativeAI", fake_model("gemini"))

    ssh_module.config = ConfigParser()
    ssh_module.config["llm"] = {
        "llm_provider": "openai",
        "model_name": "configured-model",
        "temperature": "0.3",
        "azure_deployment": "deployment-name",
        "azure_endpoint": "https://azure.example",
        "azure_api_version": "2025-01-01-preview",
        "aws_region": "us-west-2",
        "aws_credentials_profile": "deceive-profile",
    }

    openai = ssh_module.choose_llm("OpenAI", "model-x")
    assert openai.provider_name == "openai"
    assert openai.kwargs == {"model": "model-x", "temperature": 0.3}

    ollama = ssh_module.choose_llm("ollama", "model-x")
    assert ollama.provider_name == "ollama"
    assert ollama.kwargs == {"model": "model-x", "temperature": 0.3}

    aws = ssh_module.choose_llm("AWS", "model-x")
    assert aws.provider_name == "aws"
    assert aws.kwargs == {
        "model": "model-x",
        "region_name": "us-west-2",
        "credentials_profile_name": "deceive-profile",
        "temperature": 0.3,
    }

    gemini = ssh_module.choose_llm("gemini", "model-x")
    assert gemini.provider_name == "gemini"
    assert gemini.kwargs == {"model": "model-x", "temperature": 0.3}

    azure = ssh_module.choose_llm("azure")
    assert azure.provider_name == "azure"
    assert azure.kwargs == {
        "azure_deployment": "deployment-name",
        "azure_endpoint": "https://azure.example",
        "api_version": "2025-01-01-preview",
        "model": "configured-model",
        "temperature": 0.3,
    }


def test_choose_llm_rejects_unknown_provider(ssh_module):
    ssh_module.config = ConfigParser()
    ssh_module.config["llm"] = {
        "llm_provider": "openai",
        "model_name": "configured-model",
        "temperature": "0.2",
    }

    with pytest.raises(ValueError, match="Invalid LLM provider"):
        ssh_module.choose_llm("bogus")


@pytest.mark.asyncio
async def test_session_summary_logs_judgement_once(tmp_path, ssh_module):
    log_file = tmp_path / "ssh_log.log"
    _configure_minimal_logging(ssh_module, log_file)

    class FakeSession:
        def __init__(self):
            self.calls = []

        async def ainvoke(self, payload, config=None):
            self.calls.append((payload, config))
            return SimpleNamespace(
                content="The user attempted post-foothold reconnaissance.\n\nJudgement: MALICIOUS"
            )

    class FakeProcess:
        def get_extra_info(self, name):
            assert name == "username"
            return "guest"

    session = FakeSession()
    server = ssh_module.MySSHServer()
    llm_config = {"configurable": {"session_id": "session-a"}}

    await ssh_module.session_summary(FakeProcess(), llm_config, session, server)
    await ssh_module.session_summary(FakeProcess(), llm_config, session, server)

    assert len(session.calls) == 1
    payload, config = session.calls[0]
    assert payload["username"] == "guest"
    assert payload["interactive"] is True
    assert "Examine the list of all the SSH commands" in payload["messages"][0].content
    assert config == llm_config
    assert server.summary_generated is True

    for handler in ssh_module.logger.handlers:
        handler.flush()
    records = [json.loads(line) for line in log_file.read_text().splitlines()]
    assert len(records) == 1
    assert records[0]["message"] == "Session summary"
    assert records[0]["details"].endswith("Judgement: MALICIOUS")
    assert records[0]["judgement"] == "MALICIOUS"
