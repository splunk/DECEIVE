import asyncio
from base64 import b64decode
from configparser import ConfigParser
import json
from pathlib import Path
import sys
import threading

import asyncssh
import pytest
import pytest_asyncio


REPO_ROOT = Path(__file__).resolve().parents[1]
SSH_DIR = REPO_ROOT / "SSH"
sys.path.insert(0, str(SSH_DIR))

import ssh_server  # noqa: E402


PROMPT = "guest@deceive-test:~$ "


class FakeLLMResponse:
    def __init__(self, content: str):
        self.content = content


class ScriptedMessageHistory:
    async def ainvoke(self, payload, config=None):
        message = payload["messages"][-1].content
        username = payload["username"]
        interactive = payload["interactive"]

        if "Examine the list of all the SSH commands" in message:
            return FakeLLMResponse("The user ran a simple test command.\n\nJudgement: BENIGN")
        if message == "":
            return FakeLLMResponse(f"Welcome to deceive-test\n{PROMPT}")
        if message == "exit":
            return FakeLLMResponse("YYY-END-OF-SESSION-YYY")
        if message == "pwd":
            if interactive:
                return FakeLLMResponse(f"/home/{username}\n{PROMPT}")
            return FakeLLMResponse(f"/home/{username}\n")

        suffix = PROMPT if interactive else ""
        return FakeLLMResponse(f"ran {message}\n{suffix}")


@pytest.fixture(autouse=True)
def quiet_asyncio_debug():
    loop = asyncio.get_event_loop()
    loop.set_debug(False)
    loop.slow_callback_duration = 10


@pytest.fixture
def configured_runtime(tmp_path):
    host_key = tmp_path / "ssh_host_key"
    log_file = tmp_path / "ssh_log.log"

    key = asyncssh.generate_private_key("ssh-rsa")
    key.write_private_key(str(host_key))

    ssh_server.config = ConfigParser()
    ssh_server.config["honeypot"] = {
        "log_file": str(log_file),
        "sensor_name": "integration-test",
    }
    ssh_server.config["ssh"] = {
        "listen_host": "127.0.0.1",
        "port": "0",
        "host_priv_key": str(host_key),
        "server_version_string": "OpenSSH_8.2p1 Ubuntu-4ubuntu0.3",
    }
    ssh_server.config["llm"] = {
        "llm_provider": "fake",
        "model_name": "fake",
        "trimmer_max_tokens": "64000",
        "temperature": "0.0",
        "system_prompt": "",
    }
    ssh_server.config["user_accounts"] = {
        "guest": "",
        "user1": "secretpw",
        "root": "*",
    }
    ssh_server.accounts = ssh_server.get_user_accounts()
    ssh_server.llm_sessions = {}
    ssh_server.thread_local = threading.local()
    ssh_server.with_message_history = ScriptedMessageHistory()
    ssh_server.configure_logging()

    yield {"log_file": log_file}

    for handler in ssh_server.logger.handlers:
        handler.flush()
        handler.close()
    ssh_server.logger.handlers.clear()
    ssh_server.logger.filters.clear()


@pytest_asyncio.fixture
async def running_server(configured_runtime):
    server = await ssh_server.start_server()
    try:
        yield server
    finally:
        server.close()
        await server.wait_closed()


@pytest.fixture
def connect(running_server):
    async def _connect(username="guest", password=None):
        return await asyncssh.connect(
            "127.0.0.1",
            port=running_server.get_port(),
            username=username,
            password=password,
            known_hosts=None,
        )

    return _connect


@pytest.fixture
def log_records(configured_runtime):
    def _read_log_records():
        for handler in ssh_server.logger.handlers:
            handler.flush()
        return [
            json.loads(line)
            for line in configured_runtime["log_file"].read_text().splitlines()
            if line.strip()
        ]

    return _read_log_records


@pytest.mark.asyncio
async def test_non_interactive_command_runs_through_real_ssh_server(connect, log_records):
    async with await connect() as conn:
        result = await conn.run("pwd", check=True)

    assert result.stdout == "/home/guest\n"
    records = log_records()
    messages = [record["message"] for record in records]
    assert "SSH connection received" in messages
    assert "User input" in messages
    assert "LLM response" in messages
    assert "Session summary" in messages

    user_input = next(record for record in records if record["message"] == "User input")
    assert user_input["interactive"] is False
    assert b64decode(user_input["details"]).decode("utf-8") == "pwd"
    assert user_input["sensor_name"] == "integration-test"
    assert user_input["sensor_protocol"] == "ssh"
    assert user_input["task_name"].startswith("session-")

    summary = next(record for record in records if record["message"] == "Session summary")
    assert summary["judgement"] == "BENIGN"
    assert len([record for record in records if record["message"] == "Session summary"]) == 1


@pytest.mark.asyncio
async def test_interactive_session_runs_commands_and_exits(connect, log_records):
    async with await connect() as conn:
        process = await conn.create_process(term_type="xterm")
        banner = await asyncio.wait_for(process.stdout.readuntil(PROMPT), timeout=2)
        assert "Welcome to deceive-test" in banner

        process.stdin.write("pwd\n")
        output = await asyncio.wait_for(process.stdout.readuntil(PROMPT), timeout=2)
        assert "/home/guest" in output

        process.stdin.write("exit\n")
        await asyncio.wait_for(process.wait(), timeout=2)

    records = log_records()
    interactive_inputs = [
        record for record in records
        if record["message"] == "User input" and record["interactive"]
    ]
    assert [b64decode(record["details"]).decode("utf-8") for record in interactive_inputs] == ["pwd", "exit"]


@pytest.mark.asyncio
async def test_passwordless_fixed_wildcard_and_unknown_accounts_can_authenticate(connect):
    async with await connect(username="guest") as conn:
        result = await conn.run("pwd", check=True)
    assert result.stdout == "/home/guest\n"

    async with await connect(username="user1", password="secretpw") as conn:
        result = await conn.run("pwd", check=True)
    assert result.stdout == "/home/user1\n"

    async with await connect(username="root", password="anything") as conn:
        result = await conn.run("pwd", check=True)
    assert result.stdout == "/home/root\n"

    async with await connect(username="intruder", password="anything") as conn:
        result = await conn.run("pwd", check=True)
    assert result.stdout == "/home/intruder\n"


@pytest.mark.asyncio
async def test_wrong_password_is_rejected(connect):
    with pytest.raises(asyncssh.PermissionDenied):
        async with await connect(username="user1", password="wrong"):
            pass


@pytest.mark.asyncio
async def test_config_file_relative_host_key_can_start_real_ssh_server(tmp_path):
    host_key = tmp_path / "ssh_host_key"
    log_file = tmp_path / "ssh_log.log"
    config_file = tmp_path / "config.ini"

    key = asyncssh.generate_private_key("ssh-rsa")
    key.write_private_key(str(host_key))
    config_file.write_text(
        f"""
[honeypot]
log_file = {log_file}
sensor_name = config-relative-test

[ssh]
listen_host = 127.0.0.1
port = 0
host_priv_key = ssh_host_key
server_version_string = OpenSSH_8.2p1 Ubuntu-4ubuntu0.3

[llm]
llm_provider = fake
model_name = fake
trimmer_max_tokens = 64000
temperature = 0.0
system_prompt =

[user_accounts]
guest =
""".lstrip()
    )

    args = ssh_server.parse_args(["--config", str(config_file), "--prompt", "Simulate Linux."])
    ssh_server.configure_runtime(args, message_history=ScriptedMessageHistory())
    server = await ssh_server.start_server()
    try:
        assert server.get_port() > 0
        assert log_file.exists()
    finally:
        server.close()
        await server.wait_closed()


def test_config_file_relative_log_file_is_written_next_to_config(tmp_path, monkeypatch):
    config_dir = tmp_path / "config"
    cwd = tmp_path / "cwd"
    config_dir.mkdir()
    cwd.mkdir()
    config_file = config_dir / "config.ini"
    expected_log_file = config_dir / "ssh_log.log"
    config_file.write_text(
        """
[honeypot]
log_file = ssh_log.log
sensor_name = config-relative-test

[ssh]
port = 0
host_priv_key = ssh_host_key
server_version_string = OpenSSH_8.2p1 Ubuntu-4ubuntu0.3

[llm]
llm_provider = fake
model_name = fake
trimmer_max_tokens = 64000
temperature = 0.0
system_prompt =

[user_accounts]
guest =
""".lstrip()
    )
    monkeypatch.chdir(cwd)

    args = ssh_server.parse_args(["--config", str(config_file), "--prompt", "Simulate Linux."])
    ssh_server.configure_runtime(args, message_history=ScriptedMessageHistory())

    assert expected_log_file.exists()
    assert not (cwd / "ssh_log.log").exists()


@pytest.mark.asyncio
async def test_concurrent_connections_keep_log_source_ports_separate(connect, log_records):
    first = await connect()
    second = await connect()
    try:
        first_port = first.get_extra_info("sockname")[1]
        await first.run("first", check=True)
    finally:
        first.close()
        second.close()
        await first.wait_closed()
        await second.wait_closed()

    records = log_records()
    first_input = next(
        record for record in records
        if record["message"] == "User input"
        and b64decode(record["details"]).decode("utf-8") == "first"
    )
    assert first_input["src_port"] == first_port
