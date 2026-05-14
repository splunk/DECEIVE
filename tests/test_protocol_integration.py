import asyncio
from base64 import b64decode
from configparser import ConfigParser
import datetime
import json
from pathlib import Path
import ssl

import aiohttp
import asyncssh
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import pytest

from deceive import server
from conftest import ScriptedMessageHistory


PROMPT = "guest@deceive-test:~$ "


@pytest.fixture(autouse=True)
def quiet_asyncio_debug():
    loop = asyncio.get_event_loop()
    loop.set_debug(False)
    loop.slow_callback_duration = 10


@pytest.fixture
def log_records():
    def _read_log_records(runtime):
        for handler in runtime.logger.handlers:
            handler.flush()
        return [
            json.loads(line)
            for line in Path(runtime.config["honeypot"]["log_file"]).read_text().splitlines()
            if line.strip()
        ]

    return _read_log_records


async def wait_for_log_messages(runtime, log_records, expected_messages, timeout=2):
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    records = []
    while loop.time() < deadline:
        records = log_records(runtime)
        if expected_messages <= {record["message"] for record in records}:
            return records
        await asyncio.sleep(0.05)
    assert expected_messages <= {record["message"] for record in records}
    return records


def assert_single_session_id(records):
    session_ids = {record["task_name"] for record in records}
    assert len(session_ids) == 1
    session_id = session_ids.pop()
    assert session_id.startswith("session-")
    return session_id


def make_ssh_runtime(tmp_path):
    host_key = tmp_path / "ssh_host_key"
    log_file = tmp_path / "ssh_log.log"
    key = asyncssh.generate_private_key("ssh-rsa")
    key.write_private_key(str(host_key))

    config_file = tmp_path / "config.ini"
    config_file.write_text(
        f"""
[honeypot]
log_file = {log_file}
sensor_name = integration-test

[llm]
llm_provider = fake
model_name = fake
trimmer_max_tokens = 64000
temperature = 0.0
system_prompt =

[user_accounts]
guest =
user1 = secretpw
root = *

[protocol:ssh:main]
enabled = true
listen_host = 127.0.0.1
port = 0
host_priv_key = {host_key}
server_version_string = OpenSSH_8.2p1 Ubuntu-4ubuntu0.3
prompt = Simulate Linux.
""".lstrip()
    )
    args = server.parse_args(["--config", str(config_file)])
    runtime = server.configure_runtime(args, message_history=ScriptedMessageHistory())
    return runtime


@pytest.mark.asyncio
async def test_ssh_non_interactive_command_runs_through_registry(
    tmp_path, log_records
):
    runtime = make_ssh_runtime(tmp_path)
    server_group = await server.start_server(runtime)
    try:
        async with await asyncssh.connect(
            "127.0.0.1",
            port=server_group.get_port("ssh", "main"),
            username="guest",
            known_hosts=None,
        ) as conn:
            result = await conn.run("pwd", check=True)
    finally:
        server_group.close()
        await server_group.wait_closed()

    assert result.stdout == "/home/guest\n"
    records = await wait_for_log_messages(
        runtime,
        log_records,
        {"SSH connection received", "User input", "LLM response", "Session summary"},
    )
    user_input = next(record for record in records if record["message"] == "User input")
    assert user_input["interactive"] is False
    assert user_input["sensor_protocol"] == "ssh"
    assert user_input["protocol_instance"] == "ssh:main"
    assert b64decode(user_input["details"]).decode("utf-8") == "pwd"
    assert_single_session_id(
        [record for record in records if record["protocol_instance"] == "ssh:main"]
    )


@pytest.mark.asyncio
async def test_ssh_interactive_session_runs_commands_and_exits(tmp_path, log_records):
    runtime = make_ssh_runtime(tmp_path)
    server_group = await server.start_server(runtime)
    try:
        async with await asyncssh.connect(
            "127.0.0.1",
            port=server_group.get_port("ssh", "main"),
            username="guest",
            known_hosts=None,
        ) as conn:
            process = await conn.create_process(term_type="xterm")
            banner = await asyncio.wait_for(process.stdout.readuntil(PROMPT), timeout=2)
            assert "Welcome to deceive-test" in banner

            process.stdin.write("pwd\n")
            output = await asyncio.wait_for(process.stdout.readuntil(PROMPT), timeout=2)
            assert "/home/guest" in output

            process.stdin.write("exit\n")
            await asyncio.wait_for(process.wait(), timeout=2)
    finally:
        server_group.close()
        await server_group.wait_closed()

    records = await wait_for_log_messages(
        runtime, log_records, {"User input", "LLM response", "Session summary"}
    )
    interactive_inputs = [
        record
        for record in records
        if record["message"] == "User input" and record["interactive"]
    ]
    assert [b64decode(record["details"]).decode("utf-8") for record in interactive_inputs] == [
        "pwd",
        "exit",
    ]


@pytest.mark.asyncio
async def test_ssh_passwordless_fixed_wildcard_and_unknown_accounts_can_authenticate(
    tmp_path,
):
    runtime = make_ssh_runtime(tmp_path)
    server_group = await server.start_server(runtime)
    port = server_group.get_port("ssh", "main")
    try:
        async with await asyncssh.connect(
            "127.0.0.1", port=port, username="guest", known_hosts=None
        ) as conn:
            result = await conn.run("pwd", check=True)
        assert result.stdout == "/home/guest\n"

        async with await asyncssh.connect(
            "127.0.0.1",
            port=port,
            username="user1",
            password="secretpw",
            known_hosts=None,
        ) as conn:
            result = await conn.run("pwd", check=True)
        assert result.stdout == "/home/user1\n"

        async with await asyncssh.connect(
            "127.0.0.1",
            port=port,
            username="root",
            password="anything",
            known_hosts=None,
        ) as conn:
            result = await conn.run("pwd", check=True)
        assert result.stdout == "/home/root\n"

        async with await asyncssh.connect(
            "127.0.0.1",
            port=port,
            username="intruder",
            password="anything",
            known_hosts=None,
        ) as conn:
            result = await conn.run("pwd", check=True)
        assert result.stdout == "/home/intruder\n"
    finally:
        server_group.close()
        await server_group.wait_closed()


@pytest.mark.asyncio
async def test_ssh_wrong_password_is_rejected(tmp_path, log_records):
    runtime = make_ssh_runtime(tmp_path)
    server_group = await server.start_server(runtime)
    try:
        with pytest.raises(asyncssh.PermissionDenied):
            async with await asyncssh.connect(
                "127.0.0.1",
                port=server_group.get_port("ssh", "main"),
                username="user1",
                password="wrong",
                known_hosts=None,
            ):
                pass
    finally:
        server_group.close()
        await server_group.wait_closed()

    records = await wait_for_log_messages(
        runtime,
        log_records,
        {"SSH connection received", "User attempting to authenticate", "Authentication failed"},
    )
    auth_records = [
        record
        for record in records
        if record["message"]
        in {"SSH connection received", "User attempting to authenticate", "Authentication failed"}
    ]
    assert_single_session_id(auth_records)


@pytest.mark.asyncio
async def test_ssh_concurrent_connections_keep_log_source_ports_separate(
    tmp_path, log_records
):
    runtime = make_ssh_runtime(tmp_path)
    server_group = await server.start_server(runtime)
    port = server_group.get_port("ssh", "main")
    first = second = None
    try:
        first = await asyncssh.connect(
            "127.0.0.1", port=port, username="guest", known_hosts=None
        )
        second = await asyncssh.connect(
            "127.0.0.1", port=port, username="guest", known_hosts=None
        )
        first_port = first.get_extra_info("sockname")[1]
        second_port = second.get_extra_info("sockname")[1]
        await first.run("first", check=True)
    finally:
        for conn in (first, second):
            if conn is not None:
                conn.close()
                await conn.wait_closed()
        server_group.close()
        await server_group.wait_closed()

    records = await wait_for_log_messages(
        runtime, log_records, {"User input", "LLM response", "Session summary"}
    )
    first_input = next(
        record
        for record in records
        if record["message"] == "User input"
        and b64decode(record["details"]).decode("utf-8") == "first"
    )
    assert first_input["src_port"] == first_port

    first_port_records = [record for record in records if record["src_port"] == first_port]
    second_port_records = [record for record in records if record["src_port"] == second_port]
    assert_single_session_id(first_port_records)
    assert_single_session_id(second_port_records)


@pytest.mark.asyncio
async def test_legacy_ssh_config_still_starts_with_config_relative_host_key(tmp_path):
    host_key = tmp_path / "ssh_host_key"
    log_file = tmp_path / "legacy_ssh.log"
    key = asyncssh.generate_private_key("ssh-rsa")
    key.write_private_key(str(host_key))
    config_file = tmp_path / "config.ini"
    config_file.write_text(
        f"""
[honeypot]
log_file = {log_file}
sensor_name = legacy-test

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
    args = server.parse_args(["--config", str(config_file), "--prompt", "Simulate Linux."])
    runtime = server.configure_runtime(args, message_history=ScriptedMessageHistory())
    server_group = await server.start_server(runtime)
    try:
        assert server_group.get_port("ssh", "main") > 0
        assert runtime.protocol_instances[0].legacy is True
    finally:
        server_group.close()
        await server_group.wait_closed()


def make_http_runtime(tmp_path, protocol="http", *, two_instances=False):
    log_file = tmp_path / f"{protocol}_log.log"
    config = ConfigParser()
    config["honeypot"] = {"log_file": str(log_file), "sensor_name": "http-test"}
    config["llm"] = {
        "llm_provider": "fake",
        "model_name": "fake",
        "trimmer_max_tokens": "64000",
        "temperature": "0.0",
        "system_prompt": "",
    }
    config[f"protocol:{protocol}:marketing"] = {
        "enabled": "true",
        "listen_host": "127.0.0.1",
        "port": "0",
        "prompt": "Marketing website.",
    }
    if two_instances:
        config[f"protocol:{protocol}:api"] = {
            "enabled": "true",
            "listen_host": "127.0.0.1",
            "port": "0",
            "prompt": "Insecure public REST API.",
        }
    return server.DeceiveRuntime(
        config,
        str(tmp_path),
        server.discover_protocol_instances(config),
        script_dir=str(tmp_path),
        message_history=ScriptedMessageHistory(),
    )


@pytest.mark.asyncio
async def test_http_listener_responds_and_uses_cookie_session_memory(
    tmp_path, log_records
):
    runtime = make_http_runtime(tmp_path)
    server_group = await server.start_server(runtime)
    port = server_group.get_port("http", "marketing")
    try:
        async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True)) as session:
            first = await session.get(f"http://127.0.0.1:{port}/hello?x=1")
            first_text = await first.text()
            assert first.status == 200
            assert first_text == "http:marketing handled GET /hello"
            assert "deceive_session" in first.cookies

            second = await session.post(f"http://127.0.0.1:{port}/submit", data="name=a")
            second_text = await second.text()
            assert second_text == "http:marketing handled POST /submit"
    finally:
        server_group.close()
        await server_group.wait_closed()

    records = await wait_for_log_messages(
        runtime, log_records, {"User input", "LLM response", "Session summary"}
    )
    http_inputs = [record for record in records if record["message"] == "User input"]
    assert [record["http_path"] for record in http_inputs] == ["/hello", "/submit"]
    assert all(record["sensor_protocol"] == "http" for record in http_inputs)
    assert all(record["protocol_instance"] == "http:marketing" for record in http_inputs)
    assert_single_session_id(http_inputs)


@pytest.mark.asyncio
async def test_http_can_start_from_cli_only_args(tmp_path, monkeypatch, log_records):
    monkeypatch.setattr(server, "REPO_ROOT", str(tmp_path))
    args = server.parse_args(
        [
            "--protocol",
            "http",
            "--listen-host",
            "127.0.0.1",
            "--port",
            "0",
            "--prompt",
            "Simulate a browser-ready website.",
            "--log-file",
            str(tmp_path / "cli_http.log"),
        ]
    )
    runtime = server.configure_runtime(args, message_history=ScriptedMessageHistory())
    server_group = await server.start_server(runtime)
    port = server_group.get_port("http", "main")
    try:
        async with aiohttp.ClientSession() as session:
            response = await session.get(f"http://127.0.0.1:{port}/")
            assert response.status == 200
            assert await response.text() == "http:main handled GET /"
    finally:
        server_group.close()
        await server_group.wait_closed()

    records = await wait_for_log_messages(runtime, log_records, {"User input"})
    user_input = next(record for record in records if record["message"] == "User input")
    assert user_input["sensor_protocol"] == "http"
    assert user_input["protocol_instance"] == "http:main"


@pytest.mark.asyncio
async def test_multiple_http_instances_can_run_on_different_ports(tmp_path):
    runtime = make_http_runtime(tmp_path, two_instances=True)
    server_group = await server.start_server(runtime)
    try:
        marketing_port = server_group.get_port("http", "marketing")
        api_port = server_group.get_port("http", "api")
        assert marketing_port != api_port
        async with aiohttp.ClientSession() as session:
            marketing = await session.get(f"http://127.0.0.1:{marketing_port}/")
            api = await session.get(f"http://127.0.0.1:{api_port}/v1/users")
            assert await marketing.text() == "http:marketing handled GET /"
            assert await api.text() == "http:api handled GET /v1/users"
    finally:
        server_group.close()
        await server_group.wait_closed()


@pytest.mark.asyncio
async def test_disabled_protocol_instances_do_not_start(tmp_path):
    config = ConfigParser()
    config["honeypot"] = {
        "log_file": str(tmp_path / "disabled.log"),
        "sensor_name": "disabled-test",
    }
    config["llm"] = {"llm_provider": "fake", "model_name": "fake"}
    config["protocol:http:disabled"] = {"port": "0", "prompt": "Disabled."}
    runtime = server.DeceiveRuntime(
        config,
        str(tmp_path),
        server.discover_protocol_instances(config),
        script_dir=str(tmp_path),
        message_history=ScriptedMessageHistory(),
    )

    with pytest.raises(ValueError, match="No enabled protocol instances"):
        await server.start_server(runtime)


def write_self_signed_cert(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DECEIVE Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    key_file = tmp_path / "https.key"
    cert_file = tmp_path / "https.crt"
    key_file.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_file, key_file


@pytest.mark.asyncio
async def test_https_listener_uses_tls_and_logs_https_protocol(tmp_path, log_records):
    cert_file, key_file = write_self_signed_cert(tmp_path)
    runtime = make_http_runtime(tmp_path, protocol="https")
    instance = runtime.protocol_instances[0]
    instance.options["cert_file"] = str(cert_file)
    instance.options["key_file"] = str(key_file)

    server_group = await server.start_server(runtime)
    port = server_group.get_port("https", "marketing")
    try:
        client_ssl = ssl.create_default_context()
        client_ssl.check_hostname = False
        client_ssl.verify_mode = ssl.CERT_NONE
        async with aiohttp.ClientSession() as session:
            response = await session.get(
                f"https://127.0.0.1:{port}/secure", ssl=client_ssl
            )
            assert response.status == 200
            assert await response.text() == "https:marketing handled GET /secure"
    finally:
        server_group.close()
        await server_group.wait_closed()

    records = await wait_for_log_messages(runtime, log_records, {"User input"})
    user_input = next(record for record in records if record["message"] == "User input")
    assert user_input["sensor_protocol"] == "https"
    assert user_input["protocol_instance"] == "https:marketing"
    assert user_input["http_path"] == "/secure"


@pytest.mark.asyncio
async def test_https_can_start_from_cli_only_args(tmp_path, monkeypatch, log_records):
    cert_file, key_file = write_self_signed_cert(tmp_path)
    monkeypatch.setattr(server, "REPO_ROOT", str(tmp_path))
    args = server.parse_args(
        [
            "--protocol",
            "https",
            "--listen-host",
            "127.0.0.1",
            "--port",
            "0",
            "--prompt",
            "Simulate a secure browser-ready website.",
            "--cert-file",
            str(cert_file),
            "--key-file",
            str(key_file),
            "--log-file",
            str(tmp_path / "cli_https.log"),
        ]
    )
    runtime = server.configure_runtime(args, message_history=ScriptedMessageHistory())
    server_group = await server.start_server(runtime)
    port = server_group.get_port("https", "main")
    try:
        client_ssl = ssl.create_default_context()
        client_ssl.check_hostname = False
        client_ssl.verify_mode = ssl.CERT_NONE
        async with aiohttp.ClientSession() as session:
            response = await session.get(
                f"https://127.0.0.1:{port}/", ssl=client_ssl
            )
            assert response.status == 200
            assert await response.text() == "https:main handled GET /"
    finally:
        server_group.close()
        await server_group.wait_closed()

    records = await wait_for_log_messages(runtime, log_records, {"User input"})
    user_input = next(record for record in records if record["message"] == "User input")
    assert user_input["sensor_protocol"] == "https"
    assert user_input["protocol_instance"] == "https:main"
