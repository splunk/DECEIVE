import asyncio
from base64 import b64decode
from configparser import ConfigParser
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest

import asyncssh


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


class SSHIntegrationTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        loop = asyncio.get_running_loop()
        loop.set_debug(False)
        loop.slow_callback_duration = 10

        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.work_dir = Path(self.temp_dir.name)
        self.host_key = self.work_dir / "ssh_host_key"
        self.log_file = self.work_dir / "ssh_log.log"

        key = asyncssh.generate_private_key("ssh-rsa")
        key.write_private_key(str(self.host_key))

        ssh_server.config = ConfigParser()
        ssh_server.config["honeypot"] = {
            "log_file": str(self.log_file),
            "sensor_name": "integration-test",
        }
        ssh_server.config["ssh"] = {
            "listen_host": "127.0.0.1",
            "port": "0",
            "host_priv_key": str(self.host_key),
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

        self.server = await ssh_server.start_server()
        self.port = self.server.get_port()

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()
        for handler in ssh_server.logger.handlers:
            handler.flush()
            handler.close()
        ssh_server.logger.handlers.clear()
        ssh_server.logger.filters.clear()

    async def connect(self, username="guest", password=None):
        return await asyncssh.connect(
            "127.0.0.1",
            port=self.port,
            username=username,
            password=password,
            known_hosts=None,
        )

    def read_log_records(self):
        for handler in ssh_server.logger.handlers:
            handler.flush()
        return [
            json.loads(line)
            for line in self.log_file.read_text().splitlines()
            if line.strip()
        ]

    async def test_non_interactive_command_runs_through_real_ssh_server(self):
        async with await self.connect() as conn:
            result = await conn.run("pwd", check=True)

        self.assertEqual(result.stdout, "/home/guest\n")
        records = self.read_log_records()
        messages = [record["message"] for record in records]
        self.assertIn("SSH connection received", messages)
        self.assertIn("User input", messages)
        self.assertIn("LLM response", messages)
        self.assertIn("Session summary", messages)

        user_input = next(record for record in records if record["message"] == "User input")
        self.assertFalse(user_input["interactive"])
        self.assertEqual(b64decode(user_input["details"]).decode("utf-8"), "pwd")

        summary = next(record for record in records if record["message"] == "Session summary")
        self.assertEqual(summary["judgement"], "BENIGN")

    async def test_interactive_session_runs_commands_and_exits(self):
        async with await self.connect() as conn:
            process = await conn.create_process(term_type="xterm")
            banner = await asyncio.wait_for(process.stdout.readuntil(PROMPT), timeout=2)
            self.assertIn("Welcome to deceive-test", banner)

            process.stdin.write("pwd\n")
            output = await asyncio.wait_for(process.stdout.readuntil(PROMPT), timeout=2)
            self.assertIn("/home/guest", output)

            process.stdin.write("exit\n")
            await asyncio.wait_for(process.wait(), timeout=2)

        records = self.read_log_records()
        interactive_inputs = [
            record for record in records
            if record["message"] == "User input" and record["interactive"]
        ]
        self.assertEqual(
            [b64decode(record["details"]).decode("utf-8") for record in interactive_inputs],
            ["pwd", "exit"],
        )

    async def test_password_and_wildcard_accounts_can_authenticate(self):
        async with await self.connect(username="user1", password="secretpw") as conn:
            result = await conn.run("pwd", check=True)
        self.assertEqual(result.stdout, "/home/user1\n")

        async with await self.connect(username="root", password="anything") as conn:
            result = await conn.run("pwd", check=True)
        self.assertEqual(result.stdout, "/home/root\n")

    async def test_wrong_password_is_rejected(self):
        with self.assertRaises(asyncssh.PermissionDenied):
            async with await self.connect(username="user1", password="wrong"):
                pass

    @unittest.expectedFailure
    async def test_concurrent_connections_keep_log_source_ports_separate(self):
        # Known P0 bug: connection metadata is thread-local even though sessions
        # share one asyncio thread, so overlapping sessions can inherit each
        # other's source port in later log records.
        first = await self.connect()
        second = await self.connect()
        try:
            first_port = first.get_extra_info("sockname")[1]
            await first.run("first", check=True)
        finally:
            first.close()
            second.close()
            await first.wait_closed()
            await second.wait_closed()

        records = self.read_log_records()
        first_input = next(
            record for record in records
            if record["message"] == "User input"
            and b64decode(record["details"]).decode("utf-8") == "first"
        )
        self.assertEqual(first_input["src_port"], first_port)


if __name__ == "__main__":
    unittest.main()
