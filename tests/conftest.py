from configparser import ConfigParser
from pathlib import Path
import sys

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from deceive.runtime import DeceiveRuntime


class FakeLLMResponse:
    def __init__(self, content: str):
        self.content = content


class ScriptedMessageHistory:
    def __init__(self):
        self.calls = []

    async def ainvoke(self, payload, config=None):
        self.calls.append((payload, config))
        message = payload["messages"][-1].content
        username = payload.get("username", "guest")
        interactive = payload.get("interactive", False)
        instance = payload.get("protocol_instance", "unknown:main")

        if "Examine the list of all the SSH commands" in message:
            return FakeLLMResponse("The user ran a simple test command.\n\nJudgement: BENIGN")
        if "Examine the list of all the HTTP requests" in message:
            return FakeLLMResponse("The user browsed the web app.\n\nJudgement: BENIGN")
        if message == "":
            return FakeLLMResponse("Welcome to deceive-test\nguest@deceive-test:~$ ")
        if message == "exit":
            return FakeLLMResponse("YYY-END-OF-SESSION-YYY")
        if message == "pwd":
            suffix = "guest@deceive-test:~$ " if interactive else ""
            return FakeLLMResponse(f"/home/{username}\n{suffix}")
        if payload.get("protocol") in {"http", "https"}:
            return FakeLLMResponse(
                f"{instance} handled {payload['http_method']} {payload['http_path']}"
            )

        suffix = "guest@deceive-test:~$ " if interactive else ""
        return FakeLLMResponse(f"ran {message}\n{suffix}")


@pytest.fixture
def minimal_config(tmp_path):
    config = ConfigParser()
    config["honeypot"] = {
        "log_file": str(tmp_path / "deceive.log"),
        "sensor_name": "test-sensor",
    }
    config["llm"] = {
        "llm_provider": "fake",
        "model_name": "fake",
        "trimmer_max_tokens": "64000",
        "temperature": "0.0",
        "system_prompt": "",
    }
    return config


@pytest.fixture
def make_runtime(tmp_path, minimal_config):
    runtimes = []

    def _make_runtime(config, instances, message_history=None):
        runtime = DeceiveRuntime(
            config,
            str(tmp_path),
            instances,
            script_dir=str(tmp_path),
            prompt="Simulate the requested service.",
            message_history=message_history or ScriptedMessageHistory(),
        )
        runtimes.append(runtime)
        return runtime

    yield _make_runtime

    for runtime in runtimes:
        for handler in list(runtime.logger.handlers):
            handler.flush()
            handler.close()
        runtime.logger.handlers.clear()
        runtime.logger.filters.clear()
