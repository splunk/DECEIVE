from pathlib import Path
import sys

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SSH_DIR = REPO_ROOT / "SSH"
if str(SSH_DIR) not in sys.path:
    sys.path.insert(0, str(SSH_DIR))

import ssh_server  # noqa: E402


@pytest.fixture
def ssh_module():
    return ssh_server


@pytest.fixture(autouse=True)
def reset_ssh_server_state():
    original_config = ssh_server.config
    original_config_base_dir = ssh_server.config_base_dir
    original_accounts = ssh_server.accounts
    original_llm_sessions = ssh_server.llm_sessions
    original_thread_local = ssh_server.thread_local
    original_with_message_history = ssh_server.with_message_history
    original_logger_level = ssh_server.logger.level
    original_logger_propagate = ssh_server.logger.propagate

    yield

    for handler in list(ssh_server.logger.handlers):
        handler.flush()
        handler.close()
    ssh_server.logger.handlers.clear()
    ssh_server.logger.filters.clear()
    ssh_server.logger.setLevel(original_logger_level)
    ssh_server.logger.propagate = original_logger_propagate

    ssh_server.config = original_config
    ssh_server.config_base_dir = original_config_base_dir
    ssh_server.accounts = original_accounts
    ssh_server.llm_sessions = original_llm_sessions
    ssh_server.thread_local = original_thread_local
    ssh_server.with_message_history = original_with_message_history
