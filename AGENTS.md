# AGENTS.md - DECEIVE

This document gives AI coding agents the project-specific context needed to make
consistent, idiomatic changes to DECEIVE.

## Project Overview

DECEIVE, the DECeption with Evaluative Integrated Validation Engine, is a
proof-of-concept high-interaction SSH honeypot. It accepts SSH connections,
authenticates according to configurable honeypot account rules, sends attacker
input to a configured LLM backend, returns realistic Linux-like command output,
and writes JSON Lines telemetry for the full session.

The LLM-backed SSH interaction is DECEIVE's core simulation surface. The core
engineering goal is to make that live interaction observable, bounded, testable,
and believable without exposing a real shell or real filesystem.

Primary implementation files:

- `SSH/ssh_server.py` - AsyncSSH server, authentication, prompt assembly,
  LangChain message history, JSON logging, and runtime configuration.
- `SSH/config.ini.TEMPLATE` - tracked operator configuration template.
- `SSH/prompt.txt` - default user prompt describing the host being emulated.
- `tests/` - unit and integration coverage for configuration, authentication,
  logging, session behavior, and real AsyncSSH connectivity with a fake LLM.
- `README.md` - user-facing setup, runtime, testing, and log format reference.
- `TODO.txt` - lightweight backlog and known priorities.

## Start-Of-Work Checklist

For any non-trivial change:

1. Read `README.md`, `pyproject.toml`, and `TODO.txt` before editing.
2. Check `git status --short`; preserve user changes already in the tree.
3. Inspect the relevant tests before changing behavior.
4. Update `TODO.txt` only when the change completes, changes, or adds a tracked
   backlog item.
5. Update `README.md` and `SSH/config.ini.TEMPLATE` when setup, config keys,
   runtime behavior, or log fields change.

## Tech Stack

- Python 3.11, pinned by `.python-version` and `requires-python` in
  `pyproject.toml`.
- `uv` for dependency management and command execution.
- `asyncssh` for the SSH server and integration test clients.
- LangChain provider integrations for OpenAI, Azure OpenAI, Ollama, AWS Bedrock,
  and Google Gemini.
- `pytest` and `pytest-asyncio` for automated tests.
- Standard library `argparse`, `configparser`, `logging`, `json`, `asyncio`, and
  path utilities. The current CLI is argparse-based; do not switch frameworks
  unless explicitly requested.

## Dependency Management

Use `uv`; do not add `requirements.txt` or install dependencies with bare `pip`.

Common commands:

```bash
uv sync
uv run pytest
uv run pytest tests/test_ssh_server_unit.py
uv run pytest tests/test_ssh_integration.py
uv run python SSH/ssh_server.py
```

When adding or removing dependencies, update `pyproject.toml` and `uv.lock`
together. This project currently has `package = false`, so treat it as a script
repository rather than an installed Python package.

## Code Style

- Prefer clear, direct Python over clever abstractions.
- Add type hints for new or significantly changed functions. Existing code is
  still being modernized, so avoid broad type-only churn.
- Use specific exceptions and actionable error messages at runtime boundaries.
- Avoid bare `except Exception` in new code unless it is at `main()` or another
  intentional process boundary.
- Prefer `pathlib.Path` for new path-heavy code, but match nearby code when a
  small change in `SSH/ssh_server.py` would otherwise create needless churn.
- Keep lines readable, around 100 characters where practical.
- Use comments sparingly for non-obvious async, logging, or security behavior.
- Do not add linting or formatting tool mandates unless the project config is
  updated to support them.

## Runtime Architecture

### SSH Server

`start_server()` creates an AsyncSSH listener from the active config. Preserve
these behavior contracts:

- `listen_host` may constrain binding; tests use `127.0.0.1`.
- `port = 0` must work in tests to request a random local port.
- Host private keys are resolved relative to the loaded config file first, then
  relative to `SSH/`.
- The server version string intentionally imitates OpenSSH.
- The process handler must never grant access to a real local shell.

`MySSHServer` owns SSH connection/auth callbacks. `handle_client()` owns
interactive and non-interactive command handling. There is known cleanup work in
`TODO.txt` around lifecycle ownership; avoid deepening the split between server
instances and process handling.

### Authentication Semantics

The honeypot intentionally supports deceptive login modes:

- `username =` accepts login without a password.
- `username = secret` requires the exact password.
- `username = *` accepts any password, including empty passwords.
- Unknown usernames currently authenticate like wildcard accounts.

Do not "fix" the unknown-user behavior unless implementing an explicit auth
policy option. Tests should cover all four modes.

### LLM Simulation

`build_message_history()` composes:

1. The configured system prompt from `[llm].system_prompt`.
2. The user prompt from `--prompt`, `--prompt-file`, or `SSH/prompt.txt`.
3. Per-session message history trimmed to `trimmer_max_tokens`.

Preserve per-session isolation through `llm_sessions` and the session id passed
in LangChain config. Runtime supports provider selection through `choose_llm()`;
new providers should be small, testable branches with provider-specific config
kept in `SSH/config.ini.TEMPLATE`.

Interactive and non-interactive behavior differs:

- Interactive sessions receive an initial banner/MOTD and shell prompt.
- Interactive responses should end with a realistic shell prompt.
- Non-interactive command output must not include a prompt or MOTD.
- If an input would close the login shell, the model should return exactly
  `YYY-END-OF-SESSION-YYY`.

The LLM may hallucinate future user input. When changing prompts or response
handling, preserve the rule that DECEIVE answers only the current input and does
not invent the attacker's next command.

## Logging Contracts

DECEIVE logs JSON Lines to the configured `honeypot.log_file`. Relative log paths
are resolved from the directory containing the loaded config file.

Preserve these fields for session telemetry:

- `timestamp` - UTC ISO 8601 with millisecond precision.
- `level`
- `task_name` - the stable `session-...` id for the SSH session.
- `src_ip`, `src_port`, `dst_ip`, `dst_port`
- `message`
- `sensor_name`
- `sensor_protocol` - currently `ssh`

Important message types:

- `SSH connection received`
- `User attempting to authenticate`
- `Authentication success`
- `Authentication failed`
- `User input`
- `LLM response`
- `Session summary`
- `SSH connection closed`

`User input` and `LLM response` records store full content in `details` as
base64-encoded UTF-8. Keep that encoding contract stable so arbitrary terminal
bytes do not break JSON logs. Include the `interactive` boolean for command and
response records where it applies.

`Session summary` records include `details` with the LLM summary and `judgement`
as one of `BENIGN`, `SUSPICIOUS`, `MALICIOUS`, or `UNKNOWN`. Generate at most one
summary per session.

This is a honeypot: authentication logs intentionally include attempted
usernames and passwords. Do not remove that behavior casually, but also do not
log provider API keys, environment variables, local config contents, or stack
traces containing secrets.

## Configuration And Local Artifacts

Tracked:

- `SSH/config.ini.TEMPLATE`
- `SSH/prompt.txt`

Ignored/local:

- `SSH/config.ini`
- SSH host keys such as `SSH/ssh_host_key`, `SSH/deceive_host_key`, and `*.pub`
- `*.log` files including honeypot logs
- `.venv/`, `.pytest_cache/`, and other generated Python artifacts

Do not commit local credentials, provider API keys, host private keys, generated
logs, or deployment artifacts under `SSH/DEPLOY/`.

When adding config settings:

1. Add the setting to `SSH/config.ini.TEMPLATE` with a clear comment.
2. Provide a sane default in `load_config()` if the server can run without an
   explicit config file.
3. Add CLI overrides only when operators need them.
4. Cover config-file-relative behavior in tests when paths are involved.
5. Update `README.md`.

## Testing Requirements

All tests must be deterministic and must not call a live LLM provider. Use fake
message history objects, monkeypatched provider classes, or injected
`message_history` objects.

Testing conventions:

- Use `tmp_path` for config files, host keys, logs, and any file I/O.
- Bind integration servers to `127.0.0.1` and `port = 0`.
- Use `known_hosts=None` for ephemeral local AsyncSSH clients in tests.
- Flush and close log handlers in fixtures to avoid leaking global state.
- Reset module globals such as `config`, `accounts`, `llm_sessions`, and
  `with_message_history` after tests that mutate runtime state.
- Assert log shape, base64 encoding, session id consistency, and one summary per
  session when touching session flow.

Run at least the focused test file for the code you changed. Run the full suite
before commits or behavior-heavy changes:

```bash
uv run pytest
```

## Security And Safety

DECEIVE is a proof of concept, not production-ready infrastructure. Keep that
warning intact in user-facing docs unless the security posture materially
changes.

Prioritize bounded resource controls for public-facing behavior:

- Maximum input line length.
- Session idle and total timeouts.
- Connection and request limits.
- LLM call throttling.
- Cleanup for per-session message history.

Never route attacker input to a real shell or filesystem. The LLM should simulate
output only. If adding tools, retrieval, file access, or command execution, gate
them behind explicit design review and tests that prove attacker input cannot
escape the simulation boundary.

## Documentation Checklist

Update docs when behavior changes:

- `README.md` for setup, running, operator behavior, log schema, or warnings.
- `SSH/config.ini.TEMPLATE` for config changes.
- `SSH/prompt.txt` only for default emulation behavior.
- `TODO.txt` for backlog changes or completed tracked priorities.
- Tests for every observable auth, session, config, prompt, or logging contract.

## Versioning And Commits

The project version currently lives in `pyproject.toml` only. If asked to bump
the version, update `pyproject.toml`, run `uv sync` so `uv.lock` stays
consistent, and document the reason in the commit.

Prefer Conventional Commit prefixes such as `feat:`, `fix:`, `docs:`, `test:`,
`refactor:`, and `chore:` when committing.

## Known Design Decisions

- DECEIVE intentionally logs usernames and passwords supplied to the honeypot.
- Unknown usernames currently authenticate successfully to maximize deception.
- LLM calls are part of runtime behavior; only tests should replace them with
  deterministic fakes.
- Relative `log_file` paths resolve next to the loaded config file, not
  necessarily the current working directory.
- The default implementation currently lives mostly in one script. Refactor
  incrementally and keep compatibility with documented commands.
