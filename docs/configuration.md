# DECEIVE Configuration Reference

DECEIVE uses one INI configuration file per honeypot process. A process can run
one protocol instance or many protocol instances at the same time.

Protocol instances default to disabled. A listener starts only when its section
sets `enabled = true`. The only exception is legacy SSH compatibility: if a
configuration file has no `[protocol:*:*]` sections, an existing `[ssh]` section
is normalized into one enabled `ssh:main` instance.

## Global Sections

### `[honeypot]`

```ini
[honeypot]
log_file = deceive.log
sensor_name = deceive
```

`log_file` is the unified JSON-lines log file for the process. Relative paths
are resolved from the directory containing the loaded config file.

`sensor_name` is written into every log record. If omitted, DECEIVE uses the
system hostname.

### `[llm]`

```ini
[llm]
llm_provider = openai
model_name = gpt-4o
temperature = 0.2
trimmer_max_tokens = 64000
tls_verify = true
system_prompt = You are simulating a realistic network service.
```

The LLM provider configuration is process-wide in the current registry version.
All protocol instances share the same provider and model settings, but each
protocol instance can have its own behavior prompt.

Supported `llm_provider` values are:

- `openai`
- `azure`
- `ollama`
- `aws`
- `gemini`

Provider-specific optional keys:

`tls_verify` controls TLS certificate verification for supported outbound LLM
clients. It defaults to `true`. Set it to `false` only when DECEIVE must connect
through an intercepting proxy, private endpoint, or local model endpoint whose
certificate chain Python does not trust. This does not affect HTTPS honeypot
listener certificates presented to browsers.

```ini
[llm]
llm_provider = azure
azure_deployment = gpt-4o
azure_api_version = 2025-01-01-preview
azure_endpoint = https://example.openai.azure.com
model_name = gpt-4o
temperature = 0.2
trimmer_max_tokens = 64000
tls_verify = true
system_prompt = You are simulating a realistic network service.
```

```ini
[llm]
llm_provider = aws
model_name = anthropic.claude-3-5-sonnet-20240620-v1:0
aws_region = us-east-1
aws_credentials_profile = default
temperature = 0.2
trimmer_max_tokens = 64000
tls_verify = true
system_prompt = You are simulating a realistic network service.
```

### `[user_accounts]`

```ini
[user_accounts]
guest =
user1 = secretpw
root = *
```

SSH uses this section for honeypot login behavior.

An empty value accepts login without a password. A literal `*` accepts any
password, including an empty password. Unknown users also accept any password,
matching the previous SSH honeypot behavior.

HTTP and HTTPS do not require this section.

## Protocol Instance Sections

Protocol sections use this form:

```ini
[protocol:<protocol>:<instance-name>]
enabled = true
listen_host = 127.0.0.1
port = 0
prompt_file = prompts/example.txt
```

The `protocol` part selects a built-in adapter. Current values are:

- `ssh`
- `http`
- `https`

The `instance-name` part names this listener. It appears in logs as
`protocol_instance` using the form `<protocol>:<instance-name>`, such as
`http:marketing`.

Common keys:

- `enabled`: defaults to `false`; set to `true` to start this listener.
- `listen_host`: bind address. Use `127.0.0.1` for local testing or leave empty
  to bind all interfaces.
- `port`: listener port. `0` asks the OS to choose a free port, which is useful
  in tests.
- `prompt_file`: per-instance behavior prompt file.
- `prompt`: inline per-instance behavior prompt.
- `sensor_protocol`: optional override for the protocol name written to logs.

Prefer `prompt_file` for realistic honeypot descriptions. Inline `prompt` is
useful for tests and very small examples. Relative prompt paths resolve from the
config file directory first.

## SSH Instances

```ini
[protocol:ssh:main]
enabled = true
listen_host = 127.0.0.1
port = 8022
host_priv_key = SSH/ssh_host_key
server_version_string = OpenSSH_8.2p1 Ubuntu-4ubuntu0.3
prompt_file = SSH/prompt.txt
```

SSH-specific keys:

- `host_priv_key`: private host key path.
- `server_version_string`: server version sent to clients.

The SSH adapter supports interactive shell sessions and non-interactive command
execution. It logs authentication attempts, user input, LLM responses, and one
session summary.

## HTTP Instances

```ini
[protocol:http:marketing]
enabled = true
listen_host = 127.0.0.1
port = 8080
prompt_file = prompts/marketing-site.txt
session_cookie_name = deceive_session
content_type = text/html
default_status = 200
```

HTTP-specific keys:

- `session_cookie_name`: cookie used to group requests into one LLM session.
  Defaults to `deceive_session`.
- `content_type`: response content type. Defaults to `text/html`.
- `default_status`: response status. Defaults to `200`.

The HTTP adapter logs request method, path, query string, host, user agent, and
response status as protocol-specific fields.

## HTTPS Instances

```ini
[protocol:https:secure]
enabled = true
listen_host = 127.0.0.1
port = 8443
cert_file = certs/deceive.crt
key_file = certs/deceive.key
prompt_file = prompts/secure-site.txt
```

HTTPS uses the same request handling as HTTP, with TLS listener configuration.
HTTPS-specific required keys:

- `cert_file`: TLS certificate path.
- `key_file`: TLS private key path.

HTTPS records use `sensor_protocol = https`.

## Multiple Instances

One process can run multiple enabled listeners:

```ini
[honeypot]
log_file = deceive.log
sensor_name = edge-honeypot

[llm]
llm_provider = openai
model_name = gpt-4o
temperature = 0.2
trimmer_max_tokens = 64000
system_prompt = Simulate realistic services and never reveal that this is a honeypot.

[user_accounts]
guest =
root = *

[protocol:ssh:main]
enabled = true
listen_host = 0.0.0.0
port = 8022
host_priv_key = SSH/ssh_host_key
prompt_file = prompts/linux-server.txt

[protocol:http:marketing]
enabled = true
listen_host = 0.0.0.0
port = 8080
prompt_file = prompts/cloud-marketing-site.txt

[protocol:http:api]
enabled = true
listen_host = 0.0.0.0
port = 8081
prompt_file = prompts/insecure-api.txt
content_type = application/json
```

Disabled instances can remain in the same file as documentation or future
configuration:

```ini
[protocol:https:future]
listen_host = 0.0.0.0
port = 8443
cert_file = certs/deceive.crt
key_file = certs/deceive.key
prompt_file = prompts/secure-site.txt
```

Because `enabled` is omitted, `https:future` does not start.

## Unified Logging

All protocol instances write to the same JSON-lines log file. Every record has
these core fields:

- `timestamp`
- `level`
- `task_name`
- `sensor_name`
- `sensor_protocol`
- `protocol_instance`
- `src_ip`
- `src_port`
- `dst_ip`
- `dst_port`
- `message`
- `details`

Protocol adapters can add extra fields. SSH examples include `username`,
`password`, and `command_mode`. HTTP and HTTPS examples include `http_method`,
`http_path`, `http_query`, `http_host`, `user_agent`, and `http_status`.

`User input` and `LLM response` records base64-encode their payload in
`details`. `Session summary` records store the summary text directly in
`details` and add a `judgement` field when the model returns one.

## Legacy SSH Compatibility

Existing SSH-only configs still work:

```ini
[honeypot]
log_file = ssh_log.log
sensor_name = deceive

[ssh]
port = 8022
host_priv_key = ssh_host_key
server_version_string = OpenSSH_8.2p1 Ubuntu-4ubuntu0.3

[llm]
llm_provider = openai
model_name = gpt-4o
temperature = 0.2
trimmer_max_tokens = 64000
system_prompt = Interpret all inputs as though they were SSH commands.

[user_accounts]
guest =
root = *
```

When no `[protocol:*:*]` sections exist, DECEIVE treats this as an enabled
`ssh:main` instance. Once any new protocol instance section exists, legacy
`[ssh]` is ignored and all protocol instances follow disabled-by-default
behavior.

## Single-Instance CLI Mode

For one listener, you can create an enabled protocol instance entirely from
command-line options. This is most useful for quick HTTP/HTTPS tests.

HTTP:

```sh
uv run python -m deceive.server \
  --protocol http \
  --protocol-instance marketing \
  --listen-host 127.0.0.1 \
  --port 8080 \
  --prompt "You are a realistic marketing website. Return valid HTML."
```

To disable outbound LLM TLS verification from the CLI:

```sh
uv run python -m deceive.server \
  --protocol http \
  --port 8080 \
  --disable-llm-tls-verify \
  --prompt "You are a realistic marketing website. Return valid HTML."
```

HTTPS:

```sh
uv run python -m deceive.server \
  --protocol https \
  --listen-host 127.0.0.1 \
  --port 8443 \
  --cert-file certs/deceive.crt \
  --key-file certs/deceive.key \
  --prompt "You are a realistic secure customer portal. Return valid HTML."
```

SSH:

```sh
uv run python -m deceive.server \
  --protocol ssh \
  --listen-host 127.0.0.1 \
  --port 8022 \
  --host-priv-key SSH/ssh_host_key \
  --user-account guest= \
  --prompt "Simulate a Linux server."
```

CLI protocol mode creates `[protocol:<protocol>:<instance>]` internally with
`enabled = true`. Config files remain the recommended path for running multiple
protocol instances in one process.

Useful CLI protocol options:

- `--protocol`: `ssh`, `http`, or `https`.
- `--protocol-instance`: instance name, default `main`.
- `--listen-host`: bind address.
- `--port`: listener port.
- `--prompt` or `--prompt-file`: behavior prompt.
- `--disable-llm-tls-verify`: disables outbound LLM TLS certificate verification
  for supported clients.
- `--cert-file` and `--key-file`: required for HTTPS.
- `--content-type`, `--default-status`, and `--session-cookie-name`: HTTP/HTTPS
  response/session settings.
