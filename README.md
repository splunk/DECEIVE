# DECEIVE

<img align="right" src="DECEIVE.png" alt="A cybercriminal interacts with a ghostly, AI-driven honeypot system">

DECEIVE, the **DECeption with Evaluative Integrated Validation Engine**, is a
high-interaction, low-effort honeypot system. It uses an LLM backend to simulate
realistic network services without granting attackers access to a real system.

DECEIVE now runs protocol instances through a lightweight built-in registry. One
process can listen on SSH, HTTP, HTTPS, or multiple instances of the same
protocol, with one unified JSON log.

DECEIVE is a proof-of-concept project. It is not production quality. Try it,
learn from it, and be cautious about deploying it in a production environment.

## Supported Protocols

- SSH
- HTTP
- HTTPS

Future protocols are intended to be added as small built-in adapters behind the
same registry.

## Setup

DECEIVE is primarily developed on macOS, but should work on UNIX-like systems
that can run Python 3.11 or newer.

Clone the repository:

```sh
git clone https://github.com/splunk/DECEIVE
cd DECEIVE
```

Install dependencies with `uv`:

```sh
uv sync
```

Generate an SSH host key if you plan to enable SSH:

```sh
ssh-keygen -t rsa -b 4096 -f SSH/ssh_host_key
```

Copy the example config:

```sh
cp config.ini.TEMPLATE config.ini
```

Edit `config.ini` for your LLM provider, enabled protocol instances, ports, and
prompts. Full configuration details are in
[docs/configuration.md](docs/configuration.md).

## Quick Config Examples

SSH only:

```ini
[protocol:ssh:main]
enabled = true
listen_host = 127.0.0.1
port = 8022
host_priv_key = SSH/ssh_host_key
prompt_file = SSH/prompt.txt
```

Two HTTP instances in one process:

```ini
[protocol:http:marketing]
enabled = true
listen_host = 127.0.0.1
port = 8080
prompt_file = prompts/cloud-marketing-site.txt

[protocol:http:api]
enabled = true
listen_host = 127.0.0.1
port = 8081
prompt_file = prompts/insecure-api.txt
content_type = application/json
```

Protocol instances default to disabled, so omitted `enabled` means that listener
will not start.

## Running

Set any environment variables needed by your LLM backend, such as:

```sh
export OPENAI_API_KEY="<your secret API key>"
```

Start DECEIVE from the repository root:

```sh
uv run python -m deceive.server -c config.ini
```

For a single HTTP listener, you can skip the config file:

```sh
uv run python -m deceive.server \
  --protocol http \
  --listen-host 127.0.0.1 \
  --port 8080 \
  --prompt "You are the public website for a cloud services company. Return valid HTML."
```

If your outbound LLM client is behind an intercepting proxy or private endpoint
with an untrusted certificate chain, add `--disable-llm-tls-verify`.

For a single HTTPS listener:

```sh
uv run python -m deceive.server \
  --protocol https \
  --listen-host 127.0.0.1 \
  --port 8443 \
  --cert-file certs/deceive.crt \
  --key-file certs/deceive.key \
  --prompt "You are a secure customer portal. Return valid HTML."
```

The legacy SSH entrypoint still works:

```sh
uv run python SSH/ssh_server.py -c config.ini
```

Test SSH:

```sh
ssh guest@localhost -p 8022
```

Test HTTP:

```sh
curl -i http://localhost:8080/
```

## Logging

All enabled protocol instances write to one JSON-lines log file configured by
`[honeypot].log_file`. Each record includes core fields such as
`sensor_protocol`, `protocol_instance`, source/destination addresses, message,
and details. Protocol adapters add fields such as SSH usernames or HTTP paths.

See [docs/configuration.md](docs/configuration.md#unified-logging) for the full
logging schema.

## Running Tests

After `uv sync`, run:

```sh
uv run pytest
```

The test suite covers legacy SSH compatibility, the protocol registry, SSH
behavior, HTTP/HTTPS listeners, multi-instance HTTP, disabled-by-default
protocol instances, unified logging, and documentation config snippets.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for
details.
