from __future__ import annotations

from base64 import b64encode
from configparser import ConfigParser
import asyncio
import datetime
import json
import logging
import os
import socket
import sys
from dataclasses import dataclass
from operator import itemgetter
from typing import Optional
import uuid

import httpx
from langchain_aws import ChatBedrockConverse
from langchain_core.chat_history import BaseChatMessageHistory, InMemoryChatMessageHistory
from langchain_core.messages import HumanMessage, trim_messages
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.runnables import RunnablePassthrough
from langchain_core.runnables.history import RunnableWithMessageHistory
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_ollama import ChatOllama
from langchain_openai import AzureChatOpenAI, ChatOpenAI


LOGGER_NAME = "deceive"


_LOG_RECORD_ATTRS = set(
    logging.LogRecord(
        name="",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="",
        args=(),
        exc_info=None,
    ).__dict__
)
_LOG_RECORD_ATTRS.update({"message", "asctime"})


def _endpoint_parts(endpoint):
    if endpoint is not None:
        return endpoint[:2]
    return "-", "-"


def get_connection_log_extra(source) -> dict:
    if source is None:
        peername = None
        sockname = None
    else:
        peername = source.get_extra_info("peername")
        sockname = source.get_extra_info("sockname")

    src_ip, src_port = _endpoint_parts(peername)
    dst_ip, dst_port = _endpoint_parts(sockname)
    return {
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
    }


def new_session_id() -> str:
    return f"session-{uuid.uuid4()}"


def get_session_id(source, fallback=None):
    if source is None:
        return fallback
    return source.get_extra_info("deceive_session_id", fallback)


def merge_log_extra(log_extra: dict, **extra) -> dict:
    merged = dict(log_extra)
    merged.update(extra)
    return merged


def encode_details(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return b64encode(value).decode("utf-8")


@dataclass(frozen=True)
class ProtocolInstanceConfig:
    protocol: str
    name: str
    section: str
    options: dict[str, str]
    legacy: bool = False

    @property
    def full_name(self) -> str:
        return f"{self.protocol}:{self.name}"

    @property
    def sensor_protocol(self) -> str:
        return self.options.get("sensor_protocol", self.protocol)

    @property
    def enabled(self) -> bool:
        return self.getboolean("enabled", fallback=False)

    def get(self, key: str, fallback=None):
        return self.options.get(key, fallback)

    def getint(self, key: str, fallback: Optional[int] = None) -> int:
        value = self.get(key)
        if value is None:
            if fallback is None:
                raise KeyError(key)
            return fallback
        return int(value)

    def getfloat(self, key: str, fallback: Optional[float] = None) -> float:
        value = self.get(key)
        if value is None:
            if fallback is None:
                raise KeyError(key)
            return fallback
        return float(value)

    def getboolean(self, key: str, fallback: Optional[bool] = None) -> bool:
        value = self.get(key)
        if value is None:
            if fallback is None:
                raise KeyError(key)
            return fallback
        normalized = str(value).strip().lower()
        if normalized in ConfigParser.BOOLEAN_STATES:
            return ConfigParser.BOOLEAN_STATES[normalized]
        raise ValueError(f"Invalid boolean value for {self.section}.{key}: {value}")


class SessionSummaryState:
    def __init__(self):
        self.summary_generated = False


class JSONFormatter(logging.Formatter):
    def __init__(self, sensor_name, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sensor_name = sensor_name

    def format(self, record):
        log_record = {
            "timestamp": datetime.datetime.fromtimestamp(
                record.created, datetime.timezone.utc
            ).isoformat(sep="T", timespec="milliseconds"),
            "level": record.levelname,
            "task_name": getattr(record, "task_name", "-"),
            "sensor_name": self.sensor_name,
            "sensor_protocol": getattr(record, "sensor_protocol", "-"),
            "protocol_instance": getattr(record, "protocol_instance", "-"),
            "src_ip": getattr(record, "src_ip", "-"),
            "src_port": getattr(record, "src_port", "-"),
            "dst_ip": getattr(record, "dst_ip", "-"),
            "dst_port": getattr(record, "dst_port", "-"),
            "message": record.getMessage(),
            "details": getattr(record, "details", "-"),
        }
        if hasattr(record, "interactive"):
            log_record["interactive"] = record.interactive

        for key, value in record.__dict__.items():
            if key in log_record or key in _LOG_RECORD_ATTRS:
                continue
            log_record[key] = value
        return json.dumps(log_record)


class ContextFilter(logging.Filter):
    def filter(self, record):
        try:
            task = asyncio.current_task()
        except RuntimeError:
            task = None

        if not hasattr(record, "task_name"):
            record.task_name = task.get_name() if task else "-"
        if not hasattr(record, "sensor_protocol"):
            record.sensor_protocol = "-"
        if not hasattr(record, "protocol_instance"):
            record.protocol_instance = "-"
        return True


class DeceiveRuntime:
    def __init__(
        self,
        config: ConfigParser,
        config_base_dir: str,
        protocol_instances: list[ProtocolInstanceConfig],
        *,
        script_dir: str,
        prompt: Optional[str] = None,
        prompt_file: Optional[str] = None,
        message_history=None,
    ):
        self.config = config
        self.config_base_dir = config_base_dir
        self.script_dir = script_dir
        self.protocol_instances = protocol_instances
        self.prompt_override = prompt
        self.prompt_file_override = prompt_file
        self.message_history_override = message_history
        self.message_histories = {}
        self.llm_sessions: dict[str, BaseChatMessageHistory] = {}
        self.accounts = self.get_user_accounts(required=False)
        self.logger = logging.getLogger(LOGGER_NAME)
        self.configure_logging()

    def enabled_instances(self) -> list[ProtocolInstanceConfig]:
        return [instance for instance in self.protocol_instances if instance.enabled]

    def resolve_runtime_path(self, path: str) -> str:
        if os.path.isabs(path) or os.path.exists(path):
            return path

        for base_dir in (self.config_base_dir, self.script_dir):
            candidate = os.path.join(base_dir, path)
            if os.path.exists(candidate):
                return candidate

        return path

    def resolve_config_output_path(self, path: str) -> str:
        if os.path.isabs(path):
            return path
        return os.path.join(self.config_base_dir, path)

    def get_user_accounts(self, *, required: bool) -> dict:
        if "user_accounts" not in self.config or len(self.config.items("user_accounts")) == 0:
            if required:
                raise ValueError("No user accounts found in configuration file.")
            return {}
        return dict(self.config.items("user_accounts"))

    def configure_logging(self) -> None:
        logging.Formatter.formatTime = (
            lambda self, record, datefmt=None: datetime.datetime.fromtimestamp(
                record.created, datetime.timezone.utc
            ).isoformat(sep="T", timespec="milliseconds")
        )

        sensor_name = self.config["honeypot"].get("sensor_name", socket.gethostname())
        self.logger.setLevel(logging.INFO)
        self.logger.handlers.clear()
        self.logger.filters.clear()
        self.logger.propagate = False

        log_file = self.resolve_config_output_path(
            self.config["honeypot"].get("log_file", "deceive.log")
        )
        log_file_handler = logging.FileHandler(log_file)
        log_file_handler.setFormatter(JSONFormatter(sensor_name))
        self.logger.addHandler(log_file_handler)
        self.logger.addFilter(ContextFilter())

    def get_session_log_extra(
        self,
        source,
        instance: ProtocolInstanceConfig,
        session_id: Optional[str] = None,
    ) -> dict:
        resolved_session_id = session_id or get_session_id(source, "-")
        return merge_log_extra(
            get_connection_log_extra(source),
            task_name=resolved_session_id,
            sensor_protocol=instance.sensor_protocol,
            protocol_instance=instance.full_name,
        )

    def llm_get_session_history(self, session_id: str) -> BaseChatMessageHistory:
        if session_id not in self.llm_sessions:
            self.llm_sessions[session_id] = InMemoryChatMessageHistory()
        return self.llm_sessions[session_id]

    def choose_llm(
        self, llm_provider: Optional[str] = None, model_name: Optional[str] = None
    ):
        llm_provider_name = llm_provider or self.config["llm"].get(
            "llm_provider", "openai"
        )
        llm_provider_name = llm_provider_name.lower()
        model_name = model_name or self.config["llm"].get("model_name", "gpt-4o-mini")
        temperature = self.config["llm"].getfloat("temperature", 0.2)
        tls_verify = self.config["llm"].getboolean("tls_verify", True)

        if llm_provider_name == "openai":
            return ChatOpenAI(
                model=model_name,
                temperature=temperature,
                **self._httpx_client_options(tls_verify),
            )
        if llm_provider_name == "azure":
            return AzureChatOpenAI(
                azure_deployment=self.config["llm"].get("azure_deployment"),
                azure_endpoint=self.config["llm"].get("azure_endpoint"),
                api_version=self.config["llm"].get("azure_api_version"),
                model=self.config["llm"].get("model_name"),
                temperature=temperature,
                **self._httpx_client_options(tls_verify),
            )
        if llm_provider_name == "ollama":
            kwargs = {}
            if not tls_verify:
                kwargs = {
                    "client_kwargs": {"verify": False},
                    "async_client_kwargs": {"verify": False},
                    "sync_client_kwargs": {"verify": False},
                }
            return ChatOllama(model=model_name, temperature=temperature, **kwargs)
        if llm_provider_name == "aws":
            return ChatBedrockConverse(
                model=model_name,
                region_name=self.config["llm"].get("aws_region", "us-east-1"),
                credentials_profile_name=self.config["llm"].get(
                    "aws_credentials_profile", "default"
                ),
                temperature=temperature,
            )
        if llm_provider_name == "gemini":
            return ChatGoogleGenerativeAI(model=model_name, temperature=temperature)
        raise ValueError(f"Invalid LLM provider {llm_provider_name}.")

    def _httpx_client_options(self, tls_verify: bool) -> dict:
        if tls_verify:
            return {}
        return {
            "http_client": httpx.Client(verify=False),
            "http_async_client": httpx.AsyncClient(verify=False),
        }

    def get_prompts(self, instance: ProtocolInstanceConfig) -> dict:
        system_prompt = self.config["llm"].get("system_prompt", "")
        prompt = instance.get("prompt")
        prompt_file = instance.get("prompt_file")

        if prompt is not None:
            if not prompt.strip():
                print("Error: The prompt text cannot be empty.", file=sys.stderr)
                sys.exit(1)
            user_prompt = prompt
        elif prompt_file:
            user_prompt = self._read_prompt_file(prompt_file)
        elif self.prompt_override is not None:
            if not self.prompt_override.strip():
                print("Error: The prompt text cannot be empty.", file=sys.stderr)
                sys.exit(1)
            user_prompt = self.prompt_override
        elif self.prompt_file_override:
            user_prompt = self._read_prompt_file(self.prompt_file_override)
        else:
            default_prompt = self.resolve_runtime_path("prompt.txt")
            if os.path.exists(default_prompt):
                user_prompt = self._read_prompt_file(default_prompt)
            else:
                raise ValueError("Either prompt or prompt_file must be provided.")

        return {"system_prompt": system_prompt, "user_prompt": user_prompt}

    def _read_prompt_file(self, prompt_file: str) -> str:
        prompt_file = self.resolve_runtime_path(prompt_file)
        if not os.path.exists(prompt_file):
            print(
                f"Error: The specified prompt file '{prompt_file}' does not exist.",
                file=sys.stderr,
            )
            sys.exit(1)
        with open(prompt_file, "r") as f:
            return f.read()

    def build_message_history(self, instance: ProtocolInstanceConfig):
        llm = self.choose_llm(
            self.config["llm"].get("llm_provider"), self.config["llm"].get("model_name")
        )
        prompts = self.get_prompts(instance)

        llm_trimmer = trim_messages(
            max_tokens=self.config["llm"].getint("trimmer_max_tokens", 64000),
            strategy="last",
            token_counter=llm,
            include_system=True,
            allow_partial=False,
            start_on="human",
        )

        llm_prompt = ChatPromptTemplate.from_messages(
            [
                ("system", prompts["system_prompt"]),
                ("system", prompts["user_prompt"]),
                MessagesPlaceholder(variable_name="messages"),
            ]
        )

        llm_chain = (
            RunnablePassthrough.assign(messages=itemgetter("messages") | llm_trimmer)
            | llm_prompt
            | llm
        )

        return RunnableWithMessageHistory(
            llm_chain,
            self.llm_get_session_history,
            input_messages_key="messages",
        )

    def get_message_history(self, instance: ProtocolInstanceConfig):
        if self.message_history_override is not None:
            return self.message_history_override
        if instance.full_name not in self.message_histories:
            self.message_histories[instance.full_name] = self.build_message_history(instance)
        return self.message_histories[instance.full_name]

    async def invoke_llm(
        self,
        instance: ProtocolInstanceConfig,
        session_id: str,
        payload: dict,
    ):
        session = self.get_message_history(instance)
        return await session.ainvoke(
            payload,
            config={"configurable": {"session_id": session_id}},
        )

    async def summarize_session(
        self,
        summary_state: SessionSummaryState,
        instance: ProtocolInstanceConfig,
        session_id: str,
        *,
        username: str = "-",
        interactive: bool = True,
        log_extra: Optional[dict] = None,
    ):
        if summary_state.summary_generated:
            return

        llm_response = await self.invoke_llm(
            instance,
            session_id,
            {
                "messages": [HumanMessage(content=summary_prompt(instance.protocol))],
                "username": username,
                "interactive": interactive,
                "protocol": instance.protocol,
                "protocol_instance": instance.full_name,
            },
        )
        judgement = parse_judgement(llm_response.content)
        self.logger.info(
            "Session summary",
            extra=merge_log_extra(
                log_extra
                or self.get_session_log_extra(None, instance, session_id),
                details=llm_response.content,
                judgement=judgement,
            ),
        )
        summary_state.summary_generated = True


def parse_judgement(content: str) -> str:
    if "Judgement: BENIGN" in content:
        return "BENIGN"
    if "Judgement: SUSPICIOUS" in content:
        return "SUSPICIOUS"
    if "Judgement: MALICIOUS" in content:
        return "MALICIOUS"
    return "UNKNOWN"


def summary_prompt(protocol: str) -> str:
    if protocol == "ssh":
        activity = "SSH commands the user issued"
    elif protocol in {"http", "https"}:
        activity = "HTTP requests the user made"
    else:
        activity = f"{protocol.upper()} protocol interactions the user performed"

    return f"""
Examine the list of all the {activity} during this session. The user is likely
(but not proven) to be an attacker. Analyze the activity and provide the following:

A concise, high-level description of what the user did during the session, including
whether this appears to be reconnaissance, exploitation, post-foothold activity, or
another stage of an attack. Specify the likely goals of the user.

A judgement of the session's nature as either "BENIGN," "SUSPICIOUS," or
"MALICIOUS," based on the observed activity.

Ensure the high-level description accounts for the overall context and intent, even
if some actions seem benign in isolation.

End your response with "Judgement: [BENIGN/SUSPICIOUS/MALICIOUS]".

Be very terse, but always include the high-level attacker's goal. Also do not label
the sections except for the judgement, which you should label clearly, and don't
provide bullet points or item numbers.
"""
