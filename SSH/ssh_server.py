#!/usr/bin/env python3

from configparser import ConfigParser
import argparse
import asyncio
import asyncssh
import sys
import json
import os
import traceback
from typing import Optional
import logging
import datetime
import uuid
from base64 import b64encode
from operator import itemgetter
from langchain_openai import ChatOpenAI, AzureChatOpenAI
from langchain_aws import ChatBedrock, ChatBedrockConverse
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_ollama import ChatOllama 
from langchain_core.messages import HumanMessage, SystemMessage, trim_messages
from langchain_core.chat_history import BaseChatMessageHistory, InMemoryChatMessageHistory
from langchain_core.runnables.history import RunnableWithMessageHistory
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.runnables import RunnablePassthrough
from asyncssh.misc import ConnectionLost
import socket

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
config = ConfigParser()
config_base_dir = SCRIPT_DIR
accounts = {}
llm_sessions = {}
logger = logging.getLogger(__name__)
with_message_history = None


def _endpoint_parts(endpoint):
    if endpoint is not None:
        return endpoint[:2]
    return '-', '-'


def get_connection_log_extra(source) -> dict:
    if source is None:
        peername = None
        sockname = None
    else:
        peername = source.get_extra_info('peername')
        sockname = source.get_extra_info('sockname')

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
    return source.get_extra_info('deceive_session_id', fallback)


def get_session_log_extra(source, session_id: Optional[str] = None) -> dict:
    resolved_session_id = session_id or get_session_id(source, '-')
    return merge_log_extra(get_connection_log_extra(source), task_name=resolved_session_id)


def merge_log_extra(log_extra: dict, **extra) -> dict:
    merged = dict(log_extra)
    merged.update(extra)
    return merged


class JSONFormatter(logging.Formatter):
    def __init__(self, sensor_name, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sensor_name = sensor_name

    def format(self, record):
        log_record = {
            "timestamp": datetime.datetime.fromtimestamp(record.created, datetime.timezone.utc).isoformat(sep="T", timespec="milliseconds"),
            "level": record.levelname,
            "task_name": getattr(record, "task_name", "-"),
            "src_ip": getattr(record, "src_ip", "-"),
            "src_port": getattr(record, "src_port", "-"),
            "dst_ip": getattr(record, "dst_ip", "-"),
            "dst_port": getattr(record, "dst_port", "-"),
            "message": record.getMessage(),
            "sensor_name": self.sensor_name,
            "sensor_protocol": "ssh"
        }
        if hasattr(record, 'interactive'):
            log_record["interactive"] = record.interactive
        # Include any additional fields from the extra dictionary
        for key, value in record.__dict__.items():
            if key not in log_record and key != 'args' and key != 'msg':
                log_record[key] = value
        return json.dumps(log_record)

class MySSHServer(asyncssh.SSHServer):
    def __init__(self):
        super().__init__()
        self.summary_generated = False
        self.session_id = new_session_id()
        self.log_extra = get_session_log_extra(None, self.session_id)

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        conn.set_extra_info(deceive_session_id=self.session_id)
        self.log_extra = get_session_log_extra(conn, self.session_id)
        logger.info("SSH connection received", extra=self.log_extra)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if exc:
            logger.error('SSH connection error', extra=merge_log_extra(self.log_extra, error=str(exc)))
            if not isinstance(exc, ConnectionLost):
                traceback.print_exception(exc)
        else:
            logger.info("SSH connection closed", extra=self.log_extra)
        # Ensure session summary is called on connection loss if attributes are set
        if hasattr(self, '_process') and hasattr(self, '_llm_config') and hasattr(self, '_session'):
            asyncio.create_task(session_summary(self._process, self._llm_config, self._session, self, self.log_extra))

    def begin_auth(self, username: str) -> bool:
        if accounts.get(username) != '':
            logger.info("User attempting to authenticate", extra=merge_log_extra(self.log_extra, username=username))
            return True
        else:
            logger.info("Authentication success", extra=merge_log_extra(self.log_extra, username=username, password=""))
            return False

    def password_auth_supported(self) -> bool:
        return True
    def host_based_auth_supported(self) -> bool:
        return False
    def public_key_auth_supported(self) -> bool:
        return False
    def kbdinit_auth_supported(self) -> bool:
        return False

    def validate_password(self, username: str, password: str) -> bool:
        pw = accounts.get(username, '*')
        
        if pw == '*' or (pw != '*' and password == pw):
            logger.info("Authentication success", extra=merge_log_extra(self.log_extra, username=username, password=password))
            return True
        else:
            logger.info("Authentication failed", extra=merge_log_extra(self.log_extra, username=username, password=password))
            return False

async def session_summary(process: asyncssh.SSHServerProcess, llm_config: dict, session: RunnableWithMessageHistory, server: MySSHServer, log_extra: Optional[dict] = None):
    # Check if the summary has already been generated
    if server.summary_generated:
        return

    # When the SSH session ends, ask the LLM to give a nice
    # summary of the attacker's actions and probable intent,
    # as well as a snap judgement about whether we should be 
    # concerned or not.

    prompt = '''
Examine the list of all the SSH commands the user issued during
this session. The user is likely (but not proven) to be an 
attacker. Analyze the commands and provide the following:

A concise, high-level description of what the user did during the 
session, including whether this appears to be reconnaissance, 
exploitation, post-foothold activity, or another stage of an attack. 
Specify the likely goals of the user.

A judgement of the session's nature as either "BENIGN," "SUSPICIOUS," 
or "MALICIOUS," based on the observed activity.

Ensure the high-level description accounts for the overall context and intent, 
even if some commands seem benign in isolation.

End your response with "Judgement: [BENIGN/SUSPICIOUS/MALICIOUS]".

Be very terse, but always include the high-level attacker's goal (e.g., 
"post-foothold reconnaisance", "cryptomining", "data theft" or similar). 
Also do not label the sections (except for the judgement, which you should 
label clearly), and don't provide bullet points or item numbers. You do 
not need to explain every command, just provide the highlights or 
representative examples.
'''

    # Ask the LLM for its summary
    llm_response = await session.ainvoke(
        {
            "messages": [HumanMessage(content=prompt)],
            "username": process.get_extra_info('username'),
            "interactive": True  # Ensure interactive flag is passed
        },
            config=llm_config
    )

    # Extract the judgement from the response
    judgement = "UNKNOWN"
    if "Judgement: BENIGN" in llm_response.content:
        judgement = "BENIGN"
    elif "Judgement: SUSPICIOUS" in llm_response.content:
        judgement = "SUSPICIOUS"
    elif "Judgement: MALICIOUS" in llm_response.content:
        judgement = "MALICIOUS"

    logger.info(
        "Session summary",
        extra=merge_log_extra(log_extra or get_session_log_extra(process), details=llm_response.content, judgement=judgement)
    )

    server.summary_generated = True

async def handle_client(process: asyncssh.SSHServerProcess, server: MySSHServer) -> None:
    # This is the main loop for handling SSH client connections. 
    # Any user interaction should be done here.

    if with_message_history is None:
        raise RuntimeError("LLM message history is not configured.")

    task_uuid = get_session_id(process) or new_session_id()
    current_task = asyncio.current_task()
    current_task.set_name(task_uuid)

    llm_config = {"configurable": {"session_id": task_uuid}}
    log_extra = get_session_log_extra(process, task_uuid)

    try:
        if process.command:
            # Handle non-interactive command execution
            command = process.command
            logger.info(
                "User input",
                extra=merge_log_extra(log_extra, details=b64encode(command.encode('utf-8')).decode('utf-8'), interactive=False)
            )
            llm_response = await with_message_history.ainvoke(
                {
                    "messages": [HumanMessage(content=command)],
                    "username": process.get_extra_info('username'),
                    "interactive": False
                },
                    config=llm_config
            )
            process.stdout.write(f"{llm_response.content}")
            logger.info(
                "LLM response",
                extra=merge_log_extra(log_extra, details=b64encode(llm_response.content.encode('utf-8')).decode('utf-8'), interactive=False)
            )
            await session_summary(process, llm_config, with_message_history, server, log_extra)
            process.exit(0)
        else:
            # Handle interactive session
            llm_response = await with_message_history.ainvoke(
                {
                    "messages": [HumanMessage(content="")],
                    "username": process.get_extra_info('username'),
                    "interactive": True
                },
                    config=llm_config
            )

            process.stdout.write(f"{llm_response.content}")
            logger.info(
                "LLM response",
                extra=merge_log_extra(log_extra, details=b64encode(llm_response.content.encode('utf-8')).decode('utf-8'), interactive=True)
            )

            async for line in process.stdin:
                line = line.rstrip('\n')
                logger.info(
                    "User input",
                    extra=merge_log_extra(log_extra, details=b64encode(line.encode('utf-8')).decode('utf-8'), interactive=True)
                )

                # Send the command to the LLM and give the response to the user
                llm_response = await with_message_history.ainvoke(
                    {
                        "messages": [HumanMessage(content=line)],
                        "username": process.get_extra_info('username'),
                        "interactive": True
                    },
                        config=llm_config
                )
                if llm_response.content == "YYY-END-OF-SESSION-YYY":
                    await session_summary(process, llm_config, with_message_history, server, log_extra)
                    process.exit(0)
                    return
                else:
                    process.stdout.write(f"{llm_response.content}")
                    logger.info(
                        "LLM response",
                        extra=merge_log_extra(log_extra, details=b64encode(llm_response.content.encode('utf-8')).decode('utf-8'), interactive=True)
                    )

    except asyncssh.BreakReceived:
        pass
    finally:
        await session_summary(process, llm_config, with_message_history, server, log_extra)
        process.exit(0)

    # Just in case we ever get here, which we probably shouldn't
    # process.exit(0)

def resolve_runtime_path(path: str) -> str:
    if os.path.isabs(path) or os.path.exists(path):
        return path

    for base_dir in (config_base_dir, SCRIPT_DIR):
        candidate = os.path.join(base_dir, path)
        if os.path.exists(candidate):
            return candidate

    return path


def resolve_config_output_path(path: str) -> str:
    if os.path.isabs(path):
        return path
    return os.path.join(config_base_dir, path)


async def start_server():
    return await asyncssh.listen(
        host=config['ssh'].get("listen_host", ""),
        port=config['ssh'].getint("port", 8022),
        reuse_address=True,
        reuse_port=True,
        server_factory=MySSHServer,
        server_host_keys=resolve_runtime_path(config['ssh'].get("host_priv_key", "ssh_host_key")),
        process_factory=lambda process: handle_client(process, MySSHServer()),
        server_version=config['ssh'].get("server_version_string", "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3")
    )

class ContextFilter(logging.Filter):
    """
    This filter is used to add the current asyncio task name to the log record,
    so you can group events in the same session together.
    """

    def filter(self, record):

        try:
            task = asyncio.current_task()
        except RuntimeError:
            task = None

        if hasattr(record, 'task_name'):
            return True

        if task:
            task_name = task.get_name()
        else:
            task_name = '-'

        record.task_name = task_name
        
        return True

def llm_get_session_history(session_id: str) -> BaseChatMessageHistory:
    if session_id not in llm_sessions:
        llm_sessions[session_id] = InMemoryChatMessageHistory()
    return llm_sessions[session_id]

def get_user_accounts() -> dict:
    if (not 'user_accounts' in config) or (len(config.items('user_accounts')) == 0):
        raise ValueError("No user accounts found in configuration file.")
    
    accounts = dict()

    for k, v in config.items('user_accounts'):
        accounts[k] = v

    return accounts

def choose_llm(llm_provider: Optional[str] = None, model_name: Optional[str] = None):
    llm_provider_name = llm_provider or config['llm'].get("llm_provider", "openai")
    llm_provider_name = llm_provider_name.lower()
    model_name = model_name or config['llm'].get("model_name", "gpt-4o-mini")
    
    # Get temperature parameter from config, default to 0.2 if not specified
    temperature = config['llm'].getfloat("temperature", 0.2)

    if llm_provider_name == 'openai':
        llm_model = ChatOpenAI(
            model=model_name,
            temperature=temperature
        )
    elif llm_provider_name == 'azure':
        llm_model = AzureChatOpenAI(
            azure_deployment=config['llm'].get("azure_deployment"),
            azure_endpoint=config['llm'].get("azure_endpoint"),
            api_version=config['llm'].get("azure_api_version"),
            model=config['llm'].get("model_name"),  # Ensure model_name is passed here
            temperature=temperature
        )
    elif llm_provider_name == 'ollama':
        llm_model = ChatOllama(
            model=model_name,
            temperature=temperature
        )
    elif llm_provider_name == 'aws':
        llm_model = ChatBedrockConverse(
            model=model_name,
            region_name=config['llm'].get("aws_region", "us-east-1"),
            credentials_profile_name=config['llm'].get("aws_credentials_profile", "default"),
            temperature=temperature
        )
    elif llm_provider_name == 'gemini':
        llm_model = ChatGoogleGenerativeAI(
            model=model_name,
            temperature=temperature
        )
    else:
        raise ValueError(f"Invalid LLM provider {llm_provider_name}.")

    return llm_model

def get_prompts(prompt: Optional[str], prompt_file: Optional[str]) -> dict:
    system_prompt = config['llm']['system_prompt']
    if prompt is not None:
        if not prompt.strip():
            print("Error: The prompt text cannot be empty.", file=sys.stderr)
            sys.exit(1)
        user_prompt = prompt
    elif prompt_file:
        prompt_file = resolve_runtime_path(prompt_file)
        if not os.path.exists(prompt_file):
            print(f"Error: The specified prompt file '{prompt_file}' does not exist.", file=sys.stderr)
            sys.exit(1)
        with open(prompt_file, "r") as f:
            user_prompt = f.read()
    elif os.path.exists("prompt.txt"):
        with open("prompt.txt", "r") as f:
            user_prompt = f.read()
    else:
        raise ValueError("Either prompt or prompt_file must be provided.")
    return {
        "system_prompt": system_prompt,
        "user_prompt": user_prompt
    }

def parse_args(argv=None):
    parser = argparse.ArgumentParser(description='Start the SSH honeypot server.')
    parser.add_argument('-c', '--config', type=str, default=None, help='Path to the configuration file')
    parser.add_argument('-p', '--prompt', type=str, help='The entire text of the prompt')
    parser.add_argument('-f', '--prompt-file', type=str, default='prompt.txt', help='Path to the prompt file')
    parser.add_argument('-l', '--llm-provider', type=str, help='The LLM provider to use')
    parser.add_argument('-m', '--model-name', type=str, help='The model name to use')
    parser.add_argument('-t', '--trimmer-max-tokens', type=int, help='The maximum number of tokens to send to the LLM backend in a single request')
    parser.add_argument('-s', '--system-prompt', type=str, help='System prompt for the LLM')
    parser.add_argument('-r', '--temperature', type=float, help='Temperature parameter for controlling randomness in LLM responses (0.0-2.0)')
    parser.add_argument('-P', '--port', type=int, help='The port the SSH honeypot will listen on')
    parser.add_argument('-k', '--host-priv-key', type=str, help='The host key to use for the SSH server')
    parser.add_argument('-v', '--server-version-string', type=str, help='The server version string to send to clients')
    parser.add_argument('-L', '--log-file', type=str, help='The name of the file you wish to write the honeypot log to')
    parser.add_argument('-S', '--sensor-name', type=str, help='The name of the sensor, used to identify this honeypot in the logs')
    parser.add_argument('-u', '--user-account', action='append', help='User account in the form username=password. Can be repeated.')
    return parser.parse_args(argv)


def load_config(args) -> ConfigParser:
    global config_base_dir

    loaded_config = ConfigParser()
    if args.config is not None:
        if not os.path.exists(args.config):
            print(f"Error: The specified config file '{args.config}' does not exist.", file=sys.stderr)
            sys.exit(1)
        loaded_config.read(args.config)
        config_base_dir = os.path.dirname(os.path.abspath(args.config))
    else:
        default_config = resolve_runtime_path("config.ini")
        if os.path.exists(default_config):
            loaded_config.read(default_config)
            config_base_dir = os.path.dirname(os.path.abspath(default_config))
        else:
            loaded_config['honeypot'] = {'log_file': 'ssh_log.log', 'sensor_name': socket.gethostname()}
            loaded_config['ssh'] = {'port': '8022', 'host_priv_key': 'ssh_host_key', 'server_version_string': 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3'}
            loaded_config['llm'] = {'llm_provider': 'openai', 'model_name': 'gpt-3.5-turbo', 'trimmer_max_tokens': '64000', 'temperature': '0.7', 'system_prompt': ''}
            loaded_config['user_accounts'] = {}
            config_base_dir = SCRIPT_DIR

    return loaded_config


def apply_args_to_config(args) -> None:
    if args.llm_provider:
        config['llm']['llm_provider'] = args.llm_provider
    if args.model_name:
        config['llm']['model_name'] = args.model_name
    if args.trimmer_max_tokens:
        config['llm']['trimmer_max_tokens'] = str(args.trimmer_max_tokens)
    if args.system_prompt:
        config['llm']['system_prompt'] = args.system_prompt
    if args.temperature is not None:
        config['llm']['temperature'] = str(args.temperature)
    if args.port is not None:
        config['ssh']['port'] = str(args.port)
    if args.host_priv_key:
        config['ssh']['host_priv_key'] = args.host_priv_key
    if args.server_version_string:
        config['ssh']['server_version_string'] = args.server_version_string
    if args.log_file:
        config['honeypot']['log_file'] = args.log_file
    if args.sensor_name:
        config['honeypot']['sensor_name'] = args.sensor_name

    if args.user_account:
        if 'user_accounts' not in config:
            config['user_accounts'] = {}
        for account in args.user_account:
            if '=' in account:
                key, value = account.split('=', 1)
                config['user_accounts'][key.strip()] = value.strip()
            else:
                config['user_accounts'][account.strip()] = ''


def configure_logging() -> None:
    global logger

    logging.Formatter.formatTime = (lambda self, record, datefmt=None: datetime.datetime.fromtimestamp(record.created, datetime.timezone.utc).isoformat(sep="T", timespec="milliseconds"))

    sensor_name = config['honeypot'].get('sensor_name', socket.gethostname())
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    logger.filters.clear()
    logger.propagate = False

    log_file = resolve_config_output_path(config['honeypot'].get("log_file", "ssh_log.log"))
    log_file_handler = logging.FileHandler(log_file)
    log_file_handler.setFormatter(JSONFormatter(sensor_name))
    logger.addHandler(log_file_handler)
    logger.addFilter(ContextFilter())


def build_message_history(llm_system_prompt: str, llm_user_prompt: str):
    llm = choose_llm(config['llm'].get("llm_provider"), config['llm'].get("model_name"))

    llm_trimmer = trim_messages(
        max_tokens=config['llm'].getint("trimmer_max_tokens", 64000),
        strategy="last",
        token_counter=llm,
        include_system=True,
        allow_partial=False,
        start_on="human",
    )

    llm_prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                llm_system_prompt
            ),
            (
                "system",
                llm_user_prompt
            ),
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
        llm_get_session_history,
        input_messages_key="messages"
    )


def configure_runtime(args, message_history=None) -> None:
    global accounts, config, config_base_dir, llm_sessions, with_message_history

    config_base_dir = SCRIPT_DIR
    config = load_config(args)
    apply_args_to_config(args)

    accounts = get_user_accounts()
    llm_sessions = {}
    configure_logging()

    if message_history is None:
        prompts = get_prompts(args.prompt, args.prompt_file)
        with_message_history = build_message_history(prompts["system_prompt"], prompts["user_prompt"])
    else:
        with_message_history = message_history


def main(argv=None) -> int:
    try:
        args = parse_args(argv)
        configure_runtime(args)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(start_server())
        loop.run_forever()
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
