#!/usr/bin/env python3

from configparser import ConfigParser
import argparse
import asyncio
import asyncssh
import threading
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

class JSONFormatter(logging.Formatter):
    def __init__(self, sensor_name, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sensor_name = sensor_name

    def format(self, record):
        log_record = {
            "timestamp": datetime.datetime.fromtimestamp(record.created, datetime.timezone.utc).isoformat(sep="T", timespec="milliseconds"),
            "level": record.levelname,
            "task_name": record.task_name,
            "src_ip": record.src_ip,
            "src_port": record.src_port,
            "dst_ip": record.dst_ip,
            "dst_port": record.dst_port,
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

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        # Get the source and destination IPs and ports
        peername = conn.get_extra_info('peername')
        sockname = conn.get_extra_info('sockname')

        if peername is not None:
            src_ip, src_port = peername[:2]
        else:
            src_ip, src_port = '-', '-'

        if sockname is not None:
            dst_ip, dst_port = sockname[:2]
        else:
            dst_ip, dst_port = '-', '-'

        # Store the connection details in thread-local storage
        thread_local.src_ip = src_ip
        thread_local.src_port = src_port
        thread_local.dst_ip = dst_ip
        thread_local.dst_port = dst_port

        # Log the connection details
        logger.info("SSH connection received", extra={"src_ip": src_ip, "src_port": src_port, "dst_ip": dst_ip, "dst_port": dst_port})

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if exc:
            logger.error('SSH connection error', extra={"error": str(exc)})
            if not isinstance(exc, ConnectionLost):
                traceback.print_exception(exc)
        else:
            logger.info("SSH connection closed")
        # Ensure session summary is called on connection loss if attributes are set
        if hasattr(self, '_process') and hasattr(self, '_llm_config') and hasattr(self, '_session'):
            asyncio.create_task(session_summary(self._process, self._llm_config, self._session, self))

    def begin_auth(self, username: str) -> bool:
        if accounts.get(username) != '':
            logger.info("User attempting to authenticate", extra={"username": username})
            return True
        else:
            logger.info("Authentication success", extra={"username": username, "password": ""})
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
            logger.info("Authentication success", extra={"username": username, "password": password})
            return True
        else:
            logger.info("Authentication failed", extra={"username": username, "password": password})
            return False

async def session_summary(process: asyncssh.SSHServerProcess, llm_config: dict, session: RunnableWithMessageHistory, server: MySSHServer):
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

    logger.info("Session summary", extra={"details": llm_response.content, "judgement": judgement})

    server.summary_generated = True

async def handle_client(process: asyncssh.SSHServerProcess, server: MySSHServer) -> None:
    # This is the main loop for handling SSH client connections. 
    # Any user interaction should be done here.

    # Give each session a unique name
    task_uuid = f"session-{uuid.uuid4()}"
    current_task = asyncio.current_task()
    current_task.set_name(task_uuid)

    llm_config = {"configurable": {"session_id": task_uuid}}

    try:
        if process.command:
            # Handle non-interactive command execution
            command = process.command
            logger.info("User input", extra={"details": b64encode(command.encode('utf-8')).decode('utf-8'), "interactive": False})
            llm_response = await with_message_history.ainvoke(
                {
                    "messages": [HumanMessage(content=command)],
                    "username": process.get_extra_info('username'),
                    "interactive": False
                },
                    config=llm_config
            )
            process.stdout.write(f"{llm_response.content}")
            logger.info("LLM response", extra={"details": b64encode(llm_response.content.encode('utf-8')).decode('utf-8'), "interactive": False})
            await session_summary(process, llm_config, with_message_history, server)
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
            logger.info("LLM response", extra={"details": b64encode(llm_response.content.encode('utf-8')).decode('utf-8'), "interactive": True})

            async for line in process.stdin:
                line = line.rstrip('\n')
                logger.info("User input", extra={"details": b64encode(line.encode('utf-8')).decode('utf-8'), "interactive": True})

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
                    await session_summary(process, llm_config, with_message_history, server)
                    process.exit(0)
                    return
                else:
                    process.stdout.write(f"{llm_response.content}")
                    logger.info("LLM response", extra={"details": b64encode(llm_response.content.encode('utf-8')).decode('utf-8'), "interactive": True})

    except asyncssh.BreakReceived:
        pass
    finally:
        await session_summary(process, llm_config, with_message_history, server)
        process.exit(0)

    # Just in case we ever get here, which we probably shouldn't
    # process.exit(0)

async def start_server() -> None:
    async def process_factory(process: asyncssh.SSHServerProcess) -> None:
        server = process.get_server()
        await handle_client(process, server)

    await asyncssh.listen(
        port=config['ssh'].getint("port", 8022),
        reuse_address=True,
        reuse_port=True,
        server_factory=MySSHServer,
        server_host_keys=config['ssh'].get("host_priv_key", "ssh_host_key"),
        process_factory=lambda process: handle_client(process, MySSHServer()),
        server_version=config['ssh'].get("server_version_string", "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3")
    )

class ContextFilter(logging.Filter):
    """
    This filter is used to add the current asyncio task name to the log record,
    so you can group events in the same session together.
    """

    def filter(self, record):

        task = asyncio.current_task()
        if task:
            task_name = task.get_name()
        else:
            task_name = thread_local.__dict__.get('session_id', '-')

        record.src_ip = thread_local.__dict__.get('src_ip', '-')
        record.src_port = thread_local.__dict__.get('src_port', '-')   
        record.dst_ip = thread_local.__dict__.get('dst_ip', '-')
        record.dst_port = thread_local.__dict__.get('dst_port', '-')

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

#### MAIN ####

try:
    # Parse command line arguments
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
    args = parser.parse_args()

    # Determine which config file to load
    config = ConfigParser()
    if args.config is not None:
        # User explicitly set a config file; error if it doesn't exist.
        if not os.path.exists(args.config):
            print(f"Error: The specified config file '{args.config}' does not exist.", file=sys.stderr)
            sys.exit(1)
        config.read(args.config)
    else:
        default_config = "config.ini"
        if os.path.exists(default_config):
            config.read(default_config)
        else:
            # Use defaults when no config file found.
            config['honeypot'] = {'log_file': 'ssh_log.log', 'sensor_name': socket.gethostname()}
            config['ssh'] = {'port': '8022', 'host_priv_key': 'ssh_host_key', 'server_version_string': 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3'}
            config['llm'] = {'llm_provider': 'openai', 'model_name': 'gpt-3.5-turbo', 'trimmer_max_tokens': '64000', 'temperature': '0.7', 'system_prompt': ''}
            config['user_accounts'] = {}

    # Override config values with command line arguments if provided
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
    if args.port:
        config['ssh']['port'] = str(args.port)
    if args.host_priv_key:
        config['ssh']['host_priv_key'] = args.host_priv_key
    if args.server_version_string:
        config['ssh']['server_version_string'] = args.server_version_string
    if args.log_file:
        config['honeypot']['log_file'] = args.log_file
    if args.sensor_name:
        config['honeypot']['sensor_name'] = args.sensor_name

    # Merge command-line user accounts into the config
    if args.user_account:
        if 'user_accounts' not in config:
            config['user_accounts'] = {}
        for account in args.user_account:
            if '=' in account:
                key, value = account.split('=', 1)
                config['user_accounts'][key.strip()] = value.strip()
            else:
                config['user_accounts'][account.strip()] = ''

    # Read the user accounts from the configuration
    accounts = get_user_accounts()

    # Always use UTC for logging
    logging.Formatter.formatTime = (lambda self, record, datefmt=None: datetime.datetime.fromtimestamp(record.created, datetime.timezone.utc).isoformat(sep="T",timespec="milliseconds"))

    # Get the sensor name from the config or use the system's hostname
    sensor_name = config['honeypot'].get('sensor_name', socket.gethostname())

    # Set up the honeypot logger
    logger = logging.getLogger(__name__)  
    logger.setLevel(logging.INFO)  

    log_file_handler = logging.FileHandler(config['honeypot'].get("log_file", "ssh_log.log"))
    logger.addHandler(log_file_handler)

    log_file_handler.setFormatter(JSONFormatter(sensor_name))

    f = ContextFilter()
    logger.addFilter(f)

    # Now get access to the LLM

    prompts = get_prompts(args.prompt, args.prompt_file)
    llm_system_prompt = prompts["system_prompt"]
    llm_user_prompt = prompts["user_prompt"]

    llm = choose_llm(config['llm'].get("llm_provider"), config['llm'].get("model_name"))

    llm_sessions = dict()

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

    with_message_history = RunnableWithMessageHistory(
        llm_chain, 
        llm_get_session_history,
        input_messages_key="messages"
    )
    # Thread-local storage for connection details
    thread_local = threading.local()

    # Kick off the server!
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(start_server())
    loop.run_forever()

except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
    traceback.print_exc()
    sys.exit(1)

