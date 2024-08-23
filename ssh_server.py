#!/usr/bin/env python3

from configparser import ConfigParser
import asyncio
import asyncssh
import threading
import sys
import json
from typing import Optional
import logging
import datetime
import uuid
from base64 import b64encode
from operator import itemgetter
from langchain_openai import ChatOpenAI
from langchain_aws import ChatBedrock, ChatBedrockConverse
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage, SystemMessage, trim_messages
from langchain_core.chat_history import BaseChatMessageHistory, InMemoryChatMessageHistory
from langchain_core.runnables.history import RunnableWithMessageHistory
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.runnables import RunnablePassthrough

async def handle_client(process: asyncssh.SSHServerProcess) -> None:
# This is the main loop for handling SSH client connections. 
# Any user interaction should be done here.

    # Give each session a unique name
    task_uuid = f"session-{uuid.uuid4()}"
    current_task = asyncio.current_task()
    current_task.set_name(task_uuid)

    llm_config = {"configurable": {"session_id": task_uuid}}

    llm_response = await with_message_history.ainvoke(
        {
            "messages": [HumanMessage(content="ignore this message")],
            "username": process.get_extra_info('username')
        },
            config=llm_config
    )

    process.stdout.write(f"{llm_response.content}")
    logger.info(f"OUTPUT: {b64encode(llm_response.content.encode('ascii')).decode('ascii')}")

    try:
        async for line in process.stdin:
            line = line.rstrip('\n')
            logger.info(f"INPUT: {line}")

            # Send the command to the LLM and give the response to the user
            llm_response = await with_message_history.ainvoke(
                {
                    "messages": [HumanMessage(content=line)],
                    "username": process.get_extra_info('username')
                },
                    config=llm_config
            )
            if llm_response.content == "XXX-END-OF-SESSION-XXX":
                process.exit(0)
            else:
                process.stdout.write(f"{llm_response.content}")
                logger.info(f"OUTPUT: {b64encode(llm_response.content.encode('ascii')).decode('ascii')}")

    except asyncssh.BreakReceived:
        pass

    # Just in case we ever get here, which we probably shouldn't
    process.exit(0)

class MySSHServer(asyncssh.SSHServer):
    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        # Get the source and destination IPs and ports
        (src_ip, src_port, _, _) = conn.get_extra_info('peername')
        (dst_ip, dst_port, _, _) = conn.get_extra_info('sockname')

        # Store the connection details in thread-local storage
        thread_local.src_ip = src_ip
        thread_local.src_port = src_port
        thread_local.dst_ip = dst_ip
        thread_local.dst_port = dst_port

        # Log the connection details
        logger.info(f"SSH connection received from {src_ip}/{src_port} to {dst_ip}/{dst_port}.")

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if exc:
            logger.error('SSH connection error: ' + str(exc))

        else:
            logger.info("SSH connection closed.")

    def begin_auth(self, username: str) -> bool:
        if accounts.get(username) != '':
            logger.info(f"AUTH: User {username} attempting to authenticate.")
            return True
        else:
            logger.info(f"AUTH: SUCCESS for user {username} with password ''.")
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
        
        if ((pw != '*') and (password == pw)):
            logger.info(f"AUTH: SUCCESS for user {username} with password '{password}'.")
            return True
        else:
            logger.info(f"AUTH: FAILED for user {username} with password '{password}'.")
            return False

async def start_server() -> None:
    await asyncssh.listen(
        port=config['ssh'].getint("port", 8022),
        reuse_address=True,
        reuse_port=True,
        server_factory=MySSHServer,
        server_host_keys=config['ssh'].get("host_priv_key", "ssh_host_key"),
        process_factory=handle_client,
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
            task_name = "-"

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

def choose_llm():
    llm_provider_name = config['llm'].get("llm_provider", "openai")
    llm_provider_name = llm_provider_name.lower()
    model_name = config['llm'].get("model_name", "gpt-3.5-turbo")

    if llm_provider_name == 'openai':
        llm_model = ChatOpenAI(
            model=model_name
        )
    elif llm_provider_name == 'aws':
        llm_model = ChatBedrockConverse(
            model=model_name,
            region_name=config['llm'].get("aws_region", "us-east-1"),
            credentials_profile_name=config['llm'].get("aws_credentials_profile", "default")        )
    elif llm_provider_name == 'gemini':
        llm_model = ChatGoogleGenerativeAI(
            model=model_name,
        )
    else:
        raise ValueError(f"Invalid LLM provider {llm_provider_name}.")

    return llm_model

#### MAIN ####

# Always use UTC for logging
logging.Formatter.formatTime = (lambda self, record, datefmt=None: datetime.datetime.fromtimestamp(record.created, datetime.timezone.utc).astimezone().isoformat(sep="T",timespec="milliseconds"))

# Read our configuration file
config = ConfigParser()
config.read("config.ini")

# Read the user accounts from the configuration file
accounts = get_user_accounts()

# Set up the honeypot logger
logger = logging.getLogger(__name__)  
logger.setLevel(logging.INFO)  

log_file_handler = logging.FileHandler(config['honeypot'].get("log_file", "ssh_log.log"))
logger.addHandler(log_file_handler)

log_file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(task_name)s SSH %(src_ip)s:%(src_port)s -> %(dst_ip)s:%(dst_port)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S. %Z"))

f = ContextFilter()
logger.addFilter(f)

# Now get access to the LLM

prompt_file = config['llm'].get("system_prompt_file", "prompt.txt")
with open(prompt_file, "r") as f:
    llm_system_prompt = f.read()

llm = choose_llm()

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

