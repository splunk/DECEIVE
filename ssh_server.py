# To run this program, the file ``ssh_host_key`` must exist with an SSH
# private key in it to use as a server host key. An SSH host certificate
# can optionally be provided in the file ``ssh_host_key-cert.pub``.

import asyncio
import asyncssh
import sys
import json 
from typing import Optional
import logging
import datetime
import uuid
from base64 import b64encode

from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage
from langchain_core.chat_history import (
    BaseChatMessageHistory,
    InMemoryChatMessageHistory,
)
from langchain_core.runnables.history import RunnableWithMessageHistory
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.messages import SystemMessage, trim_messages
from langchain_core.runnables import RunnablePassthrough

from operator import itemgetter

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
            "messages": [HumanMessage(content="")],
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

            # If the user is trying to log out, don't send that to the 
            # LLM, just exit the session.
            if line in ['exit', 'quit', 'logout']:
                process.exit(0)

            # Send the command to the LLM and give the response to the user
            llm_response = await with_message_history.ainvoke(
                {
                    "messages": [HumanMessage(content=line)],
                    "username": process.get_extra_info('username')
                },
                    config=llm_config
            )

            process.stdout.write(f"{llm_response.content}")
            logger.info(f"OUTPUT: {b64encode(llm_response.content.encode('ascii')).decode('ascii')}")

    except asyncssh.BreakReceived:
        pass

    # Just in case we ever get here, which we probably shouldn't
    process.exit(0)

class MySSHServer(asyncssh.SSHServer):
    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        logger.info(f"SSH connection received from {conn.get_extra_info('peername')[0]}.")

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if exc:
            print('SSH connection error: ' + str(exc), file=sys.stderr)
            logger.error('SSH connection error: ' + str(exc), file=sys.stderr)

        else:
            logger.info("SSH connection closed.")

    def begin_auth(self, username: str) -> bool:
        # If the user's password is the empty string, no auth is required
        return accounts.get(username) != ''

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        pw = accounts.get(username, '*')
        return ((pw != '*') and (password == pw))

async def start_server() -> None:
    await asyncssh.create_server(MySSHServer, '', 8022,
                                 server_host_keys=['ssh_host_key'],
                                 process_factory=handle_client)

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
            task_name = "NONE"

        record.task_name = task_name

        return True

def read_accounts() -> dict:
    accounts = dict()

    with open('accounts.json', 'r') as f:
        accounts = json.loads(f.read())

    return accounts

def llm_get_session_history(session_id: str) -> BaseChatMessageHistory:
    if session_id not in llm_sessions:
        llm_sessions[session_id] = InMemoryChatMessageHistory()
    return llm_sessions[session_id]

#### MAIN ####

# Always use UTC for logging
logging.Formatter.formatTime = (lambda self, record, datefmt=None: datetime.datetime.fromtimestamp(record.created, datetime.timezone.utc).astimezone().isoformat(sep="T",timespec="milliseconds"))

# Set up the honeypot logger
logger = logging.getLogger(__name__)  
logger.setLevel(logging.INFO)  

log_file_handler = logging.FileHandler("ssh_log.log")
logger.addHandler(log_file_handler)

log_file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s:%(task_name)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S. %Z"))

f = ContextFilter()
logger.addFilter(f)

# Now get access to the LLM

with open("prompt.txt", "r") as f:
    llm_system_prompt = f.read()

llm_model = ChatOpenAI(model="gpt-4o")

llm_sessions = dict()

llm_trimmer = trim_messages(
    max_tokens=64000,
    strategy="last",
    token_counter=llm_model,
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
    | llm_model
)

with_message_history = RunnableWithMessageHistory(
    llm_chain, 
    llm_get_session_history,
    input_messages_key="messages"
)

# Read the valid accounts
accounts = read_accounts()

# Kick off the server!
loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)
loop.run_until_complete(start_server())
loop.run_forever()

