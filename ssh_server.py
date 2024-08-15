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

async def handle_client(process: asyncssh.SSHServerProcess) -> None:
# This is the main loop for handling SSH client connections. 
# Any user interaction should be done here.

    # Give each session a unique name
    current_task = asyncio.current_task()
    current_task.set_name(f"session-{uuid.uuid4()}")

    process.stdout.write('Welcome to my SSH server, %s!\n' %
                         process.get_extra_info('username'))
    
    try:
        async for line in process.stdin:
            line = line.rstrip('\n')
            logger.info(f"INPUT: {line}")
            process.stdout.write('You entered: %s\n' % line)
    except asyncssh.BreakReceived:
        pass

    process.exit(0)

class MySSHServer(asyncssh.SSHServer):
    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        logger.info(f"SSH connection received from {conn.get_extra_info('peername')[0]}.")

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if exc:
            print('SSH connection error: ' + str(exc), file=sys.stderr)
            logger.error('SSH connection error: ' + str(exc), file=sys.stderr)

        else:
            print('SSH connection closed.')
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

# Read the valid accounts
accounts = read_accounts()

# Kick off the server!
loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)
loop.run_until_complete(start_server())
loop.run_forever()

