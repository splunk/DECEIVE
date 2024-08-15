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

async def handle_client(process: asyncssh.SSHServerProcess) -> None:
# This is the main loop for handling SSH client connections. 
# Any user interaction should be done here.

    process.stdout.write('Welcome to my SSH server, %s!\n' %
                         process.get_extra_info('username'))
    
    try:
        async for line in process.stdin:
            line = line.rstrip('\n')
            logging.info(f"INPUT: {line}")
            process.stdout.write('You entered: %s\n' % line)
    except asyncssh.BreakReceived:
        pass

    process.exit(0)

class MySSHServer(asyncssh.SSHServer):
    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        logging.info(f"SSH connection received from {conn.get_extra_info('peername')[0]}.")

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if exc:
            print('SSH connection error: ' + str(exc), file=sys.stderr)
            logging.error('SSH connection error: ' + str(exc), file=sys.stderr)

        else:
            print('SSH connection closed.')
            logging.info("SSH connection closed.")

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


def read_accounts() -> dict:
    accounts = dict()

    with open('accounts.json', 'r') as f:
        accounts = json.loads(f.read())

    return accounts

#### MAIN ####

# Set up the logging
logging.basicConfig(
    filename="ssh_log.log", 
    level=logging.INFO,
    format="%(asctime)s %(levelname)s:%(message)s",
    datefmt="%Y-%m-%d %H:%M:%S. %Z"
)

logging.Formatter.formatTime = (lambda self, record, datefmt=None: datetime.datetime.fromtimestamp(record.created, datetime.timezone.utc).astimezone().isoformat(sep="T",timespec="milliseconds"))

# Read the valid accounts
accounts = read_accounts()

# Kick off the server!
loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)
loop.run_until_complete(start_server())
loop.run_forever()

