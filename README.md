# DECEIVE

<img align="right" src="DECEIVE.png" alt="A cybercriminal interacts with a ghostly, AI-driven honeypot system">

DECEIVE, the **DECeption with Evaluative Integrated Validation Engine**, is a high-interaction, low-effort honeypot system. Unlike most high-interaction honeypots, DECEIVE doesn't provide attackers with access to any actual system. AI actually does all the work of simulating a realistic honeypot system based on a configurable system prompt that describes what type of system you want to simulate. Unlike many other high-interaction honeypots which require substantial effort to seed with realistic users, data, and applications, DECEIVE's AI backend will do all this for you, automatically.

This version of DECEIVE simulates a Linux server via the SSH protocol. It will log all the user inputs, the outputs returned by the LLM backend, as well as a summary of each session after they end. It'll even tell you if it thinks a users' session was benign, suspicious, or outright malicious.

⛔️⛔️ **DECEIVE is a proof-of-concept project. It is not production quality. Try it, learn from it, but be cautious about deploying it in a production environment.** ⛔️⛔️

## Supported Host Platforms
DECEIVE is primarily developed on MacOS 15 (Sequoia), but it should work on any UNIX-like system which can run Python3.  This includes other versions of MacOS, Linux, and even Windows (via Windows Subsystem for Linux). 

## Setup
### Check out the latest code from GitHub
You can fetch the latest version using the following command:

    git clone https://github.com/splunk/DECEIVE

The rest of these instructions assume you have changed your current directory to the repo after cloning completes.

### Install Dependencies
Ensure you have Python3 installed. We recommend running DECEIVE in it's own Python virtualenv but it is not required.

Next, install the Python modules the honeypot needs:

    pip3 install -r requirements.txt

### Generate the SSH Host Key

The SSH server requires a TLS keypair for security communications. From the top directory of the repo, generate an SSH keypair using the following command:

    ssh-keygen -t rsa -b 4096 -f SSH/ssh_host_key

### Copy the Template Configuration File

   Copy the `SSH/config.ini.TEMPLATE` file to `SSH/config.ini`:

### Edit the Configuration File

Open the `SSH/config.ini` file and review the settings. Update the values as needed, paying special attention to the values in the `[llm]` section, where you will configure the LLM backend you wish to use, and to the `[user_accounts]` section, where you can configure the usernames and passwords you'd like the honeypot to support.

### Tell DECEIVE What it's Emulating
Edit the `SSH/prompt.txt` file to include a short description of the type of system you want it to pretend to be. You don't have to be very detailed here, though the more details you can provide, the better the simulation will be. You can keep it high level, like:

    You are a video game developer's system. Include realistic video game source and asset files.
If you like, you can add whatever additional details you think will be helpful.  For example:

    You are the Internet-facing mail server for bigschool.edu, a state-sponsored university in Virginia. Valid user accounts are "a20093887", "a20093887-admin", and "mxadmin". Home directories are in "/home/$USERNAME".  Everyone's default shell is /bin/zsh, except mxadmin's, which is bash. Mail spools for all campus users (be sure to include email accounts that are not valid for logon to this server) are in /var/spool/mail. Be sure to simulate some juicy emails there, but make them realistic.  Some should be personal, but some should be just about the business of administering the school, dealing with students, applying for financial aid, etc. Make the spool permissions relaxed, simulating a misconfiguration that would allow anyone on the system to read the files.

## Running the Honeypot
To start the DECEIVE honeypot server, first make sure that you have set any environment variables required by your chosen LLM backend.  For example, if you are using any of the OpenAI models, you will need to set the `OPENAI_API_KEY` variable like so:

    export OPENAI_API_KEY="<your secret API key>

Next, change to the `SSH` directory and run the following command:

    python3 ./ssh_server.py

The server will start and listen for incoming SSH connections on the configured port. It will not produce any output, but will stay executing in the foreground.

## Test it Out
Once the server is running (this can take a few seconds), access it on the configured port.  If you are on a Linux or UNIX-like system, try the following command (substitute "localhost" and "8022" as appropriate for your config):

    ssh guest@localhost -p 8022

### Logging
Logs will be written to the file specified in the `log_file` configuration option. By default, this is `SSH/ssh_log.log`. 

DECEIVE logs are in JSON lines format, with each line being a complete JSON document. 

The following is a complete example of a simple SSH session, in which the user executed two simple commands (`pwd` and `exit`):

```json
{"timestamp": "2025-01-10T20:37:55.018+00:00", "level": "INFO", "task_name": "-", "src_ip": "::1", "src_port": 58164, "dst_ip": "::1", "dst_port": 8022, "message": "SSH connection received", "name": "__main__", "levelname": "INFO", "levelno": 20, "pathname": "/home/deceive/DECEIVE/SSH/./ssh_server.py", "filename": "ssh_server.py", "module": "ssh_server", "exc_info": null, "exc_text": null, "stack_info": null, "lineno": 59, "funcName": "connection_made", "created": 1736541475.0183098, "msecs": 18.0, "relativeCreated": 13872.790813446045, "thread": 8145041472, "threadName": "MainThread", "processName": "MainProcess", "process": 10823, "taskName": null}
{"timestamp": "2025-01-10T20:37:55.177+00:00", "level": "INFO", "task_name": "Task-5", "src_ip": "::1", "src_port": 58164, "dst_ip": "::1", "dst_port": 8022, "message": "Authentication success", "name": "__main__", "levelname": "INFO", "levelno": 20, "pathname": "/home/deceive/DECEIVE/SSH/./ssh_server.py", "filename": "ssh_server.py", "module": "ssh_server", "exc_info": null, "exc_text": null, "stack_info": null, "lineno": 75, "funcName": "begin_auth", "created": 1736541475.1775439, "msecs": 177.0, "relativeCreated": 14032.02486038208, "thread": 8145041472, "threadName": "MainThread", "processName": "MainProcess", "process": 10823, "taskName": "Task-5", "username": "guest", "password": ""}
{"timestamp": "2025-01-10T20:37:57.456+00:00", "level": "INFO", "task_name": "session-6355218b-59e5-4549-add3-49e6d1efc133", "src_ip": "::1", "src_port": 58164, "dst_ip": "::1", "dst_port": 8022, "message": "LLM response", "name": "__main__", "levelname": "INFO", "levelno": 20, "pathname": "/home/deceive/DECEIVE/SSH/./ssh_server.py", "filename": "ssh_server.py", "module": "ssh_server", "exc_info": null, "exc_text": null, "stack_info": null, "lineno": 174, "funcName": "handle_client", "created": 1736541477.4568708, "msecs": 456.0, "relativeCreated": 16311.351776123047, "thread": 8145041472, "threadName": "MainThread", "processName": "MainProcess", "process": 10823, "taskName": "session-6355218b-59e5-4549-add3-49e6d1efc133", "details": "V2VsY29tZSB0byBHYW1lRGV2IENvcnAncyBEZXZlbG9wbWVudCBFbnZpcm9ubWVudAoKLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLQogICBXZWxjb21lLCBndWVzdCEgCiAgIExhc3QgbG9naW46IFR1ZSBPY3QgMjQgMTQ6MzI6MTUgMjAyMyBmcm9tIDE5Mi4xNjguMS4xMAogICBQcm9qZWN0czoKICAgICAtIEZhbnRhc3lRdWVzdAogICAgIC0gU3BhY2VFeHBsb3JlcnMKICAgICAtIFJhY2luZ01hbmlhCiAgIFN5c3RlbSBTdGF0dXM6IEFsbCBzeXN0ZW1zIG9wZXJhdGlvbmFsCiAgIFJlbWVtYmVyIHRvIGNvbW1pdCB5b3VyIGNoYW5nZXMhCi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0KCmd1ZXN0QGRldi13b3Jrc3RhdGlvbjp+JCA="}
{"timestamp": "2025-01-10T20:37:59.333+00:00", "level": "INFO", "task_name": "session-6355218b-59e5-4549-add3-49e6d1efc133", "src_ip": "::1", "src_port": 58164, "dst_ip": "::1", "dst_port": 8022, "message": "User input", "name": "__main__", "levelname": "INFO", "levelno": 20, "pathname": "/home/deceive/DECEIVE/SSH/./ssh_server.py", "filename": "ssh_server.py", "module": "ssh_server", "exc_info": null, "exc_text": null, "stack_info": null, "lineno": 184, "funcName": "handle_client", "created": 1736541479.3334038, "msecs": 333.0, "relativeCreated": 18187.88480758667, "thread": 8145041472, "threadName": "MainThread", "processName": "MainProcess", "process": 10823, "taskName": "session-6355218b-59e5-4549-add3-49e6d1efc133", "details": "cHdk"}
{"timestamp": "2025-01-10T20:38:00.189+00:00", "level": "INFO", "task_name": "session-6355218b-59e5-4549-add3-49e6d1efc133", "src_ip": "::1", "src_port": 58164, "dst_ip": "::1", "dst_port": 8022, "message": "LLM response", "name": "__main__", "levelname": "INFO", "levelno": 20, "pathname": "/home/deceive/DECEIVE/SSH/./ssh_server.py", "filename": "ssh_server.py", "module": "ssh_server", "exc_info": null, "exc_text": null, "stack_info": null, "lineno": 200, "funcName": "handle_client", "created": 1736541480.189375, "msecs": 189.0, "relativeCreated": 19043.855905532837, "thread": 8145041472, "threadName": "MainThread", "processName": "MainProcess", "process": 10823, "taskName": "session-6355218b-59e5-4549-add3-49e6d1efc133", "details": "L2hvbWUvZ3Vlc3QKCmd1ZXN0QGRldi13b3Jrc3RhdGlvbjp+JCA="}
{"timestamp": "2025-01-10T20:38:01.944+00:00", "level": "INFO", "task_name": "session-6355218b-59e5-4549-add3-49e6d1efc133", "src_ip": "::1", "src_port": 58164, "dst_ip": "::1", "dst_port": 8022, "message": "User input", "name": "__main__", "levelname": "INFO", "levelno": 20, "pathname": "/home/deceive/DECEIVE/SSH/./ssh_server.py", "filename": "ssh_server.py", "module": "ssh_server", "exc_info": null, "exc_text": null, "stack_info": null, "lineno": 184, "funcName": "handle_client", "created": 1736541481.944072, "msecs": 944.0, "relativeCreated": 20798.552989959717, "thread": 8145041472, "threadName": "MainThread", "processName": "MainProcess", "process": 10823, "taskName": "session-6355218b-59e5-4549-add3-49e6d1efc133", "details": "ZXhpdA=="}
{"timestamp": "2025-01-10T20:38:04.132+00:00", "level": "INFO", "task_name": "session-6355218b-59e5-4549-add3-49e6d1efc133", "src_ip": "::1", "src_port": 58164, "dst_ip": "::1", "dst_port": 8022, "message": "Session summary", "name": "__main__", "levelname": "INFO", "levelno": 20, "pathname": "/home/deceive/DECEIVE/SSH/./ssh_server.py", "filename": "ssh_server.py", "module": "ssh_server", "exc_info": null, "exc_text": null, "stack_info": null, "lineno": 151, "funcName": "session_summary", "created": 1736541484.1324642, "msecs": 132.0, "relativeCreated": 22986.945152282715, "thread": 8145041472, "threadName": "MainThread", "processName": "MainProcess", "process": 10823, "taskName": "session-6355218b-59e5-4549-add3-49e6d1efc133", "details": "The user issued basic commands like `pwd` to check the current working directory and `exit` to terminate the session. This activity is typical of a benign user checking their environment upon logging in and then closing the session. There is no indication of reconnaissance, exploitation, or any post-foothold activity such as privilege escalation or data exfiltration. The actions appear to be standard and routine.\n\nJudgement: BENIGN", "judgement": "BENIGN"}
{"timestamp": "2025-01-10T20:38:04.139+00:00", "level": "INFO", "task_name": "-", "src_ip": "::1", "src_port": 58164, "dst_ip": "::1", "dst_port": 8022, "message": "SSH connection closed", "name": "__main__", "levelname": "INFO", "levelno": 20, "pathname": "/home/deceive/DECEIVE/SSH/./ssh_server.py", "filename": "ssh_server.py", "module": "ssh_server", "exc_info": null, "exc_text": null, "stack_info": null, "lineno": 65, "funcName": "connection_lost", "created": 1736541484.139776, "msecs": 139.0, "relativeCreated": 22994.2569732666, "thread": 8145041472, "threadName": "MainThread", "processName": "MainProcess", "process": 10823, "taskName": null}
```

Things to note:
* Timestamps are always in UTC.  UTC||GTFO!
* The `task_name` field contains a unique value that can be used to associate all the entries from a single SSH session.
* The "message" field will tell you what type of entry this:
    * `SSH connection received`
    * `Authentication success`
    * `User input`
    * `LLM response`
    * `Session summary`
    * `SSH connection closed`
* Several of these message types also feature a `details` field with additional information
    * `User input` messages contain a base64-encoded copy of the entire user input in the `details` field, as well as an `interactive` field (true/false) that tells you whether this was an interactive or non-interactive command (i.e., whether they logged in with a terminal session or provided a command on the SSH command-line).
    * `LLM response` messages contain a base64-encoded copy of the entire simulated response in the `details` field.
    * `Session summary` messages contain not only a summary of the commands, but also a guess as to what they might have been intended to accomplish. There will also be a `judgement` field that contains one of "BENIGN", "SUSPICIOUS", or "MALICIOUS"
* Since this is a honeypot and not intended for use by real users, IT WILL LOG USERNAMES AND PASSWORDS! These are found in the `Authentication success` messages, in the `username` and `password` fields.

### Contributing
Contributions are welcome! Please submit pull requests or open issues to discuss any changes or improvements.

### License
This project is licensed under the MIT License. See the LICENSE file for details.
