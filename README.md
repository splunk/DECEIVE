# HADES

HADES, the **Honeypot And Deception Emulation System**, is a high-interaction, low-effort honeypot system. Unlike most high-interaction honeypots, HADES doesn't provide attackers with access to any actual system. AI actually does all the work of simulating a realistic honeypot system based on a configurable system prompt that describes what type of system you want to simulate. Unlike many other high-interaction honeypots which require substantial effort to seed with realistic users, data, and applications, HADES's AI backend will do all this for you, automatically.

This version of HADES simulates a Linux server via the SSH protocol.

## Setup
### Install Dependencies
Ensure you have Python3 installed. Then, install the required dependencies:

    pip install -r requirements.txt

## Configuration

Before running HADES, you need to configure it properly. Follow these steps:

### Generate the SSH Host Key

The SSH server requires a TLS keypair for security communications. You can generate an SSH keypair using the following command:

    ssh-keygen -t rsa -b 4096 -f SSH/ssh_host_key

### Copy the Template Configuration File

   Copy the `SSH/config.ini.TEMPLATE` file to `SSH/config.ini`:

### Edit the Configuration File

Open the `SSH/config.ini` file and review the settings. Update the values as needed, paying special attention to the values in the `[llm]` and `[user_accounts]` sections.

## Execution
To start the HADES honeypot server, change to the `SSH` directory and run the following command:

    python3 ./ssh_server.py

The server will start and listen for incoming SSH connections on the configured port.

## Test it Out
Once the server is running (this can take a few seconds), access it on the configured port.  If you are on a Linux or UNIX-like system, try the following command (substitute "localhost" and "8022" as appropriate for your config):

    ssh guest@localhost -p 8022

### Logging
Logs will be written to the file specified in the `log_file` configuration option. Review the logs to monitor honeypot activity.

### Contributing
Contributions are welcome! Please submit pull requests or open issues to discuss any changes or improvements.

### License
This project is licensed under the MIT License. See the LICENSE file for details.