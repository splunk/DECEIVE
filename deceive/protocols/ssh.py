from __future__ import annotations

import asyncio
import traceback
from typing import Optional

import asyncssh
from asyncssh.misc import ConnectionLost
from langchain_core.messages import HumanMessage

from deceive.runtime import (
    DeceiveRuntime,
    ProtocolInstanceConfig,
    SessionSummaryState,
    encode_details,
    get_session_id,
    merge_log_extra,
    new_session_id,
)


class MySSHServer(asyncssh.SSHServer):
    def __init__(self, runtime: DeceiveRuntime, instance: ProtocolInstanceConfig):
        super().__init__()
        self.runtime = runtime
        self.instance = instance
        self.session_id = new_session_id()
        self.log_extra = runtime.get_session_log_extra(None, instance, self.session_id)

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        conn.set_extra_info(deceive_session_id=self.session_id)
        self.log_extra = self.runtime.get_session_log_extra(
            conn, self.instance, self.session_id
        )
        self.runtime.logger.info("SSH connection received", extra=self.log_extra)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if exc:
            self.runtime.logger.error(
                "SSH connection error",
                extra=merge_log_extra(self.log_extra, error=str(exc)),
            )
            if not isinstance(exc, ConnectionLost):
                traceback.print_exception(exc)
        else:
            self.runtime.logger.info("SSH connection closed", extra=self.log_extra)

    def begin_auth(self, username: str) -> bool:
        if self.runtime.accounts.get(username) != "":
            self.runtime.logger.info(
                "User attempting to authenticate",
                extra=merge_log_extra(self.log_extra, username=username),
            )
            return True

        self.runtime.logger.info(
            "Authentication success",
            extra=merge_log_extra(self.log_extra, username=username, password=""),
        )
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
        pw = self.runtime.accounts.get(username, "*")

        if pw == "*" or (pw != "*" and password == pw):
            self.runtime.logger.info(
                "Authentication success",
                extra=merge_log_extra(
                    self.log_extra, username=username, password=password
                ),
            )
            return True

        self.runtime.logger.info(
            "Authentication failed",
            extra=merge_log_extra(self.log_extra, username=username, password=password),
        )
        return False


async def handle_client(
    process: asyncssh.SSHServerProcess,
    runtime: DeceiveRuntime,
    instance: ProtocolInstanceConfig,
    summary_state: SessionSummaryState,
) -> None:
    task_uuid = get_session_id(process) or new_session_id()
    current_task = asyncio.current_task()
    current_task.set_name(task_uuid)
    log_extra = runtime.get_session_log_extra(process, instance, task_uuid)

    try:
        if process.command:
            command = process.command
            runtime.logger.info(
                "User input",
                extra=merge_log_extra(
                    log_extra,
                    details=encode_details(command),
                    interactive=False,
                    command_mode="non_interactive",
                ),
            )
            llm_response = await runtime.invoke_llm(
                instance,
                task_uuid,
                {
                    "messages": [HumanMessage(content=command)],
                    "username": process.get_extra_info("username"),
                    "interactive": False,
                    "protocol": instance.protocol,
                    "protocol_instance": instance.full_name,
                },
            )
            process.stdout.write(f"{llm_response.content}")
            runtime.logger.info(
                "LLM response",
                extra=merge_log_extra(
                    log_extra,
                    details=encode_details(llm_response.content),
                    interactive=False,
                    command_mode="non_interactive",
                ),
            )
            await runtime.summarize_session(
                summary_state,
                instance,
                task_uuid,
                username=process.get_extra_info("username"),
                interactive=True,
                log_extra=log_extra,
            )
            process.exit(0)
        else:
            llm_response = await runtime.invoke_llm(
                instance,
                task_uuid,
                {
                    "messages": [HumanMessage(content="")],
                    "username": process.get_extra_info("username"),
                    "interactive": True,
                    "protocol": instance.protocol,
                    "protocol_instance": instance.full_name,
                },
            )
            process.stdout.write(f"{llm_response.content}")
            runtime.logger.info(
                "LLM response",
                extra=merge_log_extra(
                    log_extra,
                    details=encode_details(llm_response.content),
                    interactive=True,
                    command_mode="interactive",
                ),
            )

            async for line in process.stdin:
                line = line.rstrip("\n")
                runtime.logger.info(
                    "User input",
                    extra=merge_log_extra(
                        log_extra,
                        details=encode_details(line),
                        interactive=True,
                        command_mode="interactive",
                    ),
                )

                llm_response = await runtime.invoke_llm(
                    instance,
                    task_uuid,
                    {
                        "messages": [HumanMessage(content=line)],
                        "username": process.get_extra_info("username"),
                        "interactive": True,
                        "protocol": instance.protocol,
                        "protocol_instance": instance.full_name,
                    },
                )
                if llm_response.content == "YYY-END-OF-SESSION-YYY":
                    await runtime.summarize_session(
                        summary_state,
                        instance,
                        task_uuid,
                        username=process.get_extra_info("username"),
                        interactive=True,
                        log_extra=log_extra,
                    )
                    process.exit(0)
                    return

                process.stdout.write(f"{llm_response.content}")
                runtime.logger.info(
                    "LLM response",
                    extra=merge_log_extra(
                        log_extra,
                        details=encode_details(llm_response.content),
                        interactive=True,
                        command_mode="interactive",
                    ),
                )

    except asyncssh.BreakReceived:
        pass
    finally:
        await runtime.summarize_session(
            summary_state,
            instance,
            task_uuid,
            username=process.get_extra_info("username"),
            interactive=True,
            log_extra=log_extra,
        )
        process.exit(0)


class SSHProtocolAdapter:
    name = "ssh"

    async def start_instance(
        self, runtime: DeceiveRuntime, instance: ProtocolInstanceConfig
    ):
        if not runtime.accounts:
            raise ValueError("No user accounts found in configuration file.")

        return await asyncssh.listen(
            host=instance.get("listen_host", ""),
            port=instance.getint("port", 8022),
            reuse_address=True,
            reuse_port=True,
            server_factory=lambda: MySSHServer(runtime, instance),
            server_host_keys=runtime.resolve_runtime_path(
                instance.get("host_priv_key", "ssh_host_key")
            ),
            process_factory=lambda process: handle_client(
                process, runtime, instance, SessionSummaryState()
            ),
            server_version=instance.get(
                "server_version_string", "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3"
            ),
        )
