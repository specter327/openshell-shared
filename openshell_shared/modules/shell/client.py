# shell/client.py

# =====================================================
# LIBRARY IMPORTS
# =====================================================

import os
import tty
import termios
import asyncio
import traceback

from .protocol import ShellProtocol
from .models import (
    ProtocolType,
    ProtocolStandard,
    ShellSignal
)


# =====================================================
# SHELL CLIENT
# =====================================================

class ShellClient:

    def __init__(
        self,
        communication_handler,
        auth_token: str,
        tunnel_token: str,
        session_token: str
    ):

        self._communication_handler = (
            communication_handler
        )

        self._auth_token = auth_token
        self._tunnel_token = tunnel_token
        self._session_token = session_token

        self._is_running = False

        self._shell_protocol = ShellProtocol(
            auth_token=self._auth_token,
            tunnel_token=self._tunnel_token,
            session_token=self._session_token
        )

        self._stdin_fd = (
            os.sys.stdin.fileno()
        )

        self._old_term = None

    # =================================================
    # START
    # =================================================

    async def start(self):

        self._is_running = True

        print(
            "[SHELL] Opening PTY..."
        )

        await (
            self._communication_handler
            .send_datapackage(
                self._shell_protocol.open()
            )
        )

        self._enable_raw_mode()

        try:

            receiver_task = (
                asyncio.create_task(
                    self._receiver_loop()
                )
            )

            sender_task = (
                asyncio.create_task(
                    self._sender_loop()
                )
            )

            done, pending = (
                await asyncio.wait(
                    [
                        receiver_task,
                        sender_task
                    ],
                    return_when=
                    asyncio.FIRST_COMPLETED
                )
            )

            for task in pending:

                task.cancel()

        finally:

            self._disable_raw_mode()

            try:

                await (
                    self._communication_handler
                    .send_datapackage(
                        self._shell_protocol.close()
                    )
                )

            except Exception:

                pass

            self._is_running = False

            print(
                "\n[SHELL] Closed"
            )

    # =================================================
    # RAW MODE
    # =================================================

    def _enable_raw_mode(self):

        self._old_term = (
            termios.tcgetattr(
                self._stdin_fd
            )
        )

        tty.setraw(
            self._stdin_fd
        )

    def _disable_raw_mode(self):

        if self._old_term:

            termios.tcsetattr(
                self._stdin_fd,
                termios.TCSADRAIN,
                self._old_term
            )

    # =================================================
    # RECEIVER
    # =================================================

    async def _receiver_loop(self):

        while self._is_running:

            try:

                packet = await (
                    self._communication_handler
                    .receive_datapackage()
                )

                if not isinstance(
                    packet,
                    dict
                ):
                    continue

                payload = packet.get(
                    "payload",
                    {}
                )

                if (
                    payload.get(
                        "protocol"
                    )
                    !=
                    ProtocolStandard
                    .SHELL
                    .value
                ):
                    continue

                if (
                    payload.get(
                        "protocol_type"
                    )
                    !=
                    ProtocolType
                    .SERVER
                    .value
                ):
                    continue

                event = payload.get(
                    "event"
                )

                # -------------------------
                # OUTPUT
                # -------------------------

                if event == "OUTPUT":

                    data = payload.get(
                        "data",
                        ""
                    )

                    if data:

                        print(
                            data,
                            end="",
                            flush=True
                        )

                    continue

                # -------------------------
                # EXIT
                # -------------------------

                if event == "EXIT":

                    code = payload.get(
                        "return_code",
                        0
                    )

                    print(
                        f"\n\r"
                        f"[REMOTE EXIT {code}]"
                    )

                    self.stop()

                    break

            except asyncio.CancelledError:

                break

            except Exception:

                print(
                    "\n[SHELL-CLIENT] "
                    "Receiver exception:"
                )

                traceback.print_exc()

                self.stop()

                break

    # =================================================
    # SENDER
    # =================================================

    async def _sender_loop(self):

        loop = (
            asyncio.get_running_loop()
        )

        while self._is_running:

            try:

                data = await (
                    loop.run_in_executor(
                        None,
                        os.read,
                        self._stdin_fd,
                        1024
                    )
                )

                if not data:
                    continue

                # -------------------------
                # CTRL+C
                # -------------------------

                if data == b"\x03":

                    await (
                        self._communication_handler
                        .send_datapackage(
                            self._shell_protocol.signal(
                                ShellSignal
                                .SIGINT
                                .value
                            )
                        )
                    )

                    continue

                # -------------------------
                # CTRL+D
                # -------------------------

                if data == b"\x04":

                    self.stop()

                    break

                # -------------------------
                # INPUT
                # -------------------------

                await (
                    self._communication_handler
                    .send_datapackage(
                        self._shell_protocol.input(
                            data.decode(
                                errors="ignore"
                            )
                        )
                    )
                )

            except asyncio.CancelledError:

                break

            except Exception:

                print(
                    "\n[SHELL-CLIENT] "
                    "Sender exception:"
                )

                traceback.print_exc()

                self.stop()

                break

    # =================================================
    # STOP
    # =================================================

    def stop(self):

        self._is_running = False

        return True