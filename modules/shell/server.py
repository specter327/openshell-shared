# shell/server.py

# =====================================================
# LIBRARY IMPORTS
# =====================================================

import asyncio
import traceback

from .protocol import ShellProtocol
from .models import (
    ProtocolType,
    ProtocolStandard
)
from .session import ShellSession


# =====================================================
# SHELL SERVER
# =====================================================

class ShellServer:

    def __init__(
        self,
        communication_handler,
        auth_token: str,
        tunnel_token: str
    ):

        self._communication_handler = (
            communication_handler
        )

        self._auth_token = auth_token
        self._tunnel_token = tunnel_token

        self._is_running = False

        # -------------------------------------------------
        # SESSION REGISTRY
        # -------------------------------------------------

        self._sessions = {}

        # {
        #     session_token: {
        #         "session": ShellSession,
        #         "reader": asyncio.Task
        #     }
        # }

        # -------------------------------------------------
        # PROTOCOL
        # -------------------------------------------------

        self._shell_protocol = ShellProtocol(
            auth_token=self._auth_token,
            tunnel_token=self._tunnel_token,
            session_token=""
        )

    # =================================================
    # SESSION READER
    # =================================================

    async def _session_reader(
        self,
        session_token: str,
        session: ShellSession
    ):

        print(
            f"[SHELL-SERVER] "
            f"Reader started: "
            f"{session_token}"
        )

        try:

            while (
                self._is_running
                and
                session.is_alive()
            ):

                output = await (
                    session.read_available()
                )

                if output:

                    packet = (
                        self._shell_protocol.output(
                            session_token=session_token,
                            data=output
                        )
                    )

                    await (
                        self._communication_handler
                        .send_datapackage(
                            packet
                        )
                    )

                await asyncio.sleep(
                    0.01
                )

            # -----------------------------------------
            # PROCESS EXITED
            # -----------------------------------------

            exit_code = (
                session.return_code()
            )

            packet = (
                self._shell_protocol.exit(
                    session_token=session_token,
                    return_code=(
                        exit_code
                        if exit_code is not None
                        else -1
                    )
                )
            )

            await (
                self._communication_handler
                .send_datapackage(
                    packet
                )
            )

        except asyncio.CancelledError:

            pass

        except Exception:

            print(
                "[SHELL-SERVER] "
                "Reader exception:"
            )

            traceback.print_exc()

        finally:

            print(
                f"[SHELL-SERVER] "
                f"Reader stopped: "
                f"{session_token}"
            )

    # =================================================
    # SESSION RESOLUTION
    # =================================================

    async def _get_session(
        self,
        session_token: str
    ) -> ShellSession:

        entry = self._sessions.get(
            session_token
        )

        # ---------------------------------------------
        # CREATE
        # ---------------------------------------------

        if entry is None:

            print(
                f"[SHELL-SERVER] "
                f"Creating session: "
                f"{session_token}"
            )

            session = ShellSession(
                session_token=session_token
            )

            await session.start()

            reader_task = (
                asyncio.create_task(
                    self._session_reader(
                        session_token,
                        session
                    )
                )
            )

            self._sessions[
                session_token
            ] = {
                "session": session,
                "reader": reader_task
            }

            return session

        session = entry["session"]

        # ---------------------------------------------
        # RECREATE DEAD
        # ---------------------------------------------

        if not session.is_alive():

            print(
                f"[SHELL-SERVER] "
                f"Recreating session: "
                f"{session_token}"
            )

            try:

                entry[
                    "reader"
                ].cancel()

            except Exception:

                pass

            try:

                await session.close()

            except Exception:

                pass

            session = ShellSession(
                session_token=session_token
            )

            await session.start()

            reader_task = (
                asyncio.create_task(
                    self._session_reader(
                        session_token,
                        session
                    )
                )
            )

            self._sessions[
                session_token
            ] = {
                "session": session,
                "reader": reader_task
            }

        return session

    # =================================================
    # CLOSE SESSION
    # =================================================

    async def _close_session(
        self,
        session_token: str
    ):

        entry = self._sessions.pop(
            session_token,
            None
        )

        if entry is None:
            return

        try:

            entry[
                "reader"
            ].cancel()

        except Exception:

            pass

        try:

            await (
                entry[
                    "session"
                ].close()
            )

        except Exception:

            traceback.print_exc()

    # =================================================
    # START
    # =================================================

    async def start(self):

        self._is_running = True

        print(
            "[SHELL-SERVER] Started"
        )

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

                session_token = packet.get(
                    "session_token"
                )

                if not session_token:
                    continue

                # -------------------------------------
                # PROTOCOL VALIDATION
                # -------------------------------------

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
                    .CLIENT
                    .value
                ):
                    continue

                event = payload.get(
                    "event"
                )

                # -------------------------------------
                # OPEN
                # -------------------------------------

                if event == "OPEN":

                    await self._get_session(
                        session_token
                    )

                    continue

                # -------------------------------------
                # INPUT
                # -------------------------------------

                if event == "INPUT":

                    session = await (
                        self._get_session(
                            session_token
                        )
                    )

                    await (
                        session.write(
                            payload.get(
                                "data",
                                ""
                            )
                        )
                    )

                    continue

                # -------------------------------------
                # RESIZE
                # -------------------------------------

                if event == "RESIZE":

                    session = await (
                        self._get_session(
                            session_token
                        )
                    )

                    await (
                        session.resize(
                            payload.get(
                                "rows",
                                24
                            ),
                            payload.get(
                                "cols",
                                80
                            )
                        )
                    )

                    continue

                # -------------------------------------
                # SIGNAL
                # -------------------------------------

                if event == "SIGNAL":

                    session = await (
                        self._get_session(
                            session_token
                        )
                    )

                    await (
                        session.signal(
                            payload.get(
                                "signal"
                            )
                        )
                    )

                    continue

                # -------------------------------------
                # CLOSE
                # -------------------------------------

                if event == "CLOSE":

                    await (
                        self._close_session(
                            session_token
                        )
                    )

                    continue

            except asyncio.CancelledError:

                break

            except Exception:

                print(
                    "[SHELL-SERVER] "
                    "Captured exception:"
                )

                traceback.print_exc()

        # =================================================
        # CLEANUP
        # =================================================

        print(
            "[SHELL-SERVER] "
            "Closing sessions..."
        )

        for session_token in list(
            self._sessions.keys()
        ):

            try:

                await (
                    self._close_session(
                        session_token
                    )
                )

            except Exception:

                traceback.print_exc()

        self._sessions.clear()

        print(
            "[SHELL-SERVER] Stopped"
        )