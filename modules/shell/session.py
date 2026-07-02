# shell/session.py

# =====================================================
# LIBRARY IMPORTS
# =====================================================

import os
import pty
import fcntl
import signal
import struct
import termios
import asyncio
import subprocess


# =====================================================
# SHELL SESSION
# =====================================================

class ShellSession:

    def __init__(
        self,
        session_token: str
    ):

        self.session_token = (
            session_token
        )

        self.process = None

        self.master_fd = None
        self.slave_fd = None

        self._lock = asyncio.Lock()

    # =================================================
    # START
    # =================================================

    async def start(self):

        if self.process is not None:
            return

        self.master_fd, self.slave_fd = (
            pty.openpty()
        )

        self.process = subprocess.Popen(
            [
                "/bin/bash",
                "-i"
            ],
            stdin=self.slave_fd,
            stdout=self.slave_fd,
            stderr=self.slave_fd,
            start_new_session=True,
            close_fds=True
        )

        os.set_blocking(
            self.master_fd,
            False
        )

    # =================================================
    # WRITE
    # =================================================

    async def write(
        self,
        data: str
    ):

        async with self._lock:

            if self.process is None:

                await self.start()

            if isinstance(
                data,
                str
            ):

                data = data.encode()

            os.write(
                self.master_fd,
                data
            )

    # =================================================
    # READ
    # =================================================

    async def read(
        self,
        max_bytes: int = 65536
    ) -> str:

        if self.process is None:
            return ""

        try:

            data = os.read(
                self.master_fd,
                max_bytes
            )

            return data.decode(
                errors="ignore"
            )

        except BlockingIOError:

            return ""

        except OSError:

            return ""

    # =================================================
    # READ AVAILABLE
    # =================================================

    async def read_available(
        self,
        chunk_size: int = 65536
    ) -> str:

        output = []

        while True:

            try:

                chunk = os.read(
                    self.master_fd,
                    chunk_size
                )

                if not chunk:
                    break

                output.append(
                    chunk.decode(
                        errors="ignore"
                    )
                )

            except BlockingIOError:

                break

            except OSError:

                break

        return "".join(
            output
        )

    # =================================================
    # RESIZE
    # =================================================

    async def resize(
        self,
        rows: int,
        cols: int
    ):

        if self.master_fd is None:
            return

        winsize = struct.pack(
            "HHHH",
            rows,
            cols,
            0,
            0
        )

        fcntl.ioctl(
            self.master_fd,
            termios.TIOCSWINSZ,
            winsize
        )

    # =================================================
    # SIGNAL
    # =================================================

    async def signal(
        self,
        signal_name: str
    ):

        if self.process is None:
            return

        sig = getattr(
            signal,
            signal_name,
            None
        )

        if sig is None:
            return

        try:

            os.killpg(
                self.process.pid,
                sig
            )

        except Exception:

            pass

    # =================================================
    # PID
    # =================================================

    @property
    def pid(
        self
    ):

        if self.process is None:
            return None

        return (
            self.process.pid
        )

    # =================================================
    # IS ALIVE
    # =================================================

    def is_alive(
        self
    ) -> bool:

        if self.process is None:
            return False

        return (
            self.process.poll()
            is None
        )

    # =================================================
    # RETURN CODE
    # =================================================

    def return_code(
        self
    ):

        if self.process is None:
            return None

        return (
            self.process.poll()
        )

    # =================================================
    # CLOSE
    # =================================================

    async def close(self):

        if self.process is None:
            return

        try:

            os.killpg(
                self.process.pid,
                signal.SIGTERM
            )

        except Exception:

            pass

        try:

            await asyncio.wait_for(
                asyncio.to_thread(
                    self.process.wait
                ),
                timeout=3
            )

        except asyncio.TimeoutError:

            try:

                os.killpg(
                    self.process.pid,
                    signal.SIGKILL
                )

            except Exception:

                pass

        try:

            os.close(
                self.master_fd
            )

        except Exception:

            pass

        try:

            os.close(
                self.slave_fd
            )

        except Exception:

            pass

        self.process = None

        self.master_fd = None
        self.slave_fd = None