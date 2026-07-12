from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class IdentityStoreError(Exception):
    """Identity storage error."""
    pass


class IdentityStore:
    """
    Generic JSON-based identity store.

    Responsibilities
    ----------------
    - Manage public/private identity files.
    - Read and write JSON documents.
    - Detect existence.
    - Detect validity.
    - Persist identities atomically.

    This class intentionally knows nothing about the
    structure of the identity itself.
    """

    PUBLIC_FILENAME = "public.json"
    PRIVATE_FILENAME = "private.json"

    # =====================================================
    # CONSTRUCTOR
    # =====================================================

    def __init__(
        self,
        root_path: Path,
        identity_name: str
    ) -> None:

        self._root = (
            Path(root_path)
            / "identity"
            / identity_name.lower()
        )

        self._root.mkdir(
            parents=True,
            exist_ok=True
        )

        self._public_path = (
            self._root /
            self.PUBLIC_FILENAME
        )

        self._private_path = (
            self._root /
            self.PRIVATE_FILENAME
        )

    # =====================================================
    # PROPERTIES
    # =====================================================

    @property
    def root(self) -> Path:
        return self._root

    @property
    def public_path(self) -> Path:
        return self._public_path

    @property
    def private_path(self) -> Path:
        return self._private_path

    # =====================================================
    # PRIVATE
    # =====================================================

    def _read(
        self,
        path: Path
    ) -> str:

        if not path.exists():
            raise IdentityStoreError(
                f"File not found: {path}"
            )

        return path.read_text(
            encoding="utf-8"
        )

    def _write(
        self,
        path: Path,
        content: str
    ) -> None:

        temporary = path.with_suffix(
            path.suffix + ".tmp"
        )

        with open(
            temporary,
            "w",
            encoding="utf-8"
        ) as file:

            file.write(content)
            file.flush()

        temporary.replace(path)

    def _read_json(
        self,
        path: Path
    ) -> dict[str, Any]:

        try:

            data = json.loads(
                self._read(path)
            )

        except FileNotFoundError as exc:
            raise IdentityStoreError(
                str(exc)
            ) from exc

        except json.JSONDecodeError as exc:
            raise IdentityStoreError(
                f"Invalid JSON: {path}"
            ) from exc

        if not isinstance(data, dict):

            raise IdentityStoreError(
                f"Identity document must be a JSON object: {path}"
            )

        if not data:

            raise IdentityStoreError(
                f"Identity document is empty: {path}"
            )

        return data

    def _write_json(
        self,
        path: Path,
        data: dict[str, Any]
    ) -> None:

        if not isinstance(data, dict):

            raise IdentityStoreError(
                "Identity must be a dictionary."
            )

        text = json.dumps(
            data,
            indent=4,
            ensure_ascii=False
        )

        self._write(
            path,
            text
        )

    # =====================================================
    # STATUS
    # =====================================================

    def exists(self) -> bool:
        """
        Returns True if both identity files exist.
        """

        return (
            self.public_path.exists()
            and
            self.private_path.exists()
        )

    def is_valid(self) -> bool:
        """
        Returns True if both files exist and contain
        valid, non-empty JSON objects.
        """

        try:

            self.load_public()
            self.load_private()

            return True

        except Exception:

            return False

    # =====================================================
    # LOAD
    # =====================================================

    def load_public(self) -> dict[str, Any]:

        return self._read_json(
            self.public_path
        )

    def load_private(self) -> dict[str, Any]:

        return self._read_json(
            self.private_path
        )

    def load(
        self
    ) -> tuple[
        dict[str, Any],
        dict[str, Any]
    ]:

        return (
            self.load_public(),
            self.load_private()
        )

    # =====================================================
    # SAVE
    # =====================================================

    def save_public(
        self,
        data: dict[str, Any]
    ) -> None:

        self._write_json(
            self.public_path,
            data
        )

    def save_private(
        self,
        data: dict[str, Any]
    ) -> None:

        self._write_json(
            self.private_path,
            data
        )

    def save(
        self,
        public: dict[str, Any],
        private: dict[str, Any]
    ) -> None:

        self.save_public(public)
        self.save_private(private)

    # =====================================================
    # DELETE
    # =====================================================

    def delete(self) -> None:

        if self.public_path.exists():
            self.public_path.unlink()

        if self.private_path.exists():
            self.private_path.unlink()

        try:
            self.root.rmdir()
        except OSError:
            pass