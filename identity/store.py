# shared/identity/store.py

import json
from pathlib import Path
from typing import Any, Dict, Optional
import os


class IdentityStoreError(Exception):
    pass


class IdentityStore:
    """
    Generic filesystem-based identity vault.

    Responsibilities:
    - persist identity blobs (public/private)
    - load identity blobs
    - export safe/public view
    - ensure structural consistency

    It does NOT:
    - generate identities
    - perform cryptographic operations
    - enforce business rules
    """

    def __init__(self, base_path: Path, namespace: str):
        """
        Args:
            base_path: root storage path (e.g. storage/)
            namespace: entity namespace (ra, osam, agent, proxy, etc.)
        """

        self._base = Path(base_path)
        self._namespace = namespace

        self._root = self._base / namespace / "identity"

        self._public_path = self._root / "profile.public.json"
        self._private_path = self._root / "profile.private.json"
        self._meta_path = self._root / "metadata.json"

        self._ensure_structure()

    # ---------------------------------------------------------
    # INTERNAL
    # ---------------------------------------------------------
    def _ensure_structure(self):
        self._root.mkdir(parents=True, exist_ok=True)

    def _write_json(self, path: Path, data: Dict[str, Any]):
        tmp_path = path.with_suffix(".tmp")

        with open(tmp_path, "w") as f:
            json.dump(data, f, indent=4)

        tmp_path.replace(path)

    def _read_json(self, path: Path) -> Dict[str, Any]:
        if not path.exists():
            raise IdentityStoreError(f"Missing identity file: {path}")

        with open(path, "r") as f:
            return json.load(f)

    # ---------------------------------------------------------
    # LIFECYCLE
    # ---------------------------------------------------------
    def exists(self) -> bool:
        print("CWD:", os.getcwd())
        print("PUBLIC:", self._public_path)
        print("PRIVATE:", self._private_path)

        print("PUBLIC EXISTS:", self._public_path.exists())
        print("PRIVATE EXISTS:", self._private_path.exists())

        return self._public_path.exists() and self._private_path.exists()

    def save(
        self,
        public_profile: Dict[str, Any],
        private_profile: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Persist identity bundle atomically.
        """

        self._write_json(self._public_path, public_profile)
        self._write_json(self._private_path, private_profile)

        if metadata is not None:
            self._write_json(self._meta_path, metadata)

    def load(self) -> Dict[str, Any]:
        """
        Load full identity bundle.
        """

        return {
            "public": self._read_json(self._public_path),
            "private": self._read_json(self._private_path),
            "metadata": (
                self._read_json(self._meta_path)
                if self._meta_path.exists()
                else None
            )
        }

    def load_public(self) -> Dict[str, Any]:
        return self._read_json(self._public_path)

    def load_private(self) -> Dict[str, Any]:
        return self._read_json(self._private_path)

    # ---------------------------------------------------------
    # EXPORT (SAFE)
    # ---------------------------------------------------------
    def export_public(self, export_path: Path) -> Path:
        """
        Export only public identity (safe for sharing).
        """

        data = self.load_public()

        export_path = Path(export_path)
        export_path.mkdir(parents=True, exist_ok=True)

        file_path = export_path / f"{self._namespace}.identity.public.json"

        with open(file_path, "w") as f:
            json.dump(data, f, indent=4)

        return file_path

    # ---------------------------------------------------------
    # DELETE (optional, destructive)
    # ---------------------------------------------------------
    def delete(self) -> None:
        """
        Remove identity completely.
        """

        if self._root.exists():
            for file in self._root.glob("*"):
                file.unlink()

            self._root.rmdir()