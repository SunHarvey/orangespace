from dataclasses import dataclass
import os
from pathlib import Path
from uuid import UUID


@dataclass(frozen=True)
class Settings:
    node_id: UUID
    data_root: Path
    database_url: str
    token_lifetime_seconds: int = 8 * 60 * 60
    max_upload_bytes: int = 1024 * 1024 * 1024
    login_attempts: int = 10
    login_window_seconds: int = 300
    tunnel_config: Path | None = None
    federation_config: Path | None = None
    deployment_mode: str | None = None

    def __post_init__(self) -> None:
        if self.deployment_mode is not None:
            if type(self.deployment_mode) is not str or self.deployment_mode != "managed-local":
                raise ValueError("invalid Node deployment mode")
            from .local_store import local_path, _verify_file
            # Reuse the adapter guards; never provision or repair runtime state.
            state_path = local_path(self.database_url)
            _verify_file(state_path)
            state_root = state_path.parent.resolve(strict=True)
            personal_root = self.data_root.resolve()
            if state_root.is_relative_to(personal_root) or personal_root.is_relative_to(state_root):
                raise ValueError("Node state and personal roots must be separate")
        if self.max_upload_bytes <= 0 or self.token_lifetime_seconds <= 0:
            raise ValueError("upload size and token lifetime must be positive")
        if self.login_attempts <= 0 or self.login_window_seconds <= 0:
            raise ValueError("login limits must be positive")
        if not self.data_root.is_absolute():
            raise ValueError("ORANGESPACE_DATA_ROOT must be absolute")

    @staticmethod
    def _database_url_from_file() -> str:
        from orangespace_common.database import load_database_url
        if "ORANGESPACE_DATABASE_URL" in os.environ:
            raise ValueError("database secrets in environment are not supported")
        return load_database_url(os.environ["ORANGESPACE_DATABASE_CONFIG"])

    @classmethod
    def from_env(cls) -> "Settings":
        # A stable explicit identity prevents accidentally treating two nodes as one.
        return cls(
            federation_config=Path(os.environ["ORANGESPACE_FEDERATION_CONFIG"]) if "ORANGESPACE_FEDERATION_CONFIG" in os.environ else None,
            tunnel_config=Path(os.environ["ORANGESPACE_TUNNEL_CONFIG"]) if os.environ.get("ORANGESPACE_TUNNEL_CONFIG") else None,
            node_id=UUID(os.environ["ORANGESPACE_NODE_ID"]),
            data_root=Path(os.environ.get("ORANGESPACE_DATA_ROOT", "/var/lib/orangespace/files")),
            database_url=cls._database_url_from_file(),
            token_lifetime_seconds=int(os.environ.get("ORANGESPACE_TOKEN_TTL", "28800")),
            max_upload_bytes=int(os.environ.get("ORANGESPACE_MAX_UPLOAD_BYTES", "1073741824")),
            login_attempts=int(os.environ.get("ORANGESPACE_LOGIN_ATTEMPTS", "10")),
            login_window_seconds=int(os.environ.get("ORANGESPACE_LOGIN_WINDOW", "300")),
        )
