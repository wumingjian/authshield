from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv("AUTHSHIELD_DB", str(tmp_path / "authshield.db"))
    monkeypatch.chdir(tmp_path)
    from authshield.main import create_app

    with TestClient(create_app()) as test_client:
        yield test_client
