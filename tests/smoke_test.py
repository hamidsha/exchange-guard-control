from __future__ import annotations

import re

from fastapi.testclient import TestClient

from app.main import app


def main() -> int:
    pages = (
        "/",
        "/outbound",
        "/spoofing",
        "/candidates",
        "/reputation",
        "/mailboxes",
        "/blocks",
        "/allowlist",
        "/commands",
        "/nodes",
        "/audit",
        "/settings",
    )
    with TestClient(app) as client:
        health = client.get("/healthz")
        assert health.status_code == 200
        assert health.json() == {"status": "ok"}

        login_page = client.get("/login")
        assert login_page.status_code == 200
        csrf_match = re.search(r'name="csrf" value="([^"]+)"', login_page.text)
        assert csrf_match is not None

        login = client.post(
            "/login",
            data={
                "username": "smoke-admin",
                "password": "smoke-password",
                "csrf": csrf_match.group(1),
            },
            follow_redirects=False,
        )
        assert login.status_code == 303
        assert login.headers["location"] == "/"

        for path in pages:
            response = client.get(path)
            assert response.status_code == 200, (path, response.text[:1000])

        assigned = client.get("/mailboxes?policy=__assigned__")
        assert assigned.status_code == 200
        assert "Explicit policy assignments" in assigned.text

        spoofing = client.get("/spoofing")
        assert "Automatic enforcement is active" not in spoofing.text

    print("Exchange Guard empty-state smoke test: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

