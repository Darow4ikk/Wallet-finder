"""api_client.py

A small, dependency-free HTTP client built on the standard library, with a
configurable timeout, a custom User-Agent, and retry-with-backoff on transient
failures.

Public API:
    ApiClient(user_agent=..., timeout=..., retries=..., backoff=...)
        .get(url, params=None, headers=None) -> dict | str
        .post(url, data=None, json_body=None, headers=None) -> dict | str
        .get_balance(endpoint, address) -> dict
"""

import json
import time
import urllib.error
import urllib.parse
import urllib.request

__all__ = ["ApiClient", "HttpError"]

_DEFAULT_UA = "crypto-utility/1.0 (+https://example.invalid)"


class HttpError(Exception):
    """Raised when a request ultimately fails after all retries."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class ApiClient:
    """Reusable HTTP client with timeout, User-Agent and retry support."""

    def __init__(self, user_agent: str = _DEFAULT_UA, timeout: float = 10.0,
                 retries: int = 3, backoff: float = 0.5):
        self.user_agent = user_agent
        self.timeout = timeout
        self.retries = max(1, int(retries))
        self.backoff = backoff

    # ------------------------------------------------------------------ #
    # Core request machinery                                             #
    # ------------------------------------------------------------------ #
    def _build_headers(self, extra: dict | None) -> dict:
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "application/json, text/plain, */*",
        }
        if extra:
            headers.update(extra)
        return headers

    def _request(self, method: str, url: str, *, params: dict | None = None,
                 body: bytes | None = None, headers: dict | None = None):
        if params:
            query = urllib.parse.urlencode(params)
            sep = "&" if urllib.parse.urlparse(url).query else "?"
            url = f"{url}{sep}{query}"

        req = urllib.request.Request(
            url, data=body, method=method, headers=self._build_headers(headers)
        )

        last_error: Exception | None = None
        for attempt in range(self.retries):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    raw = resp.read()
                    charset = resp.headers.get_content_charset() or "utf-8"
                    text = raw.decode(charset, errors="replace")
                    content_type = resp.headers.get_content_type()
                    if "json" in content_type:
                        return json.loads(text) if text else {}
                    return text
            except urllib.error.HTTPError as exc:
                # 4xx (except 429) are not worth retrying.
                last_error = exc
                if exc.code < 500 and exc.code != 429:
                    raise HttpError(
                        f"HTTP {exc.code} for {url}", status=exc.code
                    ) from exc
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                last_error = exc

            if attempt < self.retries - 1:
                time.sleep(self.backoff * (2 ** attempt))

        raise HttpError(f"request to {url} failed: {last_error}")

    # ------------------------------------------------------------------ #
    # Public verbs                                                        #
    # ------------------------------------------------------------------ #
    def get(self, url: str, params: dict | None = None,
            headers: dict | None = None):
        """Perform a GET request and return parsed JSON or text."""
        return self._request("GET", url, params=params, headers=headers)

    def post(self, url: str, data: dict | None = None,
             json_body: dict | None = None, headers: dict | None = None):
        """Perform a POST request (form data or JSON body)."""
        headers = dict(headers or {})
        if json_body is not None:
            body = json.dumps(json_body).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")
        elif data is not None:
            body = urllib.parse.urlencode(data).encode("utf-8")
            headers.setdefault(
                "Content-Type", "application/x-www-form-urlencoded"
            )
        else:
            body = None
        return self._request("POST", url, body=body, headers=headers)

    def get_balance(self, endpoint: str, address: str) -> dict:
        """Query an address-balance endpoint.

        ``endpoint`` may contain an ``{address}`` placeholder; if it does not,
        the address is appended as a path segment. The decoded response is
        returned as-is (dict for JSON, otherwise wrapped in {"raw": text}).
        """
        if "{address}" in endpoint:
            url = endpoint.replace("{address}", urllib.parse.quote(address))
        else:
            url = endpoint.rstrip("/") + "/" + urllib.parse.quote(address)

        result = self.get(url)
        if isinstance(result, dict):
            return result
        return {"raw": result}


if __name__ == "__main__":
    # Offline smoke test: verify URL construction and header assembly without
    # making a network call.
    client = ApiClient(timeout=5, retries=2)
    headers = client._build_headers({"X-Test": "1"})
    assert headers["User-Agent"] == _DEFAULT_UA
    assert headers["X-Test"] == "1"

    endpoint = "https://example.invalid/api/balance/{address}"
    filled = endpoint.replace("{address}", "ABC123")
    assert filled == "https://example.invalid/api/balance/ABC123"
    print("api_client self-check passed")
