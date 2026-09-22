import os
import re
import base64
import time
import uuid
import hmac
import hashlib
import json
import logging
import tempfile
import threading
from pathlib import PurePosixPath
from typing import Annotated, Any, Optional

import httpx
from pydantic import Field
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

SITE_ID = os.environ.get("YALTA_SITE_ID", "yalta-main").strip()
SITE_URL = os.environ.get("YALTA_SITE_URL", "https://yamebel.pro").rstrip("/")
SHARED_SECRET = os.environ.get("YALTA_SHARED_SECRET", "")
REQUEST_TIMEOUT = float(os.environ.get("YMB_REQUEST_TIMEOUT", "20"))
PORT = int(os.environ.get("PORT", "10000"))

YANDEX_MARKETING_CLIENT_ID = os.environ.get("YANDEX_MARKETING_CLIENT_ID", "").strip()
YANDEX_MARKETING_OAUTH_TOKEN = os.environ.get("YANDEX_MARKETING_OAUTH_TOKEN", "").strip()
YANDEX_DIRECT_CLIENT_LOGIN = os.environ.get("YANDEX_DIRECT_CLIENT_LOGIN", "").strip()

METRIKA_BASE = "https://api-metrika.yandex.net"
DIRECT_BASE = "https://api.direct.yandex.com/json/v5"
DIRECT_REPORTS_URL = "https://api.direct.yandex.com/json/v5/reports"

# Marketing writes are intentionally two-step. Preview creates an immutable,
# short-lived in-memory plan; apply requires the exact plan id + confirmation
# token. Render restart invalidates pending plans by design.
MARKETING_PLAN_TTL_SECONDS = int(os.environ.get("YMB_MARKETING_PLAN_TTL_SECONDS", "900"))
MARKETING_PLAN_HISTORY_SECONDS = int(os.environ.get("YMB_MARKETING_PLAN_HISTORY_SECONDS", "86400"))
MARKETING_PLAN_STORE_PATH = os.environ.get(
    "YMB_MARKETING_PLAN_STORE_PATH",
    os.path.join(tempfile.gettempdir(), "ya_mebel_marketing_plans.json"),
)
_MARKETING_PLAN_LOCK = threading.RLock()

if not SHARED_SECRET:
    raise RuntimeError("YALTA_SHARED_SECRET is not configured.")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("ya-mebel-mcp-gateway-yalta")

mcp = FastMCP(
    "Я Мебель WordPress Ялта",
    stateless_http=True,
    json_response=True,
    host="0.0.0.0",
    port=PORT,
)

NS = "/ya-mebel-bridge/v1"

ThemeRelativePath = Annotated[
    str,
    Field(
        min_length=1,
        max_length=240,
        description=(
            "Relative path of an existing text/source file inside the active or parent "
            "WordPress theme, for example 'template-o-nas.php' or 'assets/css/main.css'. "
            "Absolute paths, '..' traversal, backslashes, NUL bytes, WordPress secrets, "
            "and files outside the allowed theme roots are not permitted."
        ),
    ),
]

_ALLOWED_THEME_TEXT_EXTENSIONS = {
    ".php", ".css", ".js", ".json", ".txt", ".md", ".xml", ".svg",
}
_BLOCKED_THEME_BASENAMES = {
    "wp-config.php",
    ".env",
    ".htaccess",
    "php.ini",
    "user.ini",
    # This site's functions.php currently contains hard-coded credentials/tokens.
    # Block it from MCP reads until those secrets have been moved and rotated.
    "functions.php",
}

# Keep each MCP result comfortably below large-tool-response limits.
# WordPress may return up to 1 MiB to the gateway; the gateway exposes it to the
# MCP client in explicit, lossless line windows instead of silently truncating.
DEFAULT_READ_MAX_LINES = 5000
MAX_READ_MAX_LINES = 5000
MAX_READ_CHUNK_BYTES = 750 * 1024


def _validate_theme_relative_path(path: str) -> str:
    """Defense-in-depth validation before the WordPress REST request."""
    candidate = path.strip()

    if not candidate:
        raise ValueError("Theme file path must not be empty.")
    if "\x00" in candidate:
        raise ValueError("NUL bytes are not allowed in theme file paths.")
    if "\\" in candidate:
        raise ValueError("Backslashes are not allowed; use a POSIX-style relative path.")
    if candidate.startswith("/"):
        raise ValueError("Absolute paths are not allowed.")

    posix_path = PurePosixPath(candidate)
    if posix_path.is_absolute() or ".." in posix_path.parts:
        raise ValueError("Path traversal is not allowed.")

    basename = posix_path.name.lower()
    if basename in _BLOCKED_THEME_BASENAMES or basename.startswith(".env"):
        raise ValueError("This file is not readable through the theme-file tool.")

    suffix = posix_path.suffix.lower()
    if suffix not in _ALLOWED_THEME_TEXT_EXTENSIONS:
        raise ValueError(
            "Only allow-listed text/source file types from the theme may be read."
        )

    return posix_path.as_posix()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _validate_sha256_hex(value: str) -> str:
    """Normalize and validate an externally supplied SHA-256 digest."""
    candidate = value.strip().lower()
    if len(candidate) != 64 or any(ch not in "0123456789abcdef" for ch in candidate):
        raise ValueError("expected_sha256 must be exactly 64 hexadecimal characters.")
    return candidate


def _bounded_text_result(
    data: dict[str, Any],
    *,
    start_line: int = 1,
    max_lines: int = DEFAULT_READ_MAX_LINES,
) -> dict[str, Any]:
    """Return a lossless, byte-bounded line window from a theme-file response."""
    content = data.get("content")
    if not isinstance(content, str):
        raise RuntimeError("WordPress theme-file response does not contain text content.")

    if start_line < 1:
        raise ValueError("start_line must be >= 1.")
    if max_lines < 1 or max_lines > MAX_READ_MAX_LINES:
        raise ValueError(f"max_lines must be between 1 and {MAX_READ_MAX_LINES}.")

    raw = content.encode("utf-8")
    declared_size = data.get("size")
    if not isinstance(declared_size, int):
        declared_size = len(raw)
    if declared_size != len(raw):
        raise RuntimeError(
            f"WordPress size mismatch: endpoint declared {declared_size} bytes, "
            f"gateway decoded {len(raw)} UTF-8 bytes."
        )

    declared_sha256 = str(data.get("sha256") or "").lower()
    actual_sha256 = _sha256_bytes(raw)
    if declared_sha256 and not hmac.compare_digest(declared_sha256, actual_sha256):
        raise RuntimeError("WordPress SHA-256 mismatch while reading theme file.")

    # keepends=True guarantees that concatenating sequential chunks reproduces
    # the exact UTF-8 source byte-for-byte. The MCP-facing chunk is capped by
    # both line count and bytes, so a large source cannot overflow a tool result.
    lines = content.splitlines(keepends=True)
    total_lines = len(lines)
    if total_lines == 0:
        if start_line != 1:
            raise ValueError("start_line is beyond the end of the file.")
        chunk = ""
        end_line = 0
        returned_bytes = 0
        has_more = False
        next_start_line = None
    else:
        if start_line > total_lines:
            raise ValueError(
                f"start_line {start_line} is beyond total_lines {total_lines}."
            )
        start_index = start_line - 1
        selected: list[str] = []
        returned_bytes = 0
        end_index = start_index
        hard_end = min(start_index + max_lines, total_lines)
        for idx in range(start_index, hard_end):
            line = lines[idx]
            line_bytes = len(line.encode("utf-8"))
            if line_bytes > MAX_READ_CHUNK_BYTES:
                raise RuntimeError(
                    f"Source line {idx + 1} is {line_bytes} bytes, exceeding the "
                    f"{MAX_READ_CHUNK_BYTES}-byte per-result safety cap. "
                    "Use a byte-range reader for this exceptional file."
                )
            if selected and returned_bytes + line_bytes > MAX_READ_CHUNK_BYTES:
                break
            selected.append(line)
            returned_bytes += line_bytes
            end_index = idx + 1
        chunk = "".join(selected)
        end_line = end_index
        has_more = end_index < total_lines
        next_start_line = end_index + 1 if has_more else None

    return {
        "ok": bool(data.get("ok", True)),
        "site_id": data.get("site_id", SITE_ID),
        "warnings": data.get("warnings", []),
        "path": data.get("path"),
        "sha256": actual_sha256,
        "size": declared_size,
        "encoding": "utf-8",
        "total_lines": total_lines,
        "start_line": start_line,
        "end_line": end_line,
        "returned_bytes": returned_bytes,
        "content": chunk,
        "has_more": has_more,
        "next_start_line": next_start_line,
    }


def _signed_headers(method: str, route: str, body: bytes = b"") -> dict[str, str]:
    timestamp = str(int(time.time()))
    nonce = uuid.uuid4().hex
    canonical = "\n".join([
        method.upper(),
        route,
        timestamp,
        nonce,
        _sha256_bytes(body),
    ])
    signature = hmac.new(
        SHARED_SECRET.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return {
        "X-YMB-Site": SITE_ID,
        "X-YMB-Timestamp": timestamp,
        "X-YMB-Nonce": nonce,
        "X-YMB-Signature": signature,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def _safe_response_text(response: httpx.Response, limit: int = 4000) -> str:
    try:
        text = response.text
    except Exception:
        return "<unable to decode response body>"
    if len(text) > limit:
        return text[:limit] + "...<truncated>"
    return text


async def _wp(
    method: str,
    route: str,
    *,
    params: Optional[dict[str, Any]] = None,
    payload: Optional[dict[str, Any]] = None,
    signed: bool = True,
) -> dict[str, Any]:
    method = method.upper()
    body = b""
    if payload is not None:
        body = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

    headers = {"Accept": "application/json"}
    if signed:
        headers = _signed_headers(method, route, body)
    elif payload is not None:
        headers["Content-Type"] = "application/json"

    url = f"{SITE_URL}/wp-json{route}"

    try:
        async with httpx.AsyncClient(
            timeout=REQUEST_TIMEOUT,
            follow_redirects=True,
        ) as client:
            response = await client.request(
                method,
                url,
                params=params,
                content=body if payload is not None else None,
                headers=headers,
            )
    except httpx.TimeoutException as exc:
        logger.exception(
            "Timeout calling WordPress: method=%s route=%s timeout=%s",
            method,
            route,
            REQUEST_TIMEOUT,
        )
        raise RuntimeError(
            f"WordPress request timed out after {REQUEST_TIMEOUT}s: {method} {route}"
        ) from exc
    except httpx.HTTPError as exc:
        logger.exception(
            "HTTP transport error calling WordPress: method=%s route=%s",
            method,
            route,
        )
        raise RuntimeError(
            f"WordPress transport error: {method} {route}: {exc}"
        ) from exc

    if response.status_code >= 400:
        response_text = _safe_response_text(response)
        logger.error(
            "WordPress returned HTTP %s: method=%s route=%s body=%s",
            response.status_code,
            method,
            route,
            response_text,
        )
        raise RuntimeError(
            f"WordPress returned HTTP {response.status_code} for {method} {route}: "
            f"{response_text}"
        )

    try:
        data = response.json()
    except ValueError as exc:
        response_text = _safe_response_text(response)
        logger.error(
            "WordPress returned invalid JSON: method=%s route=%s status=%s body=%s",
            method,
            route,
            response.status_code,
            response_text,
        )
        raise RuntimeError(
            f"WordPress returned invalid JSON for {method} {route}: {response_text}"
        ) from exc

    return {
        "status_code": response.status_code,
        "data": data,
    }


def _marketing_auth_headers() -> dict[str, str]:
    if not YANDEX_MARKETING_OAUTH_TOKEN:
        raise RuntimeError("YANDEX_MARKETING_OAUTH_TOKEN is not configured.")
    return {
        "Authorization": f"OAuth {YANDEX_MARKETING_OAUTH_TOKEN}",
        "Accept": "application/json",
    }


def _direct_auth_headers() -> dict[str, str]:
    if not YANDEX_MARKETING_OAUTH_TOKEN:
        raise RuntimeError("YANDEX_MARKETING_OAUTH_TOKEN is not configured.")
    return {
        "Authorization": f"Bearer {YANDEX_MARKETING_OAUTH_TOKEN}",
        "Accept": "application/json",
    }


def _direct_response_meta(response: httpx.Response) -> dict[str, Any]:
    """Safe Direct diagnostics. Never includes auth/request payload secrets."""
    return {
        "http_status": response.status_code,
        "request_id": response.headers.get("RequestId"),
        "units": response.headers.get("Units"),
        "units_used_login": response.headers.get("Units-Used-Login"),
    }


def _parse_direct_json(response: httpx.Response, *, operation: str) -> dict[str, Any]:
    response_text = _safe_response_text(response, limit=12000)
    meta = _direct_response_meta(response)
    if response.status_code >= 400:
        raise RuntimeError(
            f"Yandex Direct HTTP error during {operation}: {meta}; body={response_text}"
        )
    try:
        data = response.json()
    except ValueError as exc:
        raise RuntimeError(
            f"Yandex Direct returned non-JSON during {operation}: {meta}; body={response_text}"
        ) from exc
    if not isinstance(data, dict):
        raise RuntimeError(
            f"Yandex Direct returned unexpected JSON during {operation}: {meta}; body={response_text}"
        )
    if data.get("error"):
        raise RuntimeError(
            f"Yandex Direct API error during {operation}: {meta}; error={data['error']}"
        )
    return data


def _direct_action_issues(data: dict[str, Any]) -> dict[str, Any]:
    """Collect per-object Errors/Warnings from AddResults/UpdateResults/etc."""
    result = data.get("result")
    errors: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    if isinstance(result, dict):
        for result_key, value in result.items():
            if not isinstance(value, list):
                continue
            for index, item in enumerate(value):
                if not isinstance(item, dict):
                    continue
                if item.get("Errors"):
                    errors.append({"result_key": result_key, "index": index, "errors": item["Errors"]})
                if item.get("Warnings"):
                    warnings.append({"result_key": result_key, "index": index, "warnings": item["Warnings"]})
    return {"errors": errors, "warnings": warnings}


def _clean_api_path(path: str) -> str:
    candidate = str(path or "").strip()
    if not candidate.startswith("/"):
        candidate = "/" + candidate
    if "://" in candidate or "\\" in candidate or "\x00" in candidate:
        raise ValueError("Only a relative Yandex API path is allowed.")
    if ".." in PurePosixPath(candidate).parts:
        raise ValueError("Path traversal is not allowed.")
    return candidate


async def _yandex_http(
    method: str,
    url: str,
    *,
    params: Optional[dict[str, Any]] = None,
    payload: Optional[Any] = None,
    content: Optional[bytes] = None,
    content_type: Optional[str] = None,
) -> Any:
    headers = _marketing_auth_headers()
    if content_type:
        headers["Content-Type"] = content_type
    elif payload is not None:
        headers["Content-Type"] = "application/json"

    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=True) as client:
            response = await client.request(
                method.upper(),
                url,
                params=params,
                json=payload if content is None else None,
                content=content,
                headers=headers,
            )
    except httpx.TimeoutException as exc:
        raise RuntimeError(f"Yandex API timeout after {REQUEST_TIMEOUT}s.") from exc
    except httpx.HTTPError as exc:
        raise RuntimeError(f"Yandex API transport error: {exc}") from exc

    if response.status_code >= 400:
        raise RuntimeError(
            f"Yandex API returned HTTP {response.status_code}: {_safe_response_text(response)}"
        )

    ctype = response.headers.get("content-type", "")
    if "json" in ctype:
        return response.json()
    return {
        "status_code": response.status_code,
        "content_type": ctype,
        "text": response.text,
        "headers": {
            k: v for k, v in response.headers.items()
            if k.lower().startswith("reports-") or k.lower() in {"retry-in"}
        },
    }



def _load_marketing_plan_store() -> dict[str, dict[str, Any]]:
    """Load durable short-lived marketing plans from a local atomic JSON store."""
    with _MARKETING_PLAN_LOCK:
        try:
            with open(MARKETING_PLAN_STORE_PATH, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            if isinstance(raw, dict):
                return {str(k): v for k, v in raw.items() if isinstance(v, dict)}
        except FileNotFoundError:
            pass
        except Exception as exc:
            logger.error("Marketing plan store read failed: %s", exc)
        return {}


def _save_marketing_plan_store(store: dict[str, dict[str, Any]]) -> None:
    """Atomic replace so preview/apply cannot observe a partially written store."""
    with _MARKETING_PLAN_LOCK:
        directory = os.path.dirname(MARKETING_PLAN_STORE_PATH) or "."
        os.makedirs(directory, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix=".ymb-plans-", suffix=".json", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(store, fh, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, MARKETING_PLAN_STORE_PATH)
        finally:
            try:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
            except OSError:
                pass


def _marketing_audit_event(plan: dict[str, Any], event: str, **data: Any) -> None:
    """Append safe diagnostics to the plan record; never store OAuth secrets/tokens."""
    events = plan.setdefault("events", [])
    events.append({
        "time": time.time(),
        "event": event,
        **data,
    })
    # Bound history per plan.
    if len(events) > 50:
        del events[:-50]


def _prune_marketing_plans(store: Optional[dict[str, dict[str, Any]]] = None) -> dict[str, dict[str, Any]]:
    now = time.time()
    current = store if store is not None else _load_marketing_plan_store()
    changed = False
    for plan_id, plan in list(current.items()):
        terminal_at = float(plan.get("terminal_at") or 0)
        expires_at = float(plan.get("expires_at") or 0)
        if terminal_at and terminal_at + MARKETING_PLAN_HISTORY_SECONDS <= now:
            current.pop(plan_id, None)
            changed = True
        elif not terminal_at and expires_at + MARKETING_PLAN_HISTORY_SECONDS <= now:
            current.pop(plan_id, None)
            changed = True
    if changed:
        _save_marketing_plan_store(current)
    return current


def _make_marketing_plan(
    api: str,
    method: str,
    target: str,
    *,
    params: Optional[dict[str, Any]] = None,
    payload: Optional[Any] = None,
    content_base64: Optional[str] = None,
    content_type: Optional[str] = None,
) -> dict[str, Any]:
    method = method.upper()
    if method not in {"POST", "PUT", "DELETE"}:
        raise ValueError("Marketing write plan supports POST, PUT or DELETE only.")

    plan_id = uuid.uuid4().hex
    confirmation_token = uuid.uuid4().hex
    now = time.time()
    canonical = json.dumps(
        {
            "api": api,
            "method": method,
            "target": target,
            "params": params or {},
            "payload": payload,
            "content_base64": content_base64,
            "content_type": content_type,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    plan = {
        "plan_id": plan_id,
        "confirmation_token_hash": _sha256_bytes(confirmation_token.encode("utf-8")),
        "api": api,
        "method": method,
        "target": target,
        "params": params or {},
        "payload": payload,
        "content_base64": content_base64,
        "content_type": content_type,
        "created_at": now,
        "expires_at": now + MARKETING_PLAN_TTL_SECONDS,
        "sha256": _sha256_bytes(canonical.encode("utf-8")),
        "state": "pending",
        "used": False,
        "terminal_at": None,
        "result_summary": None,
        "events": [],
    }
    _marketing_audit_event(plan, "preview_created")
    with _MARKETING_PLAN_LOCK:
        store = _prune_marketing_plans(_load_marketing_plan_store())
        store[plan_id] = plan
        _save_marketing_plan_store(store)

    return {
        "ok": True,
        "preview_only": True,
        "plan_id": plan_id,
        "confirmation_token": confirmation_token,
        "expires_in_seconds": MARKETING_PLAN_TTL_SECONDS,
        "operation_sha256": plan["sha256"],
        "api": api,
        "method": method,
        "target": target,
        "params": params or {},
        "payload": payload,
        "content_type": content_type,
        "requires_explicit_user_confirmation": True,
        "plan_store": "durable_atomic_file",
    }


async def _execute_marketing_plan(plan: dict[str, Any]) -> Any:
    api = plan["api"]
    method = plan["method"]
    params = plan.get("params") or None
    payload = plan.get("payload")
    content = None
    if plan.get("content_base64") is not None:
        try:
            content = base64.b64decode(plan["content_base64"], validate=True)
        except Exception as exc:
            raise ValueError("Invalid strict Base64 content in marketing plan.") from exc

    if api == "metrika":
        url = METRIKA_BASE + _clean_api_path(plan["target"])
        return await _yandex_http(
            method, url, params=params, payload=payload, content=content,
            content_type=plan.get("content_type"),
        )

    if api == "direct":
        if not YANDEX_DIRECT_CLIENT_LOGIN:
            raise RuntimeError("YANDEX_DIRECT_CLIENT_LOGIN is required for confirmed Direct writes.")
        service = str(plan["target"]).strip().lower()
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,80}", service):
            raise ValueError("Invalid Direct service name.")
        headers = _direct_auth_headers()
        headers["Content-Type"] = "application/json; charset=utf-8"
        headers["Accept-Language"] = "ru"
        if YANDEX_DIRECT_CLIENT_LOGIN:
            headers["Client-Login"] = YANDEX_DIRECT_CLIENT_LOGIN
        body = plan.get("payload")
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=True) as client:
            response = await client.post(f"{DIRECT_BASE}/{service}", headers=headers, json=body)
        meta = _direct_response_meta(response)
        response_text = _safe_response_text(response, limit=12000)
        logger.info(
            "Yandex Direct write response: service=%s method=%s meta=%s body=%s",
            service, (body or {}).get("method"), meta, response_text,
        )
        data = _parse_direct_json(
            response, operation=f"{service}.{(body or {}).get('method', 'unknown')}"
        )
        issues = _direct_action_issues(data)
        if issues["errors"]:
            # HTTP 200 can still mean that one or more requested objects were rejected.
            # Treat that as a failed apply so callers never see a false success.
            logger.error("Yandex Direct item errors: meta=%s errors=%s", meta, issues["errors"])
            raise RuntimeError(
                f"Yandex Direct rejected one or more objects: {meta}; errors={issues['errors']}"
            )
        if issues["warnings"]:
            logger.warning("Yandex Direct item warnings: meta=%s warnings=%s", meta, issues["warnings"])
        return {
            "ok": True,
            **meta,
            "warnings": issues["warnings"],
            "direct_response": data,
        }

    raise ValueError("Unknown marketing API.")


@mcp.tool(
    title="Yandex Marketing API status",
    description="Read-only check of Marketing API configuration. Never exposes OAuth secrets.",
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
async def marketing_api_status() -> dict[str, Any]:
    return {
        "ok": True,
        "server_revision": "v6.1-yalta-direct-safe-write",
        "oauth_token_configured": bool(YANDEX_MARKETING_OAUTH_TOKEN),
        "client_id_configured": bool(YANDEX_MARKETING_CLIENT_ID),
        "direct_client_login_configured": bool(YANDEX_DIRECT_CLIENT_LOGIN),
        "write_policy": (
            "allow-listed generic safe writes + Yalta fixed campaign wrappers -> "
            "preview -> immutable plan -> explicit confirmation -> apply -> read-back verification"
        ),
        "plan_ttl_seconds": MARKETING_PLAN_TTL_SECONDS,
        "plan_store": "durable_atomic_file",
        "plan_store_path_configured": bool(MARKETING_PLAN_STORE_PATH),
        "direct_apply_tool": "apply_direct_safe_write",
        "direct_write_capabilities": [
            "generic_safe_update_campaign_adgroup_keyword_textad",
            "generic_safe_actions_suspend_resume_archive_unarchive_moderate",
            "generic_safe_add_textcampaign_adgroup_keyword_textad",
            "yalta_search_campaign_710957838",
            "yalta_rsya_campaign_710989135",
            "yalta_search_negatives_fixed_campaign",
            "yalta_rsya_excluded_sites_fixed_campaign",
            "yalta_fixed_campaign_actions",
            "yalta_rsya_autotargeting_205765233585",
            "yalta_rsya_working_ad_1916320049195790898",
        ],
        "yalta_fixed_scope": {
            "search_campaign_id": 710957838,
            "rsya_campaign_id": 710989135,
            "search_kitchen_group_id": 5765010118,
            "rsya_kitchen_group_id": 5765233585,
            "search_autotargeting_id": 205765010118,
            "rsya_autotargeting_id": 205765233585,
            "search_kitchen_ad_id": 17761831376,
            "rsya_working_ad_id": "1916320049195790898",
        },
        "direct_safe_write_tools": [
            "direct_safe_write_capabilities",
            "preview_direct_safe_update",
            "preview_direct_safe_action",
            "preview_direct_safe_add",
            "apply_direct_safe_write",
        ],
        "metrika_apply_tool": "no public generic write; fixed operations only",
    }


@mcp.tool(
    title="Metrica read",
    description=(
        "READ-ONLY universal Yandex Metrica REST reader. Supports Management API, "
        "Reporting API and Logs API GET resources by relative path."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
async def metrika_read(
    path: str,
    params: Optional[dict[str, Any]] = None,
) -> Any:
    safe_path = _clean_api_path(path)
    return await _yandex_http("GET", METRIKA_BASE + safe_path, params=params)


@mcp.tool(
    title="List Yandex Metrica counters",
    description="READ-ONLY: list counters available to the OAuth user.",
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
async def metrika_list_counters(
    fields: str = "goals,mirrors,grants,filters,operations,counter_flags,measurement_tokens",
) -> Any:
    return await _yandex_http(
        "GET",
        f"{METRIKA_BASE}/management/v1/counters",
        params={"field": fields},
    )


@mcp.tool(
    title="Metrica report",
    description="READ-ONLY: run a Yandex Metrica Reporting API request (/stat/v1/data).",
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
async def metrika_report(params: dict[str, Any]) -> Any:
    return await _yandex_http("GET", f"{METRIKA_BASE}/stat/v1/data", params=params)


async def _preview_metrika_write_internal(
    method: str,
    path: str,
    params: Optional[dict[str, Any]] = None,
    payload: Optional[Any] = None,
    content_base64: Optional[str] = None,
    content_type: Optional[str] = None,
) -> dict[str, Any]:
    safe_path = _clean_api_path(path)
    if content_base64 is not None:
        base64.b64decode(content_base64, validate=True)
    return _make_marketing_plan(
        "metrika", method, safe_path, params=params, payload=payload,
        content_base64=content_base64, content_type=content_type,
    )


@mcp.tool(
    title="Yandex Direct read",
    description=(
        "READ-ONLY universal Direct API v5 reader. Calls only the get method of the "
        "specified Direct service; mutating Direct methods are rejected here."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
async def direct_get(
    service: str,
    params: dict[str, Any],
) -> Any:
    service_name = str(service).strip().lower()
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,80}", service_name):
        raise ValueError("Invalid Direct service name.")
    headers = _direct_auth_headers()
    headers["Content-Type"] = "application/json; charset=utf-8"
    headers["Accept-Language"] = "ru"
    if YANDEX_DIRECT_CLIENT_LOGIN:
        headers["Client-Login"] = YANDEX_DIRECT_CLIENT_LOGIN
    body = {"method": "get", "params": params}
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=True) as client:
        response = await client.post(f"{DIRECT_BASE}/{service_name}", headers=headers, json=body)
    return _parse_direct_json(response, operation=f"{service_name}.get")


@mcp.tool(
    title="Yandex Direct report",
    description="READ-ONLY: request a Yandex Direct Reports API v5 report.",
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
async def direct_report(
    params: dict[str, Any],
    return_money_in_micros: bool = False,
    skip_report_header: bool = True,
    skip_report_summary: bool = True,
) -> Any:
    headers = _direct_auth_headers()
    headers["Content-Type"] = "application/json; charset=utf-8"
    headers["Accept-Language"] = "ru"
    headers["processingMode"] = "auto"
    headers["returnMoneyInMicros"] = "true" if return_money_in_micros else "false"
    headers["skipReportHeader"] = "true" if skip_report_header else "false"
    headers["skipReportSummary"] = "true" if skip_report_summary else "false"
    if YANDEX_DIRECT_CLIENT_LOGIN:
        headers["Client-Login"] = YANDEX_DIRECT_CLIENT_LOGIN
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=True) as client:
        response = await client.post(DIRECT_REPORTS_URL, headers=headers, json={"params": params})
    if response.status_code >= 400:
        raise RuntimeError(
            f"Yandex Direct Reports returned HTTP {response.status_code}: {_safe_response_text(response)}"
        )
    return {
        "status_code": response.status_code,
        "text": response.text,
        "headers": {
            k: v for k, v in response.headers.items()
            if k.lower().startswith("reports-") or k.lower() == "retry-in"
        },
    }


async def _preview_direct_write_internal(
    service: str,
    method: str,
    params: dict[str, Any],
) -> dict[str, Any]:
    service_name = str(service).strip().lower()
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,80}", service_name):
        raise ValueError("Invalid Direct service name.")
    method_name = str(method).strip()
    if method_name.lower() == "get":
        raise ValueError("Use direct_get for read-only Direct requests.")
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,80}", method_name):
        raise ValueError("Invalid Direct method name.")
    if not isinstance(params, dict) or not params:
        raise ValueError("Direct write params must be a non-empty object.")

    # Guard a known campaigns.add schema trap: BudgetType is not part of
    # StrategyMaximumConversionRateAdd in the current Direct v5 add schema.
    if service_name == "campaigns" and method_name.lower() == "add":
        for campaign in params.get("Campaigns", []) if isinstance(params.get("Campaigns"), list) else []:
            tc = campaign.get("TextCampaign") if isinstance(campaign, dict) else None
            search = ((tc or {}).get("BiddingStrategy") or {}).get("Search") if isinstance(tc, dict) else None
            wb = (search or {}).get("WbMaximumConversionRate") if isinstance(search, dict) else None
            if isinstance(wb, dict) and "BudgetType" in wb:
                raise ValueError(
                    "campaigns.add: remove WbMaximumConversionRate.BudgetType; "
                    "use WeeklySpendLimit for the weekly budget in the current Direct v5 add schema."
                )
    return _make_marketing_plan(
        "direct",
        "POST",
        service_name,
        payload={"method": method_name, "params": params},
    )


async def _apply_confirmed_marketing_plan(
    plan_id: str,
    confirmation_token: str,
    *,
    required_api: str,
) -> Any:
    """Internal executor. Generic execution is never exposed as an MCP write tool."""
    now = time.time()

    # Critical: preview/apply may arrive in different stateless HTTP requests.
    # Never rely on process memory for authorization state.
    with _MARKETING_PLAN_LOCK:
        store = _prune_marketing_plans(_load_marketing_plan_store())
        plan = store.get(plan_id)
        if not plan:
            raise ValueError("Marketing plan not found. It may have expired or the durable store was reset.")
        if str(plan.get("api")) != required_api:
            raise ValueError(f"This confirmation tool accepts only {required_api} plans.")
        expected = str(plan["confirmation_token_hash"])
        actual = _sha256_bytes(str(confirmation_token).encode("utf-8"))
        if not hmac.compare_digest(expected, actual):
            _marketing_audit_event(plan, "confirmation_rejected", reason="invalid_token")
            store[plan_id] = plan
            _save_marketing_plan_store(store)
            raise ValueError("Invalid confirmation token.")
        if plan.get("state") != "pending" or plan.get("used"):
            raise ValueError(f"Marketing plan is not pending; current state={plan.get('state')}.")
        if float(plan["expires_at"]) <= now:
            plan["state"] = "expired"
            plan["terminal_at"] = now
            _marketing_audit_event(plan, "expired_before_apply")
            store[plan_id] = plan
            _save_marketing_plan_store(store)
            raise ValueError("Marketing plan has expired.")

        # Consume BEFORE any external request. This prevents duplicate mutation if the
        # client retries after an ambiguous timeout or tool transport failure.
        plan["used"] = True
        plan["state"] = "executing"
        plan["apply_started_at"] = now
        _marketing_audit_event(plan, "apply_started", api=required_api)
        store[plan_id] = plan
        _save_marketing_plan_store(store)

    try:
        result = await _execute_marketing_plan(plan)
    except Exception as exc:
        # Do not make the plan reusable. A transport failure can be ambiguous:
        # Yandex may have accepted the mutation even if the response was lost.
        with _MARKETING_PLAN_LOCK:
            store = _load_marketing_plan_store()
            current = store.get(plan_id, plan)
            current["state"] = "failed_or_ambiguous"
            current["terminal_at"] = time.time()
            current["result_summary"] = {
                "ok": False,
                "error_type": type(exc).__name__,
                "error": str(exc)[:4000],
            }
            _marketing_audit_event(
                current, "apply_failed_or_ambiguous",
                error_type=type(exc).__name__,
                error=str(exc)[:4000],
            )
            store[plan_id] = current
            _save_marketing_plan_store(store)
        raise

    with _MARKETING_PLAN_LOCK:
        store = _load_marketing_plan_store()
        current = store.get(plan_id, plan)
        current["state"] = "succeeded"
        current["terminal_at"] = time.time()
        # Keep only safe compact diagnostics in durable history.
        summary = {"ok": True}
        if isinstance(result, dict):
            for key in ("http_status", "request_id", "units", "units_used_login", "warnings"):
                if key in result:
                    summary[key] = result[key]
        current["result_summary"] = summary
        _marketing_audit_event(current, "apply_succeeded", **summary)
        store[plan_id] = current
        _save_marketing_plan_store(store)

    return {
        "ok": True,
        "applied": True,
        "operation_sha256": plan["sha256"],
        "api": plan["api"],
        "method": plan["method"],
        "target": plan["target"],
        "result": result,
    }


async def _direct_request(service: str, body: dict[str, Any]) -> httpx.Response:
    """Low-level Direct HTTP helper used only by fixed-operation pre/post read checks."""
    service_name = str(service or "").strip().lower()
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,80}", service_name):
        raise ValueError("Invalid Direct service name.")
    if not isinstance(body, dict) or not body:
        raise ValueError("Direct request body must be a non-empty object.")

    headers = _direct_auth_headers()
    headers["Content-Type"] = "application/json; charset=utf-8"
    headers["Accept-Language"] = "ru"
    if YANDEX_DIRECT_CLIENT_LOGIN:
        headers["Client-Login"] = YANDEX_DIRECT_CLIENT_LOGIN

    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=True) as client:
        return await client.post(
            f"{DIRECT_BASE}/{service_name}",
            headers=headers,
            json=body,
        )


# =============================================================================
# Direct Safe Write Framework v1
# Generic across account-owned objects; never accepts a Direct service, method,
# URL endpoint or raw API payload from the caller. All writes are compiled from a
# small allow-listed schema, then go through immutable preview -> confirmation ->
# apply -> read-back verification. Existing fixed Rostov operations remain intact.
# =============================================================================

DIRECT_SAFE_SCOPE = "direct_safe_write_v1"
DIRECT_SAFE_POLICY_VERSION = "2026-09-21"
DIRECT_SAFE_YES_NO = {"YES", "NO"}
DIRECT_SAFE_ATTRIBUTION_MODELS = {"FCCD", "LC", "LSCCD", "AUTO"}
DIRECT_SAFE_TEXT_CAMPAIGN_SETTINGS = {
    "ADD_METRICA_TAG",
    "ADD_OPENSTAT_TAG",
    "ADD_TO_FAVORITES",
    "ENABLE_AREA_OF_INTEREST_TARGETING",
    "ENABLE_COMPANY_INFO",
    "ENABLE_EXTENDED_AD_TITLE",
    "ENABLE_SITE_MONITORING",
    "EXCLUDE_PAUSED_COMPETING_ADS",
    "MAINTAIN_NETWORK_CPC",
    "REQUIRE_SERVICING",
}
DIRECT_SAFE_AUTOTARGET_CATEGORIES = {
    "Exact", "Narrow", "Alternative", "Accessory", "Broader",
}
DIRECT_SAFE_AUTOTARGET_BRANDS = {
    "WithoutBrands", "WithAdvertiserBrand", "WithCompetitorsBrand",
}
DIRECT_SAFE_STRATEGY_TYPES = {
    "SERVING_OFF",
    "WB_MAXIMUM_CONVERSION_RATE",
    "WB_MAXIMUM_CLICKS",
    "AVERAGE_CPA",
    "PAY_FOR_CONVERSION",
}
DIRECT_SAFE_ENTITY_ALIASES = {
    "campaign": "campaign",
    "campaigns": "campaign",
    "ad_group": "ad_group",
    "adgroup": "ad_group",
    "adgroups": "ad_group",
    "keyword": "keyword",
    "keywords": "keyword",
    "autotargeting": "keyword",
    "text_ad": "text_ad",
    "ad": "text_ad",
    "ads": "text_ad",
}
DIRECT_SAFE_ACTIONS = {
    "campaign": {"suspend", "resume", "archive", "unarchive"},
    "keyword": {"suspend", "resume"},
    "text_ad": {"suspend", "resume", "moderate", "archive", "unarchive"},
}


def _direct_safe_entity(value: Any) -> str:
    key = str(value or "").strip().lower().replace("-", "_")
    entity = DIRECT_SAFE_ENTITY_ALIASES.get(key)
    if not entity:
        raise ValueError(
            "Unsupported Direct safe-write entity. Allowed: campaign, ad_group, keyword, text_ad."
        )
    return entity


def _direct_safe_positive_id(value: Any, name: str = "id") -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a positive integer.")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a positive integer.") from exc
    if parsed <= 0:
        raise ValueError(f"{name} must be a positive integer.")
    return parsed


def _direct_safe_yes_no(value: Any, name: str) -> str:
    if isinstance(value, bool):
        return "YES" if value else "NO"
    text = str(value or "").strip().upper()
    if text not in DIRECT_SAFE_YES_NO:
        raise ValueError(f"{name} must be YES/NO or boolean.")
    return text


def _direct_safe_clean_string(
    value: Any,
    name: str,
    *,
    max_length: int,
    allow_empty: bool = False,
) -> str:
    text = str(value if value is not None else "").strip()
    if not text and not allow_empty:
        raise ValueError(f"{name} must not be empty.")
    if len(text) > max_length:
        raise ValueError(f"{name} exceeds {max_length} characters.")
    if "\x00" in text:
        raise ValueError(f"{name} contains a NUL byte.")
    return text


def _direct_safe_clean_string_list(
    value: Any,
    name: str,
    *,
    max_items: int,
    max_item_length: int,
    allow_empty: bool,
    total_length: Optional[int] = None,
) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a list of strings.")
    if len(value) > max_items:
        raise ValueError(f"{name} exceeds the maximum of {max_items} items.")
    cleaned: list[str] = []
    seen: set[str] = set()
    for raw in value:
        item = re.sub(r"\s+", " ", str(raw or "").strip())
        if not item:
            continue
        if len(item) > max_item_length:
            raise ValueError(f"{name} contains an item longer than {max_item_length} characters.")
        key = item.casefold()
        if key not in seen:
            seen.add(key)
            cleaned.append(item)
    if not allow_empty and not cleaned:
        raise ValueError(f"{name} must contain at least one usable item.")
    if total_length is not None and sum(len(x) for x in cleaned) > total_length:
        raise ValueError(f"{name} exceeds the total character limit of {total_length}.")
    return cleaned


def _direct_safe_region_ids(value: Any) -> list[int]:
    if not isinstance(value, list) or not value:
        raise ValueError("region_ids must be a non-empty list of Direct geo-region IDs.")
    if len(value) > 1000:
        raise ValueError("region_ids is unexpectedly large (max 1000 in this gateway).")
    result: list[int] = []
    seen: set[int] = set()
    for raw in value:
        if isinstance(raw, bool):
            raise ValueError("region_ids items must be integers.")
        try:
            region_id = int(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError("region_ids items must be integers.") from exc
        if region_id == 0:
            normalized = 0
        elif region_id < 0:
            normalized = -_direct_safe_positive_id(abs(region_id), "region_id")
        else:
            normalized = _direct_safe_positive_id(region_id, "region_id")
        if normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    if 0 in result and any(x < 0 for x in result):
        raise ValueError("region_ids cannot combine region 0 with excluded (negative) regions.")
    if all(x < 0 for x in result):
        raise ValueError("region_ids cannot consist only of excluded regions.")
    return result


def _direct_safe_fingerprint(value: Any) -> str:
    canonical = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return _sha256_bytes(canonical.encode("utf-8"))


def _direct_safe_normalize_priority_goals(value: Any) -> Optional[list[dict[str, Any]]]:
    if value is None:
        return None
    if not isinstance(value, list):
        raise ValueError("priority_goals must be a list or null.")
    if len(value) > 30:
        raise ValueError("priority_goals supports at most 30 goals.")
    result: list[dict[str, Any]] = []
    seen: set[int] = set()
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"priority_goals[{index}] must be an object.")
        allowed = {"goal_id", "value", "is_metrika_source_of_value"}
        unknown = set(item) - allowed
        if unknown:
            raise ValueError(f"priority_goals[{index}] has unsupported fields: {sorted(unknown)}")
        goal_id = _direct_safe_positive_id(item.get("goal_id"), "goal_id")
        if goal_id in seen:
            raise ValueError(f"Duplicate priority goal ID: {goal_id}")
        seen.add(goal_id)
        try:
            goal_value = int(item.get("value"))
        except (TypeError, ValueError) as exc:
            raise ValueError("priority goal value must be an integer in Direct money units.") from exc
        if goal_value < 0:
            raise ValueError("priority goal value cannot be negative.")
        normalized = {
            "GoalId": goal_id,
            "Value": goal_value,
            "Operation": "SET",
        }
        if "is_metrika_source_of_value" in item:
            normalized["IsMetrikaSourceOfValue"] = _direct_safe_yes_no(
                item.get("is_metrika_source_of_value"), "is_metrika_source_of_value"
            )
        result.append(normalized)
    return result


def _direct_safe_strategy_lane(value: Any, lane_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"bidding_strategy.{lane_name} must be an object.")
    allowed_public = {
        "type", "goal_id", "weekly_spend_limit", "bid_ceiling", "average_cpa", "cpa"
    }
    unknown = set(value) - allowed_public
    if unknown:
        raise ValueError(
            f"bidding_strategy.{lane_name} has unsupported fields: {sorted(unknown)}"
        )
    strategy_type = str(value.get("type") or "").strip().upper()
    if strategy_type not in DIRECT_SAFE_STRATEGY_TYPES:
        raise ValueError(
            f"Unsupported bidding strategy type {strategy_type!r}. Allowed: {sorted(DIRECT_SAFE_STRATEGY_TYPES)}"
        )
    result: dict[str, Any] = {"BiddingStrategyType": strategy_type}
    if strategy_type == "SERVING_OFF":
        if set(value) != {"type"}:
            raise ValueError(f"{lane_name} SERVING_OFF accepts only the type field.")
        return result

    def _money(name: str, required: bool = False) -> Optional[int]:
        if name not in value:
            if required:
                raise ValueError(f"bidding_strategy.{lane_name}.{name} is required.")
            return None
        try:
            v = int(value.get(name))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"bidding_strategy.{lane_name}.{name} must be an integer.") from exc
        if v <= 0:
            raise ValueError(f"bidding_strategy.{lane_name}.{name} must be > 0.")
        return v

    if strategy_type == "WB_MAXIMUM_CONVERSION_RATE":
        nested = {
            "WeeklySpendLimit": _money("weekly_spend_limit", True),
            "GoalId": _direct_safe_positive_id(value.get("goal_id"), "goal_id"),
        }
        if "bid_ceiling" in value and value.get("bid_ceiling") is not None:
            nested["BidCeiling"] = _money("bid_ceiling", True)
        result["WbMaximumConversionRate"] = nested
    elif strategy_type == "WB_MAXIMUM_CLICKS":
        nested = {"WeeklySpendLimit": _money("weekly_spend_limit", True)}
        if "bid_ceiling" in value and value.get("bid_ceiling") is not None:
            nested["BidCeiling"] = _money("bid_ceiling", True)
        result["WbMaximumClicks"] = nested
    elif strategy_type == "AVERAGE_CPA":
        nested = {
            "AverageCpa": _money("average_cpa", True),
            "GoalId": _direct_safe_positive_id(value.get("goal_id"), "goal_id"),
        }
        weekly = _money("weekly_spend_limit", False)
        if weekly is not None:
            nested["WeeklySpendLimit"] = weekly
        if "bid_ceiling" in value and value.get("bid_ceiling") is not None:
            nested["BidCeiling"] = _money("bid_ceiling", True)
        result["AverageCpa"] = nested
    elif strategy_type == "PAY_FOR_CONVERSION":
        nested = {
            "Cpa": _money("cpa", True),
            "GoalId": _direct_safe_positive_id(value.get("goal_id"), "goal_id"),
        }
        weekly = _money("weekly_spend_limit", False)
        if weekly is not None:
            nested["WeeklySpendLimit"] = weekly
        result["PayForConversion"] = nested
    return result


def _direct_safe_bidding_strategy(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("bidding_strategy must be an object with search and network.")
    unknown = set(value) - {"search", "network"}
    if unknown:
        raise ValueError(f"bidding_strategy has unsupported fields: {sorted(unknown)}")
    if "search" not in value or "network" not in value:
        raise ValueError("bidding_strategy must explicitly specify both search and network lanes.")
    return {
        "Search": _direct_safe_strategy_lane(value["search"], "search"),
        "Network": _direct_safe_strategy_lane(value["network"], "network"),
    }


def _direct_safe_strategy_public(value: Any) -> Any:
    if not isinstance(value, dict):
        return None
    output: dict[str, Any] = {}
    for public_lane, api_lane in (("search", "Search"), ("network", "Network")):
        lane = value.get(api_lane)
        if not isinstance(lane, dict):
            output[public_lane] = None
            continue
        st = str(lane.get("BiddingStrategyType") or "")
        pub: dict[str, Any] = {"type": st}
        if st == "WB_MAXIMUM_CONVERSION_RATE":
            n = lane.get("WbMaximumConversionRate") or {}
            pub.update({
                "goal_id": n.get("GoalId"),
                "weekly_spend_limit": n.get("WeeklySpendLimit"),
                "bid_ceiling": n.get("BidCeiling"),
            })
        elif st == "WB_MAXIMUM_CLICKS":
            n = lane.get("WbMaximumClicks") or {}
            pub.update({
                "weekly_spend_limit": n.get("WeeklySpendLimit"),
                "bid_ceiling": n.get("BidCeiling"),
            })
        elif st == "AVERAGE_CPA":
            n = lane.get("AverageCpa") or {}
            pub.update({
                "average_cpa": n.get("AverageCpa"),
                "goal_id": n.get("GoalId"),
                "weekly_spend_limit": n.get("WeeklySpendLimit"),
                "bid_ceiling": n.get("BidCeiling"),
            })
        elif st == "PAY_FOR_CONVERSION":
            n = lane.get("PayForConversion") or {}
            pub.update({
                "cpa": n.get("Cpa"),
                "goal_id": n.get("GoalId"),
                "weekly_spend_limit": n.get("WeeklySpendLimit"),
            })
        output[public_lane] = pub
    return output


def _direct_safe_autotargeting_settings(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or not value:
        raise ValueError("autotargeting_settings must be a non-empty object.")
    unknown = set(value) - {"categories", "brand_options"}
    if unknown:
        raise ValueError(f"autotargeting_settings has unsupported fields: {sorted(unknown)}")
    result: dict[str, Any] = {}
    if "categories" in value:
        categories = value.get("categories")
        if not isinstance(categories, dict) or not categories:
            raise ValueError("autotargeting_settings.categories must be a non-empty object.")
        unknown_cat = set(categories) - DIRECT_SAFE_AUTOTARGET_CATEGORIES
        if unknown_cat:
            raise ValueError(f"Unsupported autotargeting categories: {sorted(unknown_cat)}")
        result["Categories"] = {
            key: _direct_safe_yes_no(val, f"categories.{key}")
            for key, val in categories.items()
        }
    if "brand_options" in value:
        brands = value.get("brand_options")
        if not isinstance(brands, dict) or not brands:
            raise ValueError("autotargeting_settings.brand_options must be a non-empty object.")
        unknown_brand = set(brands) - DIRECT_SAFE_AUTOTARGET_BRANDS
        if unknown_brand:
            raise ValueError(f"Unsupported autotargeting brand options: {sorted(unknown_brand)}")
        result["BrandOptions"] = {
            key: _direct_safe_yes_no(val, f"brand_options.{key}")
            for key, val in brands.items()
        }
    return result


async def _direct_safe_get_entity(entity: str, entity_id: int) -> Optional[dict[str, Any]]:
    entity = _direct_safe_entity(entity)
    entity_id = _direct_safe_positive_id(entity_id)
    if entity == "campaign":
        body = {
            "method": "get",
            "params": {
                "SelectionCriteria": {"Ids": [entity_id]},
                "FieldNames": [
                    "Id", "Name", "State", "Status", "Type", "NegativeKeywords", "ExcludedSites"
                ],
                "TextCampaignFieldNames": [
                    "Settings", "TrackingParams", "CounterIds", "AttributionModel",
                    "PriorityGoals", "BiddingStrategy"
                ],
            },
        }
        response = await _direct_request("campaigns", body)
        data = _parse_direct_json(response, operation="campaigns.get safe-write pre/post check")
        items = ((data.get("result") or {}).get("Campaigns") or [])
    elif entity == "ad_group":
        body = {
            "method": "get",
            "params": {
                "SelectionCriteria": {"Ids": [entity_id]},
                "FieldNames": [
                    "Id", "Name", "CampaignId", "RegionIds", "NegativeKeywords",
                    "TrackingParams", "Status", "ServingStatus", "Type"
                ],
            },
        }
        response = await _direct_request("adgroups", body)
        data = _parse_direct_json(response, operation="adgroups.get safe-write pre/post check")
        items = ((data.get("result") or {}).get("AdGroups") or [])
    elif entity == "keyword":
        body = {
            "method": "get",
            "params": {
                "SelectionCriteria": {"Ids": [entity_id]},
                "FieldNames": [
                    "Id", "Keyword", "State", "Status", "AdGroupId", "CampaignId",
                    "UserParam1", "UserParam2"
                ],
                "AutotargetingSettingsCategoriesFieldNames": [
                    "Exact", "Narrow", "Alternative", "Accessory", "Broader"
                ],
                "AutotargetingSettingsBrandOptionsFieldNames": [
                    "WithoutBrands", "WithAdvertiserBrand", "WithCompetitorsBrand"
                ],
            },
        }
        response = await _direct_request("keywords", body)
        data = _parse_direct_json(response, operation="keywords.get safe-write pre/post check")
        items = ((data.get("result") or {}).get("Keywords") or [])
    else:
        body = {
            "method": "get",
            "params": {
                "SelectionCriteria": {"Ids": [entity_id]},
                "FieldNames": [
                    "Id", "CampaignId", "AdGroupId", "Status", "State", "Type"
                ],
                "TextAdFieldNames": [
                    "Title", "Title2", "Text", "Href", "Mobile", "DisplayUrlPath", "SitelinkSetId"
                ],
            },
        }
        response = await _direct_request("ads", body)
        data = _parse_direct_json(response, operation="ads.get safe-write pre/post check")
        items = ((data.get("result") or {}).get("Ads") or [])
    return items[0] if items else None


def _direct_safe_campaign_settings_map(campaign: dict[str, Any]) -> dict[str, str]:
    settings = (((campaign.get("TextCampaign") or {}).get("Settings")) or [])
    result: dict[str, str] = {}
    for item in settings:
        if isinstance(item, dict) and item.get("Option"):
            result[str(item["Option"])] = str(item.get("Value") or "")
    return result


def _direct_safe_snapshot(entity: str, obj: dict[str, Any], change_keys: list[str]) -> dict[str, Any]:
    entity = _direct_safe_entity(entity)
    snapshot: dict[str, Any] = {}
    if entity == "campaign":
        tc = obj.get("TextCampaign") or {}
        settings_map = _direct_safe_campaign_settings_map(obj)
        for key in change_keys:
            if key == "name":
                snapshot[key] = obj.get("Name")
            elif key == "negative_keywords":
                snapshot[key] = list(((obj.get("NegativeKeywords") or {}).get("Items") or []))
            elif key == "excluded_sites":
                snapshot[key] = list(((obj.get("ExcludedSites") or {}).get("Items") or []))
            elif key == "tracking_params":
                snapshot[key] = tc.get("TrackingParams") or ""
            elif key == "counter_ids":
                snapshot[key] = list(((tc.get("CounterIds") or {}).get("Items") or []))
            elif key == "attribution_model":
                snapshot[key] = tc.get("AttributionModel")
            elif key == "priority_goals":
                normalized = []
                for item in ((tc.get("PriorityGoals") or {}).get("Items") or []):
                    if isinstance(item, dict):
                        normalized.append({
                            "GoalId": item.get("GoalId"),
                            "Value": item.get("Value"),
                            "IsMetrikaSourceOfValue": item.get("IsMetrikaSourceOfValue"),
                        })
                snapshot[key] = normalized
            elif key == "bidding_strategy":
                snapshot[key] = _direct_safe_strategy_public(tc.get("BiddingStrategy"))
            elif key.startswith("setting:"):
                option = key.split(":", 1)[1]
                snapshot[key] = settings_map.get(option)
    elif entity == "ad_group":
        for key in change_keys:
            if key == "name":
                snapshot[key] = obj.get("Name")
            elif key == "region_ids":
                snapshot[key] = list(obj.get("RegionIds") or [])
            elif key == "negative_keywords":
                snapshot[key] = list(((obj.get("NegativeKeywords") or {}).get("Items") or []))
            elif key == "tracking_params":
                snapshot[key] = obj.get("TrackingParams") or ""
    elif entity == "keyword":
        auto = obj.get("AutotargetingSettings") or {}
        for key in change_keys:
            if key == "keyword":
                snapshot[key] = obj.get("Keyword")
            elif key == "user_param1":
                snapshot[key] = obj.get("UserParam1")
            elif key == "user_param2":
                snapshot[key] = obj.get("UserParam2")
            elif key == "autotargeting_settings":
                snapshot[key] = {
                    "Categories": dict(auto.get("Categories") or {}),
                    "BrandOptions": dict(auto.get("BrandOptions") or {}),
                }
    else:
        text_ad = obj.get("TextAd") or {}
        for key in change_keys:
            api_key = {
                "title": "Title", "title2": "Title2", "text": "Text", "href": "Href",
                "display_url_path": "DisplayUrlPath", "sitelink_set_id": "SitelinkSetId",
            }.get(key)
            if api_key:
                snapshot[key] = text_ad.get(api_key)
    return snapshot


def _direct_safe_compile_campaign_update(
    campaign: dict[str, Any], changes: dict[str, Any]
) -> tuple[dict[str, Any], list[str], dict[str, Any]]:
    if str(campaign.get("Type") or "") != "TEXT_CAMPAIGN":
        raise ValueError("Generic safe campaign update currently supports TEXT_CAMPAIGN only.")
    allowed = {
        "name", "negative_keywords", "excluded_sites", "tracking_params", "counter_ids",
        "attribution_model", "priority_goals", "settings", "add_metrica_tag",
        "area_of_interest_targeting", "bidding_strategy",
    }
    unknown = set(changes) - allowed
    if unknown:
        raise ValueError(f"Unsupported campaign update fields: {sorted(unknown)}")
    item: dict[str, Any] = {"Id": int(campaign["Id"])}
    tc: dict[str, Any] = {}
    change_keys: list[str] = []
    expected: dict[str, Any] = {}

    if "name" in changes:
        value = _direct_safe_clean_string(changes["name"], "name", max_length=255)
        item["Name"] = value
        change_keys.append("name")
        expected["name"] = value
    if "negative_keywords" in changes:
        raw = changes["negative_keywords"]
        if raw is None:
            item["NegativeKeywords"] = None
            cleaned: list[str] = []
        else:
            cleaned = _direct_safe_clean_string_list(
                raw, "negative_keywords", max_items=1000, max_item_length=255,
                allow_empty=True, total_length=20000,
            )
            item["NegativeKeywords"] = {"Items": cleaned} if cleaned else None
        change_keys.append("negative_keywords")
        expected["negative_keywords"] = cleaned
    if "excluded_sites" in changes:
        raw = changes["excluded_sites"]
        if raw is None:
            item["ExcludedSites"] = None
            sites: list[str] = []
        else:
            sites = _direct_safe_clean_string_list(
                raw, "excluded_sites", max_items=1000, max_item_length=255, allow_empty=True
            )
            item["ExcludedSites"] = {"Items": sites} if sites else None
        change_keys.append("excluded_sites")
        expected["excluded_sites"] = sites
    if "tracking_params" in changes:
        value = _direct_safe_clean_string(
            changes["tracking_params"], "tracking_params", max_length=1024, allow_empty=True
        )
        tc["TrackingParams"] = value
        change_keys.append("tracking_params")
        expected["tracking_params"] = value
    if "counter_ids" in changes:
        raw = changes["counter_ids"]
        if raw is None:
            tc["CounterIds"] = None
            ids: list[int] = []
        else:
            if not isinstance(raw, list) or len(raw) > 100:
                raise ValueError("counter_ids must be a list of at most 100 positive integers or null.")
            ids = []
            for x in raw:
                v = _direct_safe_positive_id(x, "counter_id")
                if v not in ids:
                    ids.append(v)
            tc["CounterIds"] = {"Items": ids} if ids else None
        change_keys.append("counter_ids")
        expected["counter_ids"] = ids
    if "attribution_model" in changes:
        value = str(changes["attribution_model"] or "").strip().upper()
        if value not in DIRECT_SAFE_ATTRIBUTION_MODELS:
            raise ValueError(f"Unsupported attribution_model: {value}")
        tc["AttributionModel"] = value
        change_keys.append("attribution_model")
        expected["attribution_model"] = value
    if "priority_goals" in changes:
        goals = _direct_safe_normalize_priority_goals(changes["priority_goals"])
        tc["PriorityGoals"] = None if goals is None else {"Items": goals}
        change_keys.append("priority_goals")
        expected["priority_goals"] = [] if goals is None else [
            {
                "GoalId": x.get("GoalId"),
                "Value": x.get("Value"),
                "IsMetrikaSourceOfValue": x.get("IsMetrikaSourceOfValue"),
            }
            for x in goals
        ]
    if "bidding_strategy" in changes:
        api_strategy = _direct_safe_bidding_strategy(changes["bidding_strategy"])
        tc["BiddingStrategy"] = api_strategy
        change_keys.append("bidding_strategy")
        expected["bidding_strategy"] = _direct_safe_strategy_public(api_strategy)

    settings_input: dict[str, Any] = {}
    if "settings" in changes:
        if not isinstance(changes["settings"], dict):
            raise ValueError("settings must be an object of Direct setting option -> YES/NO.")
        settings_input.update(changes["settings"])
    if "add_metrica_tag" in changes:
        if "ADD_METRICA_TAG" in settings_input:
            raise ValueError("Specify either add_metrica_tag or settings.ADD_METRICA_TAG, not both.")
        settings_input["ADD_METRICA_TAG"] = changes["add_metrica_tag"]
    if "area_of_interest_targeting" in changes:
        if "ENABLE_AREA_OF_INTEREST_TARGETING" in settings_input:
            raise ValueError(
                "Specify either area_of_interest_targeting or settings.ENABLE_AREA_OF_INTEREST_TARGETING, not both."
            )
        settings_input["ENABLE_AREA_OF_INTEREST_TARGETING"] = changes["area_of_interest_targeting"]
    if settings_input:
        settings_items = []
        for raw_option, raw_value in settings_input.items():
            option = str(raw_option or "").strip().upper()
            if option not in DIRECT_SAFE_TEXT_CAMPAIGN_SETTINGS:
                raise ValueError(f"Unsupported TextCampaign setting: {option}")
            value = _direct_safe_yes_no(raw_value, option)
            settings_items.append({"Option": option, "Value": value})
            key = f"setting:{option}"
            change_keys.append(key)
            expected[key] = value
        tc["Settings"] = settings_items
    if tc:
        item["TextCampaign"] = tc
    if set(item) == {"Id"}:
        raise ValueError("No usable campaign changes were supplied.")
    return item, change_keys, expected


def _direct_safe_compile_ad_group_update(
    group: dict[str, Any], changes: dict[str, Any]
) -> tuple[dict[str, Any], list[str], dict[str, Any]]:
    allowed = {"name", "region_ids", "negative_keywords", "tracking_params"}
    unknown = set(changes) - allowed
    if unknown:
        raise ValueError(f"Unsupported ad_group update fields: {sorted(unknown)}")
    item: dict[str, Any] = {"Id": int(group["Id"])}
    change_keys: list[str] = []
    expected: dict[str, Any] = {}
    if "name" in changes:
        v = _direct_safe_clean_string(changes["name"], "name", max_length=255)
        item["Name"] = v; change_keys.append("name"); expected["name"] = v
    if "region_ids" in changes:
        v = _direct_safe_region_ids(changes["region_ids"])
        item["RegionIds"] = v; change_keys.append("region_ids"); expected["region_ids"] = v
    if "negative_keywords" in changes:
        raw = changes["negative_keywords"]
        if raw is None:
            cleaned: list[str] = []; item["NegativeKeywords"] = None
        else:
            cleaned = _direct_safe_clean_string_list(
                raw, "negative_keywords", max_items=1000, max_item_length=255,
                allow_empty=True, total_length=20000,
            )
            item["NegativeKeywords"] = {"Items": cleaned} if cleaned else None
        change_keys.append("negative_keywords"); expected["negative_keywords"] = cleaned
    if "tracking_params" in changes:
        v = _direct_safe_clean_string(
            changes["tracking_params"], "tracking_params", max_length=1024, allow_empty=True
        )
        item["TrackingParams"] = v; change_keys.append("tracking_params"); expected["tracking_params"] = v
    if set(item) == {"Id"}:
        raise ValueError("No usable ad_group changes were supplied.")
    return item, change_keys, expected


def _direct_safe_compile_keyword_update(
    keyword: dict[str, Any], changes: dict[str, Any]
) -> tuple[dict[str, Any], list[str], dict[str, Any]]:
    allowed = {"keyword", "user_param1", "user_param2", "autotargeting_settings"}
    unknown = set(changes) - allowed
    if unknown:
        raise ValueError(f"Unsupported keyword update fields: {sorted(unknown)}")
    item: dict[str, Any] = {"Id": int(keyword["Id"])}
    change_keys: list[str] = []
    expected: dict[str, Any] = {}
    is_auto = str(keyword.get("Keyword") or "") == "---autotargeting"
    if "keyword" in changes:
        if is_auto:
            raise ValueError("The ---autotargeting keyword text cannot be changed.")
        v = _direct_safe_clean_string(changes["keyword"], "keyword", max_length=4096)
        item["Keyword"] = v; change_keys.append("keyword"); expected["keyword"] = v
    for public, api in (("user_param1", "UserParam1"), ("user_param2", "UserParam2")):
        if public in changes:
            raw = changes[public]
            v = None if raw is None else _direct_safe_clean_string(raw, public, max_length=255, allow_empty=True)
            item[api] = v; change_keys.append(public); expected[public] = v
    if "autotargeting_settings" in changes:
        if not is_auto:
            raise ValueError("autotargeting_settings can be changed only on the ---autotargeting criterion.")
        v = _direct_safe_autotargeting_settings(changes["autotargeting_settings"])
        item["AutotargetingSettings"] = v
        change_keys.append("autotargeting_settings")
        # Expected is a partial snapshot because Direct allows partial category/brand updates.
        expected["autotargeting_settings"] = v
    if set(item) == {"Id"}:
        raise ValueError("No usable keyword changes were supplied.")
    return item, change_keys, expected


def _direct_safe_compile_text_ad_update(
    ad: dict[str, Any], changes: dict[str, Any]
) -> tuple[dict[str, Any], list[str], dict[str, Any]]:
    if str(ad.get("Type") or "") != "TEXT_AD":
        raise ValueError("Generic safe ad update currently supports TEXT_AD only.")
    allowed = {"title", "title2", "text", "href", "display_url_path", "sitelink_set_id"}
    unknown = set(changes) - allowed
    if unknown:
        raise ValueError(f"Unsupported text_ad update fields: {sorted(unknown)}")
    text_ad: dict[str, Any] = {}
    change_keys: list[str] = []
    expected: dict[str, Any] = {}
    limits = {"title": 56, "title2": 30, "text": 81, "href": 1024, "display_url_path": 20}
    api_names = {
        "title": "Title", "title2": "Title2", "text": "Text", "href": "Href",
        "display_url_path": "DisplayUrlPath", "sitelink_set_id": "SitelinkSetId",
    }
    for key in ("title", "title2", "text", "href", "display_url_path"):
        if key not in changes:
            continue
        raw = changes[key]
        allow_none = key in {"title2", "href", "display_url_path"}
        if raw is None and allow_none:
            value = None
        else:
            value = _direct_safe_clean_string(
                raw, key, max_length=limits[key], allow_empty=allow_none
            )
        if key == "href" and value and not re.match(r"^https?://", value, flags=re.I):
            raise ValueError("href must start with http:// or https://")
        text_ad[api_names[key]] = value
        change_keys.append(key)
        expected[key] = value
    if "sitelink_set_id" in changes:
        raw = changes["sitelink_set_id"]
        value = None if raw is None else _direct_safe_positive_id(raw, "sitelink_set_id")
        text_ad["SitelinkSetId"] = value
        change_keys.append("sitelink_set_id")
        expected["sitelink_set_id"] = value
    if not text_ad:
        raise ValueError("No usable text_ad changes were supplied.")
    return {"Id": int(ad["Id"]), "TextAd": text_ad}, change_keys, expected


def _direct_safe_partial_match(actual: Any, expected: Any) -> bool:
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return False
        return all(k in actual and _direct_safe_partial_match(actual[k], v) for k, v in expected.items())
    if isinstance(expected, list):
        return actual == expected
    return actual == expected


def _direct_safe_snapshots_match(actual: dict[str, Any], expected: dict[str, Any]) -> bool:
    for key, expected_value in expected.items():
        if key == "autotargeting_settings":
            if not _direct_safe_partial_match(actual.get(key), expected_value):
                return False
        elif actual.get(key) != expected_value:
            return False
    return True


async def _direct_safe_preview_update_internal(
    entity: str, entity_id: int, changes: dict[str, Any]
) -> dict[str, Any]:
    entity = _direct_safe_entity(entity)
    entity_id = _direct_safe_positive_id(entity_id, "entity_id")
    if not isinstance(changes, dict) or not changes:
        raise ValueError("changes must be a non-empty object.")
    current = await _direct_safe_get_entity(entity, entity_id)
    if not current:
        return {
            "ok": False, "preview_only": True, "blocked_by_precondition": True,
            "reason": "entity_missing", "entity": entity, "entity_id": entity_id,
        }
    if entity == "campaign":
        item, change_keys, expected = _direct_safe_compile_campaign_update(current, changes)
        service, list_key = "campaigns", "Campaigns"
    elif entity == "ad_group":
        item, change_keys, expected = _direct_safe_compile_ad_group_update(current, changes)
        service, list_key = "adgroups", "AdGroups"
    elif entity == "keyword":
        item, change_keys, expected = _direct_safe_compile_keyword_update(current, changes)
        service, list_key = "keywords", "Keywords"
    else:
        item, change_keys, expected = _direct_safe_compile_text_ad_update(current, changes)
        service, list_key = "ads", "Ads"
    before = _direct_safe_snapshot(entity, current, change_keys)
    if _direct_safe_snapshots_match(before, expected):
        return {
            "ok": False, "preview_only": True, "blocked_by_precondition": True,
            "reason": "already_matches", "entity": entity, "entity_id": entity_id,
            "current": before,
        }
    payload = {"method": "update", "params": {list_key: [item]}}
    metadata = {
        "scope": DIRECT_SAFE_SCOPE,
        "policy_version": DIRECT_SAFE_POLICY_VERSION,
        "operation": "update",
        "entity": entity,
        "entity_id": entity_id,
        "change_keys": change_keys,
        "base_fingerprint": _direct_safe_fingerprint(before),
        "expected_snapshot": expected,
    }
    preview = _make_marketing_plan("direct", "POST", service, params=metadata, payload=payload)
    preview["safe_write"] = True
    preview["policy_version"] = DIRECT_SAFE_POLICY_VERSION
    preview["summary"] = {
        "operation": "update", "entity": entity, "entity_id": entity_id,
        "current": before, "proposed": expected,
    }
    return preview


@mcp.tool(
    title="Direct safe-write capabilities",
    description=(
        "READ-ONLY. Shows the generic account-wide Direct safe-write policy. It exposes no OAuth "
        "secret and cannot mutate Direct. New campaign/group/ad IDs do not require new tools."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False),
)
async def direct_safe_write_capabilities() -> dict[str, Any]:
    return {
        "ok": True,
        "scope": DIRECT_SAFE_SCOPE,
        "policy_version": DIRECT_SAFE_POLICY_VERSION,
        "workflow": "preview -> immutable plan -> explicit confirmation -> apply -> read-back verification",
        "generic_update": {
            "campaign": [
                "name", "negative_keywords", "excluded_sites", "tracking_params", "counter_ids",
                "attribution_model", "priority_goals", "settings", "add_metrica_tag",
                "area_of_interest_targeting", "bidding_strategy",
            ],
            "ad_group": ["name", "region_ids", "negative_keywords", "tracking_params"],
            "keyword": ["keyword", "user_param1", "user_param2", "autotargeting_settings"],
            "text_ad": ["title", "title2", "text", "href", "display_url_path", "sitelink_set_id"],
        },
        "generic_actions": {k: sorted(v) for k, v in DIRECT_SAFE_ACTIONS.items()},
        "generic_add": ["text_campaign", "ad_group", "keyword", "text_ad"],
        "not_exposed": ["raw service", "raw method", "raw Direct payload", "delete"],
    }


@mcp.tool(
    title="Preview generic safe Direct update",
    description=(
        "PREVIEW ONLY. Safely updates an account-owned campaign, ad group, keyword/autotargeting, "
        "or text ad by ID using an allow-listed field schema. The caller cannot choose the Direct "
        "service/method or provide a raw API payload. Creates an immutable plan and performs no write."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
async def preview_direct_safe_update(
    entity: str,
    entity_id: Annotated[int, Field(gt=0)],
    changes: dict[str, Any],
) -> dict[str, Any]:
    return await _direct_safe_preview_update_internal(entity, entity_id, changes)


async def _direct_safe_state_snapshot(entity: str, obj: dict[str, Any]) -> dict[str, Any]:
    if entity == "campaign":
        return {"state": obj.get("State"), "status": obj.get("Status")}
    if entity == "keyword":
        return {"state": obj.get("State"), "status": obj.get("Status")}
    return {"state": obj.get("State"), "status": obj.get("Status")}


@mcp.tool(
    title="Preview generic safe Direct action",
    description=(
        "PREVIEW ONLY. Prepares an allow-listed state action (suspend/resume/archive/unarchive/moderate) "
        "for account-owned Direct objects. Delete and arbitrary methods are not exposed."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
async def preview_direct_safe_action(
    entity: str,
    action: str,
    entity_ids: list[int],
) -> dict[str, Any]:
    entity = _direct_safe_entity(entity)
    action = str(action or "").strip().lower()
    allowed_actions = DIRECT_SAFE_ACTIONS.get(entity) or set()
    if action not in allowed_actions:
        raise ValueError(f"Action {action!r} is not allowed for {entity}; allowed={sorted(allowed_actions)}")
    if not isinstance(entity_ids, list) or not entity_ids or len(entity_ids) > 1000:
        raise ValueError("entity_ids must contain 1..1000 positive IDs.")
    ids: list[int] = []
    before: dict[str, Any] = {}
    for raw in entity_ids:
        entity_id = _direct_safe_positive_id(raw, "entity_id")
        if entity_id in ids:
            continue
        obj = await _direct_safe_get_entity(entity, entity_id)
        if not obj:
            return {
                "ok": False, "preview_only": True, "blocked_by_precondition": True,
                "reason": "entity_missing", "entity": entity, "entity_id": entity_id,
            }
        ids.append(entity_id)
        before[str(entity_id)] = await _direct_safe_state_snapshot(entity, obj)
    service = {"campaign": "campaigns", "keyword": "keywords", "text_ad": "ads"}[entity]
    payload = {"method": action, "params": {"SelectionCriteria": {"Ids": ids}}}
    metadata = {
        "scope": DIRECT_SAFE_SCOPE,
        "policy_version": DIRECT_SAFE_POLICY_VERSION,
        "operation": "action",
        "entity": entity,
        "action": action,
        "entity_ids": ids,
        "base_fingerprint": _direct_safe_fingerprint(before),
    }
    preview = _make_marketing_plan("direct", "POST", service, params=metadata, payload=payload)
    preview["safe_write"] = True
    preview["summary"] = {"operation": "action", "entity": entity, "action": action, "ids": ids, "current": before}
    return preview


def _direct_safe_compile_text_campaign_add(spec: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    allowed = {
        "name", "start_date", "negative_keywords", "excluded_sites", "settings", "counter_ids",
        "tracking_params", "attribution_model", "priority_goals", "bidding_strategy",
    }
    unknown = set(spec) - allowed
    if unknown:
        raise ValueError(f"Unsupported text_campaign add fields: {sorted(unknown)}")
    name = _direct_safe_clean_string(spec.get("name"), "name", max_length=255)
    if "bidding_strategy" not in spec:
        raise ValueError("text_campaign add requires bidding_strategy.")
    item: dict[str, Any] = {"Name": name}
    expected: dict[str, Any] = {"name": name}
    if "start_date" in spec:
        date = str(spec["start_date"] or "").strip()
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
            raise ValueError("start_date must be YYYY-MM-DD.")
        item["StartDate"] = date
    if "negative_keywords" in spec:
        vals = _direct_safe_clean_string_list(
            spec["negative_keywords"], "negative_keywords", max_items=1000,
            max_item_length=255, allow_empty=True, total_length=20000,
        )
        item["NegativeKeywords"] = {"Items": vals} if vals else None
        expected["negative_keywords"] = vals
    if "excluded_sites" in spec:
        vals = _direct_safe_clean_string_list(
            spec["excluded_sites"], "excluded_sites", max_items=1000,
            max_item_length=255, allow_empty=True,
        )
        item["ExcludedSites"] = {"Items": vals} if vals else None
        expected["excluded_sites"] = vals
    tc: dict[str, Any] = {"BiddingStrategy": _direct_safe_bidding_strategy(spec["bidding_strategy"])}
    expected["bidding_strategy"] = _direct_safe_strategy_public(tc["BiddingStrategy"])
    if "settings" in spec:
        if not isinstance(spec["settings"], dict):
            raise ValueError("settings must be an object.")
        settings = []
        for k, v in spec["settings"].items():
            option = str(k or "").strip().upper()
            if option not in DIRECT_SAFE_TEXT_CAMPAIGN_SETTINGS:
                raise ValueError(f"Unsupported TextCampaign setting: {option}")
            settings.append({"Option": option, "Value": _direct_safe_yes_no(v, option)})
        tc["Settings"] = settings
    if "counter_ids" in spec:
        raw = spec["counter_ids"]
        if not isinstance(raw, list) or len(raw) > 100:
            raise ValueError("counter_ids must be a list of at most 100 IDs.")
        ids = []
        for x in raw:
            i = _direct_safe_positive_id(x, "counter_id")
            if i not in ids:
                ids.append(i)
        tc["CounterIds"] = {"Items": ids} if ids else None
        expected["counter_ids"] = ids
    if "tracking_params" in spec:
        v = _direct_safe_clean_string(spec["tracking_params"], "tracking_params", max_length=1024, allow_empty=True)
        tc["TrackingParams"] = v; expected["tracking_params"] = v
    if "attribution_model" in spec:
        v = str(spec["attribution_model"] or "").strip().upper()
        if v not in DIRECT_SAFE_ATTRIBUTION_MODELS:
            raise ValueError(f"Unsupported attribution_model: {v}")
        tc["AttributionModel"] = v; expected["attribution_model"] = v
    if "priority_goals" in spec:
        goals = _direct_safe_normalize_priority_goals(spec["priority_goals"])
        if goals is not None:
            # Campaign add does not use the update-only Operation marker.
            add_goals = [{k: v for k, v in x.items() if k != "Operation"} for x in goals]
            tc["PriorityGoals"] = {"Items": add_goals}
    item["TextCampaign"] = tc
    return item, expected


def _direct_safe_compile_add(entity: str, spec: dict[str, Any]) -> tuple[str, str, dict[str, Any], dict[str, Any]]:
    entity = str(entity or "").strip().lower().replace("-", "_")
    if not isinstance(spec, dict) or not spec:
        raise ValueError("spec must be a non-empty object.")
    if entity == "text_campaign":
        item, expected = _direct_safe_compile_text_campaign_add(spec)
        return "campaigns", "Campaigns", item, expected
    if entity == "ad_group":
        allowed = {"name", "campaign_id", "region_ids", "negative_keywords", "tracking_params"}
        unknown = set(spec) - allowed
        if unknown:
            raise ValueError(f"Unsupported ad_group add fields: {sorted(unknown)}")
        campaign_id = _direct_safe_positive_id(spec.get("campaign_id"), "campaign_id")
        item = {
            "Name": _direct_safe_clean_string(spec.get("name"), "name", max_length=255),
            "CampaignId": campaign_id,
            "RegionIds": _direct_safe_region_ids(spec.get("region_ids")),
        }
        if "negative_keywords" in spec:
            vals = _direct_safe_clean_string_list(
                spec["negative_keywords"], "negative_keywords", max_items=1000,
                max_item_length=255, allow_empty=True, total_length=20000,
            )
            item["NegativeKeywords"] = {"Items": vals} if vals else None
        if "tracking_params" in spec:
            item["TrackingParams"] = _direct_safe_clean_string(
                spec["tracking_params"], "tracking_params", max_length=1024, allow_empty=True
            )
        expected = {"name": item["Name"], "region_ids": item["RegionIds"], "campaign_id": campaign_id}
        return "adgroups", "AdGroups", item, expected
    if entity == "keyword":
        allowed = {"keyword", "ad_group_id", "user_param1", "user_param2", "autotargeting_settings"}
        unknown = set(spec) - allowed
        if unknown:
            raise ValueError(f"Unsupported keyword add fields: {sorted(unknown)}")
        item = {
            "Keyword": _direct_safe_clean_string(spec.get("keyword"), "keyword", max_length=4096),
            "AdGroupId": _direct_safe_positive_id(spec.get("ad_group_id"), "ad_group_id"),
        }
        for public, api in (("user_param1", "UserParam1"), ("user_param2", "UserParam2")):
            if public in spec:
                item[api] = _direct_safe_clean_string(spec[public], public, max_length=255, allow_empty=True)
        if "autotargeting_settings" in spec:
            if item["Keyword"] != "---autotargeting":
                raise ValueError("autotargeting_settings is allowed only when keyword is ---autotargeting.")
            item["AutotargetingSettings"] = _direct_safe_autotargeting_settings(spec["autotargeting_settings"])
        expected = {"keyword": item["Keyword"], "ad_group_id": item["AdGroupId"]}
        return "keywords", "Keywords", item, expected
    if entity == "text_ad":
        allowed = {
            "ad_group_id", "title", "title2", "text", "href", "mobile", "display_url_path", "sitelink_set_id"
        }
        unknown = set(spec) - allowed
        if unknown:
            raise ValueError(f"Unsupported text_ad add fields: {sorted(unknown)}")
        title = _direct_safe_clean_string(spec.get("title"), "title", max_length=56)
        text_value = _direct_safe_clean_string(spec.get("text"), "text", max_length=81)
        text_ad: dict[str, Any] = {"Title": title, "Text": text_value, "Mobile": _direct_safe_yes_no(spec.get("mobile", False), "mobile")}
        if "title2" in spec:
            text_ad["Title2"] = None if spec["title2"] is None else _direct_safe_clean_string(spec["title2"], "title2", max_length=30, allow_empty=True)
        if "href" in spec:
            href = _direct_safe_clean_string(spec["href"], "href", max_length=1024)
            if not re.match(r"^https?://", href, flags=re.I):
                raise ValueError("href must start with http:// or https://")
            text_ad["Href"] = href
        if "display_url_path" in spec:
            text_ad["DisplayUrlPath"] = _direct_safe_clean_string(spec["display_url_path"], "display_url_path", max_length=20, allow_empty=True)
        if "sitelink_set_id" in spec:
            text_ad["SitelinkSetId"] = _direct_safe_positive_id(spec["sitelink_set_id"], "sitelink_set_id")
        item = {"AdGroupId": _direct_safe_positive_id(spec.get("ad_group_id"), "ad_group_id"), "TextAd": text_ad}
        expected = {"title": title, "text": text_value, "ad_group_id": item["AdGroupId"]}
        return "ads", "Ads", item, expected
    raise ValueError("Unsupported add entity. Allowed: text_campaign, ad_group, keyword, text_ad.")


async def _direct_safe_parent_precheck(entity: str, item: dict[str, Any]) -> None:
    if entity == "ad_group":
        parent = await _direct_safe_get_entity("campaign", int(item["CampaignId"]))
        if not parent:
            raise ValueError("Parent campaign is not accessible to this Direct account.")
    elif entity == "keyword":
        parent = await _direct_safe_get_entity("ad_group", int(item["AdGroupId"]))
        if not parent:
            raise ValueError("Parent ad group is not accessible to this Direct account.")
    elif entity == "text_ad":
        parent = await _direct_safe_get_entity("ad_group", int(item["AdGroupId"]))
        if not parent:
            raise ValueError("Parent ad group is not accessible to this Direct account.")


@mcp.tool(
    title="Preview generic safe Direct add",
    description=(
        "PREVIEW ONLY. Creates one allow-listed TextCampaign, ad group, keyword/autotargeting or "
        "TextAd specification. No raw Direct service/method/payload is accepted. Parent objects are "
        "read-checked before the immutable plan is created."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
async def preview_direct_safe_add(entity: str, spec: dict[str, Any]) -> dict[str, Any]:
    normalized_entity = str(entity or "").strip().lower().replace("-", "_")
    service, list_key, item, expected = _direct_safe_compile_add(normalized_entity, spec)
    await _direct_safe_parent_precheck(normalized_entity, item)
    if normalized_entity == "text_campaign":
        # Prevent accidental duplicate campaign creation by exact name at preview time.
        existing = await _direct_find_campaign_by_name_exact(str(item["Name"]))
        if existing:
            return {
                "ok": False, "preview_only": True, "blocked_by_precondition": True,
                "reason": "exact_name_campaign_exists", "existing": existing,
            }
    payload = {"method": "add", "params": {list_key: [item]}}
    metadata = {
        "scope": DIRECT_SAFE_SCOPE,
        "policy_version": DIRECT_SAFE_POLICY_VERSION,
        "operation": "add",
        "entity": normalized_entity,
        "expected_snapshot": expected,
    }
    preview = _make_marketing_plan("direct", "POST", service, params=metadata, payload=payload)
    preview["safe_write"] = True
    preview["summary"] = {"operation": "add", "entity": normalized_entity, "spec": expected}
    return preview


def _direct_safe_validate_plan_shape(plan: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
    if plan.get("api") != "direct" or plan.get("method") != "POST":
        raise ValueError("Plan is not a Direct safe-write plan.")
    meta = plan.get("params") or {}
    if meta.get("scope") != DIRECT_SAFE_SCOPE or meta.get("policy_version") != DIRECT_SAFE_POLICY_VERSION:
        raise ValueError("Plan is outside the current Direct safe-write policy scope.")
    if not hmac.compare_digest(str(plan.get("sha256") or ""), _marketing_plan_recomputed_sha256(plan)):
        raise ValueError("Direct safe-write plan integrity hash mismatch.")
    operation = str(meta.get("operation") or "")
    entity = str(meta.get("entity") or "")
    payload = plan.get("payload") or {}
    service = str(plan.get("target") or "")
    if operation == "update":
        expected_service = {"campaign": "campaigns", "ad_group": "adgroups", "keyword": "keywords", "text_ad": "ads"}.get(entity)
        list_key = {"campaign": "Campaigns", "ad_group": "AdGroups", "keyword": "Keywords", "text_ad": "Ads"}.get(entity)
        if service != expected_service or payload.get("method") != "update":
            raise ValueError("Safe update plan service/method mismatch.")
        arr = ((payload.get("params") or {}).get(list_key) or [])
        if len(arr) != 1 or int(arr[0].get("Id") or 0) != int(meta.get("entity_id") or 0):
            raise ValueError("Safe update plan object ID mismatch.")
    elif operation == "action":
        expected_service = {"campaign": "campaigns", "keyword": "keywords", "text_ad": "ads"}.get(entity)
        action = str(meta.get("action") or "")
        if service != expected_service or action not in (DIRECT_SAFE_ACTIONS.get(entity) or set()) or payload.get("method") != action:
            raise ValueError("Safe action plan service/action mismatch.")
        payload_ids = (((payload.get("params") or {}).get("SelectionCriteria") or {}).get("Ids") or [])
        if [int(x) for x in payload_ids] != [int(x) for x in (meta.get("entity_ids") or [])]:
            raise ValueError("Safe action plan IDs mismatch.")
    elif operation == "add":
        expected_service = {"text_campaign": "campaigns", "ad_group": "adgroups", "keyword": "keywords", "text_ad": "ads"}.get(entity)
        list_key = {"text_campaign": "Campaigns", "ad_group": "AdGroups", "keyword": "Keywords", "text_ad": "Ads"}.get(entity)
        if service != expected_service or payload.get("method") != "add":
            raise ValueError("Safe add plan service/method mismatch.")
        arr = ((payload.get("params") or {}).get(list_key) or [])
        if len(arr) != 1 or not isinstance(arr[0], dict):
            raise ValueError("Safe add plan must contain exactly one allow-listed object.")
        # Recompile from the immutable API object isn't safe/reliable; validate top-level keys again.
        allowed_keys = {
            "text_campaign": {"Name", "StartDate", "NegativeKeywords", "ExcludedSites", "TextCampaign"},
            "ad_group": {"Name", "CampaignId", "RegionIds", "NegativeKeywords", "TrackingParams"},
            "keyword": {"Keyword", "AdGroupId", "UserParam1", "UserParam2", "AutotargetingSettings"},
            "text_ad": {"AdGroupId", "TextAd"},
        }[entity]
        if not set(arr[0]).issubset(allowed_keys):
            raise ValueError("Safe add plan contains fields outside the allow-list.")
    else:
        raise ValueError("Unknown Direct safe-write operation.")
    return operation, entity, meta


async def _direct_safe_preapply_check(plan: dict[str, Any], operation: str, entity: str, meta: dict[str, Any]) -> None:
    if operation == "update":
        entity_id = int(meta["entity_id"])
        current = await _direct_safe_get_entity(entity, entity_id)
        if not current:
            raise ValueError("Target Direct object disappeared after preview.")
        before = _direct_safe_snapshot(entity, current, list(meta.get("change_keys") or []))
        if not hmac.compare_digest(
            str(meta.get("base_fingerprint") or ""), _direct_safe_fingerprint(before)
        ):
            raise ValueError("Target Direct fields changed after preview; create a fresh preview.")
    elif operation == "action":
        before: dict[str, Any] = {}
        for entity_id in meta.get("entity_ids") or []:
            obj = await _direct_safe_get_entity(entity, int(entity_id))
            if not obj:
                raise ValueError(f"Target Direct object {entity_id} disappeared after preview.")
            before[str(int(entity_id))] = await _direct_safe_state_snapshot(entity, obj)
        if not hmac.compare_digest(
            str(meta.get("base_fingerprint") or ""), _direct_safe_fingerprint(before)
        ):
            raise ValueError("Target Direct object states changed after preview; create a fresh preview.")
    elif operation == "add":
        payload = plan.get("payload") or {}
        list_key = {"text_campaign": "Campaigns", "ad_group": "AdGroups", "keyword": "Keywords", "text_ad": "Ads"}[entity]
        item = (((payload.get("params") or {}).get(list_key)) or [])[0]
        await _direct_safe_parent_precheck(entity, item)
        if entity == "text_campaign":
            existing = await _direct_find_campaign_by_name_exact(str(item["Name"]))
            if existing:
                raise ValueError("A campaign with this exact name appeared after preview; refusing duplicate add.")


def _direct_safe_action_expected(action: str, before: dict[str, Any]) -> bool:
    state = str(before.get("state") or "")
    status = str(before.get("status") or "")
    if action == "suspend":
        return state == "SUSPENDED"
    if action == "resume":
        return state in {"ON", "OFF"} and state != "SUSPENDED"
    if action == "archive":
        return state == "ARCHIVED"
    if action == "unarchive":
        return state != "ARCHIVED"
    if action == "moderate":
        return status in {"MODERATION", "ACCEPTED", "PREACCEPTED"}
    return False


async def _direct_safe_verify_plan(plan: dict[str, Any], operation: str, entity: str, meta: dict[str, Any], applied: Optional[dict[str, Any]]) -> dict[str, Any]:
    if operation == "update":
        entity_id = int(meta["entity_id"])
        obj = await _direct_safe_get_entity(entity, entity_id)
        if not obj:
            return {"verified": False, "reason": "entity_missing_after_write"}
        actual = _direct_safe_snapshot(entity, obj, list(meta.get("change_keys") or []))
        expected = dict(meta.get("expected_snapshot") or {})
        return {"verified": _direct_safe_snapshots_match(actual, expected), "actual": actual, "expected": expected}
    if operation == "action":
        actual: dict[str, Any] = {}
        verified = True
        for entity_id in meta.get("entity_ids") or []:
            obj = await _direct_safe_get_entity(entity, int(entity_id))
            if not obj:
                verified = False
                actual[str(entity_id)] = None
                continue
            snap = await _direct_safe_state_snapshot(entity, obj)
            actual[str(entity_id)] = snap
            if not _direct_safe_action_expected(str(meta.get("action") or ""), snap):
                verified = False
        return {"verified": verified, "actual": actual, "action": meta.get("action")}
    # Add: identify the newly created object from Direct AddResults.
    direct_wrapper = ((applied or {}).get("result") or {}) if isinstance(applied, dict) else {}
    direct_response = (direct_wrapper.get("direct_response") or {}) if isinstance(direct_wrapper, dict) else {}
    direct_result = (direct_response.get("result") or {}) if isinstance(direct_response, dict) else {}
    add_results = direct_result.get("AddResults") or []
    if len(add_results) != 1 or not add_results[0].get("Id"):
        return {"verified": False, "reason": "missing_add_result_id"}
    new_id = int(add_results[0]["Id"])
    read_entity = "campaign" if entity == "text_campaign" else entity
    obj = await _direct_safe_get_entity(read_entity, new_id)
    if not obj:
        return {"verified": False, "reason": "created_entity_not_readable", "created_id": new_id}
    expected = dict(meta.get("expected_snapshot") or {})
    if entity == "text_campaign":
        keys = list(expected)
        actual = _direct_safe_snapshot("campaign", obj, keys)
    elif entity == "ad_group":
        actual = {
            "name": obj.get("Name"), "region_ids": list(obj.get("RegionIds") or []),
            "campaign_id": obj.get("CampaignId"),
        }
    elif entity == "keyword":
        actual = {"keyword": obj.get("Keyword"), "ad_group_id": obj.get("AdGroupId")}
    else:
        actual = {
            "title": (obj.get("TextAd") or {}).get("Title"),
            "text": (obj.get("TextAd") or {}).get("Text"),
            "ad_group_id": obj.get("AdGroupId"),
        }
    return {"verified": _direct_safe_snapshots_match(actual, expected), "created_id": new_id, "actual": actual, "expected": expected}


@mcp.tool(
    title="Apply generic safe Direct plan",
    description=(
        "WRITE. Applies exactly one immutable plan produced by a Direct safe-write preview tool. "
        "The caller can supply only plan_id and confirmation_token; service, method, object IDs and "
        "fields cannot be changed at apply time. Re-checks stale state and performs read-back verification."
    ),
    annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True),
)
async def apply_direct_safe_write(
    plan_id: Annotated[str, Field(min_length=1, max_length=120)],
    confirmation_token: Annotated[str, Field(min_length=1, max_length=256)],
) -> dict[str, Any]:
    store = _prune_marketing_plans(_load_marketing_plan_store())
    plan = store.get(plan_id)
    if not plan:
        raise ValueError("Direct safe-write plan not found or expired.")
    operation, entity, meta = _direct_safe_validate_plan_shape(plan)
    if float(plan.get("expires_at") or 0) <= time.time():
        raise ValueError("Direct safe-write plan has expired.")
    if plan.get("state") != "pending" or plan.get("used"):
        raise ValueError(f"Direct safe-write plan is not pending; state={plan.get('state')}.")
    await _direct_safe_preapply_check(plan, operation, entity, meta)
    try:
        applied = await _apply_confirmed_marketing_plan(
            plan_id, confirmation_token, required_api="direct"
        )
    except Exception:
        # Never auto-retry an ambiguous write. Read back once; if intended state is present,
        # return a verified success instead of sending the mutation twice.
        verification = await _direct_safe_verify_plan(plan, operation, entity, meta, None)
        if verification.get("verified"):
            _record_marketing_plan_postcheck(
                plan_id, "direct_safe_verified_after_ambiguous_error",
                operation=operation, entity=entity,
            )
            return {
                "ok": True,
                "applied": True,
                "applied_state": "verified_after_ambiguous_error",
                "safe_write": True,
                "operation": operation,
                "entity": entity,
                "post_write_verified": True,
                "verification": verification,
                "warning": "Write response was ambiguous; no retry was performed. Read-back matched the intended state.",
            }
        raise
    verification = await _direct_safe_verify_plan(plan, operation, entity, meta, applied)
    verified = bool(verification.get("verified"))
    _record_marketing_plan_postcheck(
        plan_id, "direct_safe_post_write_verification",
        operation=operation, entity=entity, verified=verified,
    )
    return {
        "ok": verified,
        "applied": True,
        "safe_write": True,
        "policy_version": DIRECT_SAFE_POLICY_VERSION,
        "operation": operation,
        "entity": entity,
        "post_write_verified": verified,
        "verification": verification,
        "direct_result": applied,
    }


async def _direct_find_campaign_by_name_exact(name: str) -> list[dict[str, Any]]:
    """READ-ONLY pre/post-condition helper. Exact name match only."""
    response = await _direct_request(
        "campaigns",
        {
            "method": "get",
            "params": {
                "SelectionCriteria": {},
                "FieldNames": ["Id", "Name", "State", "Status", "Type"],
            },
        },
    )
    data = _parse_direct_json(response, operation="campaigns.get fixed-operation verification")
    campaigns = ((data.get("result") or {}).get("Campaigns") or [])
    return [c for c in campaigns if str(c.get("Name") or "") == name]


def _marketing_plan_recomputed_sha256(plan: dict[str, Any]) -> str:
    canonical = json.dumps(
        {
            "api": plan.get("api"),
            "method": plan.get("method"),
            "target": plan.get("target"),
            "params": plan.get("params") or {},
            "payload": plan.get("payload"),
            "content_base64": plan.get("content_base64"),
            "content_type": plan.get("content_type"),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return _sha256_bytes(canonical.encode("utf-8"))


def _record_marketing_plan_postcheck(plan_id: str, event: str, **data: Any) -> None:
    with _MARKETING_PLAN_LOCK:
        store = _load_marketing_plan_store()
        plan = store.get(plan_id)
        if not plan:
            return
        _marketing_audit_event(plan, event, **data)
        store[plan_id] = plan
        _save_marketing_plan_store(store)



YALTA_SEARCH_CAMPAIGN_ID = 710957838
YALTA_RSYA_CAMPAIGN_ID = 710989135
YALTA_SEARCH_KITCHEN_GROUP_ID = 5765010118
YALTA_RSYA_KITCHEN_GROUP_ID = 5765233585
YALTA_SEARCH_AUTOTARGETING_ID = 205765010118
YALTA_RSYA_AUTOTARGETING_ID = 205765233585
YALTA_SEARCH_KITCHEN_AD_ID = 17761831376
# Intentionally hard-coded server-side: this Direct ad ID is larger than JS Number.MAX_SAFE_INTEGER.
YALTA_RSYA_WORKING_AD_ID = 1916320049195790898


def _yalta_campaign_id(kind: str) -> int:
    value = str(kind or "").strip().lower()
    if value in {"search", "поиск"}:
        return YALTA_SEARCH_CAMPAIGN_ID
    if value in {"rsya", "рся", "network"}:
        return YALTA_RSYA_CAMPAIGN_ID
    raise ValueError("campaign must be 'search' or 'rsya'.")


async def _yalta_campaign_get(campaign_id: int) -> Optional[dict[str, Any]]:
    response = await _direct_request(
        "campaigns",
        {
            "method": "get",
            "params": {
                "SelectionCriteria": {"Ids": [int(campaign_id)]},
                "FieldNames": [
                    "Id", "Name", "State", "Status", "Type", "StartDate",
                    "NegativeKeywords", "ExcludedSites",
                ],
                "TextCampaignFieldNames": [
                    "BiddingStrategy", "CounterIds", "PriorityGoals",
                    "AttributionModel", "Settings", "TrackingParams",
                ],
            },
        },
    )
    data = _parse_direct_json(response, operation="campaigns.get yalta fixed scope")
    campaigns = ((data.get("result") or {}).get("Campaigns") or [])
    return campaigns[0] if campaigns else None


async def _yalta_groups_get() -> list[dict[str, Any]]:
    response = await _direct_request(
        "adgroups",
        {
            "method": "get",
            "params": {
                "SelectionCriteria": {
                    "CampaignIds": [YALTA_SEARCH_CAMPAIGN_ID, YALTA_RSYA_CAMPAIGN_ID]
                },
                "FieldNames": [
                    "Id", "CampaignId", "Status", "ServingStatus", "Name",
                    "RegionIds", "NegativeKeywords", "TrackingParams",
                ],
            },
        },
    )
    data = _parse_direct_json(response, operation="adgroups.get yalta fixed scope")
    return ((data.get("result") or {}).get("AdGroups") or [])


async def _yalta_kitchen_keywords_get() -> list[dict[str, Any]]:
    response = await _direct_request(
        "keywords",
        {
            "method": "get",
            "params": {
                "SelectionCriteria": {
                    "AdGroupIds": [YALTA_SEARCH_KITCHEN_GROUP_ID, YALTA_RSYA_KITCHEN_GROUP_ID]
                },
                "FieldNames": [
                    "Id", "Keyword", "AdGroupId", "CampaignId", "State", "Status",
                ],
            },
        },
    )
    data = _parse_direct_json(response, operation="keywords.get yalta kitchen groups")
    return ((data.get("result") or {}).get("Keywords") or [])


async def _yalta_ads_get() -> list[dict[str, Any]]:
    response = await _direct_request(
        "ads",
        {
            "method": "get",
            "params": {
                "SelectionCriteria": {
                    "CampaignIds": [YALTA_SEARCH_CAMPAIGN_ID, YALTA_RSYA_CAMPAIGN_ID]
                },
                "FieldNames": ["Id", "AdGroupId", "CampaignId", "State", "Status", "Type"],
                "TextAdFieldNames": [
                    "Title", "Title2", "Text", "Href", "DisplayUrlPath", "SitelinkSetId",
                ],
            },
        },
    )
    data = _parse_direct_json(response, operation="ads.get yalta fixed scope")
    return ((data.get("result") or {}).get("Ads") or [])


async def _yalta_fixed_action_preview(
    entity: str,
    action: str,
    entity_ids: list[int],
    *,
    fixed_operation: str,
) -> dict[str, Any]:
    entity = _direct_safe_entity(entity)
    action = str(action or "").strip().lower()
    allowed_actions = DIRECT_SAFE_ACTIONS.get(entity) or set()
    if action not in allowed_actions:
        raise ValueError(
            f"Action {action!r} is not allowed for {entity}; allowed={sorted(allowed_actions)}"
        )
    ids: list[int] = []
    before: dict[str, Any] = {}
    for raw in entity_ids:
        entity_id = _direct_safe_positive_id(raw, "entity_id")
        if entity_id in ids:
            continue
        obj = await _direct_safe_get_entity(entity, entity_id)
        if not obj:
            return {
                "ok": False,
                "preview_only": True,
                "blocked_by_precondition": True,
                "reason": "entity_missing",
                "entity": entity,
                "entity_id": str(entity_id),
                "fixed_operation": fixed_operation,
            }
        ids.append(entity_id)
        before[str(entity_id)] = await _direct_safe_state_snapshot(entity, obj)

    service = {"campaign": "campaigns", "keyword": "keywords", "text_ad": "ads"}[entity]
    payload = {"method": action, "params": {"SelectionCriteria": {"Ids": ids}}}
    metadata = {
        "scope": DIRECT_SAFE_SCOPE,
        "policy_version": DIRECT_SAFE_POLICY_VERSION,
        "operation": "action",
        "entity": entity,
        "action": action,
        "entity_ids": ids,
        "base_fingerprint": _direct_safe_fingerprint(before),
        "fixed_operation": fixed_operation,
        "fixed_campaign_scope": "yalta",
    }
    preview = _make_marketing_plan(
        "direct", "POST", service, params=metadata, payload=payload
    )
    preview["safe_write"] = True
    preview["policy_version"] = DIRECT_SAFE_POLICY_VERSION
    preview["fixed_operation"] = fixed_operation
    preview["fixed_campaign_scope"] = "yalta"
    preview["summary"] = {
        "operation": "action",
        "entity": entity,
        "action": action,
        "ids": [str(x) if x > 9007199254740991 else x for x in ids],
        "current": before,
    }
    return preview


def _yalta_clean_phrases(
    items: list[str],
    *,
    argument_name: str,
    allow_empty: bool,
    max_items: int = 1000,
) -> list[str]:
    return _direct_safe_clean_string_list(
        items,
        argument_name,
        max_items=max_items,
        max_item_length=255,
        allow_empty=allow_empty,
        total_length=20000,
    )


def _yalta_site_key(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip()).casefold()


@mcp.tool(
    title="Yalta Direct protected scope",
    description=(
        "READ-ONLY. Returns the fixed Yalta Direct campaign/group/object IDs protected by this "
        "gateway. No write is performed."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False),
)
async def yalta_direct_scope() -> dict[str, Any]:
    return {
        "ok": True,
        "search_campaign": {"id": YALTA_SEARCH_CAMPAIGN_ID, "name": "Поиск"},
        "rsya_campaign": {"id": YALTA_RSYA_CAMPAIGN_ID, "name": "РСЯ"},
        "search_kitchen_group_id": YALTA_SEARCH_KITCHEN_GROUP_ID,
        "rsya_kitchen_group_id": YALTA_RSYA_KITCHEN_GROUP_ID,
        "search_autotargeting_id": YALTA_SEARCH_AUTOTARGETING_ID,
        "rsya_autotargeting_id": YALTA_RSYA_AUTOTARGETING_ID,
        "search_kitchen_ad_id": YALTA_SEARCH_KITCHEN_AD_ID,
        "rsya_working_ad_id": str(YALTA_RSYA_WORKING_AD_ID),
        "write_workflow": "preview -> immutable plan -> explicit confirmation -> apply_direct_safe_write -> read-back verification",
    }


@mcp.tool(
    title="Yalta Direct status",
    description=(
        "READ-ONLY. Returns current state for the fixed Yalta Search 710957838 and RSYA 710989135 "
        "campaigns, their groups, Kitchen-group keywords/autotargeting and ads."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
async def yalta_direct_status() -> dict[str, Any]:
    search = await _yalta_campaign_get(YALTA_SEARCH_CAMPAIGN_ID)
    rsya = await _yalta_campaign_get(YALTA_RSYA_CAMPAIGN_ID)
    groups = await _yalta_groups_get()
    keywords = await _yalta_kitchen_keywords_get()
    ads = await _yalta_ads_get()

    def _campaign_summary(c: Optional[dict[str, Any]]) -> Optional[dict[str, Any]]:
        if not c:
            return None
        tc = c.get("TextCampaign") or {}
        return {
            "Id": c.get("Id"),
            "Name": c.get("Name"),
            "State": c.get("State"),
            "Status": c.get("Status"),
            "Type": c.get("Type"),
            "NegativeKeywords": c.get("NegativeKeywords"),
            "ExcludedSites": c.get("ExcludedSites"),
            "BiddingStrategy": tc.get("BiddingStrategy"),
            "CounterIds": tc.get("CounterIds"),
            "PriorityGoals": tc.get("PriorityGoals"),
            "AttributionModel": tc.get("AttributionModel"),
            "TrackingParams": tc.get("TrackingParams"),
        }

    search_keywords = [
        x for x in keywords if int(x.get("AdGroupId") or 0) == YALTA_SEARCH_KITCHEN_GROUP_ID
    ]
    rsya_keywords = [
        x for x in keywords if int(x.get("AdGroupId") or 0) == YALTA_RSYA_KITCHEN_GROUP_ID
    ]
    return {
        "ok": True,
        "search": _campaign_summary(search),
        "rsya": _campaign_summary(rsya),
        "groups": groups,
        "search_kitchen": {
            "group_id": YALTA_SEARCH_KITCHEN_GROUP_ID,
            "keywords": search_keywords,
            "autotargeting": next(
                (x for x in search_keywords if int(x.get("Id") or 0) == YALTA_SEARCH_AUTOTARGETING_ID),
                None,
            ),
            "ad": next(
                (x for x in ads if int(x.get("Id") or 0) == YALTA_SEARCH_KITCHEN_AD_ID),
                None,
            ),
        },
        "rsya_kitchen": {
            "group_id": YALTA_RSYA_KITCHEN_GROUP_ID,
            "keywords": rsya_keywords,
            "autotargeting": next(
                (x for x in rsya_keywords if int(x.get("Id") or 0) == YALTA_RSYA_AUTOTARGETING_ID),
                None,
            ),
            "working_ad": next(
                (x for x in ads if int(x.get("Id") or 0) == YALTA_RSYA_WORKING_AD_ID),
                None,
            ),
        },
    }


@mcp.tool(
    title="Preview Yalta Search campaign action",
    description=(
        "PREVIEW ONLY. Suspends or resumes only Yalta Search campaign 710957838. "
        "The campaign ID is fixed server-side."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
async def preview_yalta_search_campaign_action(action: str) -> dict[str, Any]:
    action = str(action or "").strip().lower()
    if action not in {"suspend", "resume"}:
        raise ValueError("action must be suspend or resume.")
    return await _yalta_fixed_action_preview(
        "campaign", action, [YALTA_SEARCH_CAMPAIGN_ID],
        fixed_operation=f"yalta_search_campaign_{action}_v1",
    )


@mcp.tool(
    title="Preview Yalta RSYA campaign action",
    description=(
        "PREVIEW ONLY. Suspends or resumes only Yalta RSYA campaign 710989135. "
        "The campaign ID is fixed server-side."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
async def preview_yalta_rsya_campaign_action(action: str) -> dict[str, Any]:
    action = str(action or "").strip().lower()
    if action not in {"suspend", "resume"}:
        raise ValueError("action must be suspend or resume.")
    return await _yalta_fixed_action_preview(
        "campaign", action, [YALTA_RSYA_CAMPAIGN_ID],
        fixed_operation=f"yalta_rsya_campaign_{action}_v1",
    )


@mcp.tool(
    title="Preview Yalta Search campaign negatives",
    description=(
        "PREVIEW ONLY. Replaces campaign-level negative keywords only for fixed Yalta Search "
        "campaign 710957838. Uses the generic Direct safe-write plan and apply_direct_safe_write."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
async def preview_set_yalta_search_campaign_negatives(
    negative_keywords: list[str],
) -> dict[str, Any]:
    cleaned = _yalta_clean_phrases(
        negative_keywords, argument_name="negative_keywords", allow_empty=True
    )
    preview = await _direct_safe_preview_update_internal(
        "campaign",
        YALTA_SEARCH_CAMPAIGN_ID,
        {"negative_keywords": cleaned},
    )
    if isinstance(preview, dict):
        preview["fixed_campaign_scope"] = "yalta_search_710957838"
    return preview


@mcp.tool(
    title="Read Yalta RSYA excluded sites",
    description=(
        "READ-ONLY. Returns ExcludedSites only for fixed Yalta RSYA campaign 710989135."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
async def get_yalta_rsya_excluded_sites() -> dict[str, Any]:
    campaign = await _yalta_campaign_get(YALTA_RSYA_CAMPAIGN_ID)
    if not campaign:
        return {
            "ok": False,
            "reason": "campaign_missing",
            "campaign_id": YALTA_RSYA_CAMPAIGN_ID,
        }
    items = ((campaign.get("ExcludedSites") or {}).get("Items") or [])
    cleaned = _yalta_clean_phrases(
        items, argument_name="current ExcludedSites.Items", allow_empty=True
    )
    return {
        "ok": True,
        "campaign_id": YALTA_RSYA_CAMPAIGN_ID,
        "excluded_sites": cleaned,
        "count": len(cleaned),
    }


@mcp.tool(
    title="Preview set Yalta RSYA excluded sites",
    description=(
        "PREVIEW ONLY. Replaces ExcludedSites only for fixed Yalta RSYA campaign 710989135. "
        "An empty list safely clears ExcludedSites."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
async def preview_set_yalta_rsya_excluded_sites(
    excluded_sites: list[str],
) -> dict[str, Any]:
    cleaned = _yalta_clean_phrases(
        excluded_sites, argument_name="excluded_sites", allow_empty=True
    )
    preview = await _direct_safe_preview_update_internal(
        "campaign",
        YALTA_RSYA_CAMPAIGN_ID,
        {"excluded_sites": cleaned},
    )
    if isinstance(preview, dict):
        preview["fixed_campaign_scope"] = "yalta_rsya_710989135"
        preview["mode"] = "set"
    return preview


@mcp.tool(
    title="Preview add Yalta RSYA excluded sites",
    description=(
        "PREVIEW ONLY. Adds specified sites/apps/SSPs to ExcludedSites for fixed Yalta RSYA "
        "campaign 710989135 while preserving the current list."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
async def preview_add_yalta_rsya_excluded_sites(sites: list[str]) -> dict[str, Any]:
    additions = _yalta_clean_phrases(sites, argument_name="sites", allow_empty=False)
    current_result = await get_yalta_rsya_excluded_sites()
    if not current_result.get("ok"):
        return {**current_result, "preview_only": True}
    current = list(current_result.get("excluded_sites") or [])
    seen = {_yalta_site_key(x) for x in current}
    proposed = list(current)
    for value in additions:
        key = _yalta_site_key(value)
        if key not in seen:
            seen.add(key)
            proposed.append(value)
    if len(proposed) > 1000:
        raise ValueError("Result would exceed Direct limit of 1000 excluded sites.")
    preview = await _direct_safe_preview_update_internal(
        "campaign",
        YALTA_RSYA_CAMPAIGN_ID,
        {"excluded_sites": proposed},
    )
    if isinstance(preview, dict):
        preview["fixed_campaign_scope"] = "yalta_rsya_710989135"
        preview["mode"] = "add"
        preview["added"] = [x for x in proposed if _yalta_site_key(x) not in {_yalta_site_key(y) for y in current}]
    return preview


@mcp.tool(
    title="Preview remove Yalta RSYA excluded sites",
    description=(
        "PREVIEW ONLY. Removes only specified sites/apps/SSPs from ExcludedSites for fixed "
        "Yalta RSYA campaign 710989135 while preserving all other exclusions."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
async def preview_remove_yalta_rsya_excluded_sites(sites: list[str]) -> dict[str, Any]:
    removals = _yalta_clean_phrases(sites, argument_name="sites", allow_empty=False)
    current_result = await get_yalta_rsya_excluded_sites()
    if not current_result.get("ok"):
        return {**current_result, "preview_only": True}
    current = list(current_result.get("excluded_sites") or [])
    remove_keys = {_yalta_site_key(x) for x in removals}
    proposed = [x for x in current if _yalta_site_key(x) not in remove_keys]
    preview = await _direct_safe_preview_update_internal(
        "campaign",
        YALTA_RSYA_CAMPAIGN_ID,
        {"excluded_sites": proposed},
    )
    if isinstance(preview, dict):
        preview["fixed_campaign_scope"] = "yalta_rsya_710989135"
        preview["mode"] = "remove"
        preview["removed"] = [x for x in current if _yalta_site_key(x) in remove_keys]
    return preview


@mcp.tool(
    title="Preview Yalta RSYA autotargeting action",
    description=(
        "PREVIEW ONLY. Suspends or resumes only the fixed Yalta RSYA Kitchen autotargeting "
        "criterion 205765233585."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
async def preview_yalta_rsya_autotargeting_action(action: str) -> dict[str, Any]:
    action = str(action or "").strip().lower()
    if action not in {"suspend", "resume"}:
        raise ValueError("action must be suspend or resume.")
    return await _yalta_fixed_action_preview(
        "keyword", action, [YALTA_RSYA_AUTOTARGETING_ID],
        fixed_operation=f"yalta_rsya_autotargeting_{action}_v1",
    )


@mcp.tool(
    title="Preview Yalta Search autotargeting settings",
    description=(
        "PREVIEW ONLY. Updates only AutotargetingSettings of the fixed Yalta Search Kitchen "
        "autotargeting criterion 205765010118. It does not suspend the search autotargeting object."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
async def preview_yalta_search_autotargeting_settings(
    autotargeting_settings: dict[str, Any],
) -> dict[str, Any]:
    preview = await _direct_safe_preview_update_internal(
        "keyword",
        YALTA_SEARCH_AUTOTARGETING_ID,
        {"autotargeting_settings": autotargeting_settings},
    )
    if isinstance(preview, dict):
        preview["fixed_campaign_scope"] = "yalta_search_710957838"
    return preview


@mcp.tool(
    title="Preview Yalta Search Kitchen ad action",
    description=(
        "PREVIEW ONLY. Applies suspend/resume/moderate only to fixed Yalta Search Kitchen ad "
        "17761831376."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
async def preview_yalta_search_kitchen_ad_action(action: str) -> dict[str, Any]:
    action = str(action or "").strip().lower()
    if action not in {"suspend", "resume", "moderate"}:
        raise ValueError("action must be suspend, resume or moderate.")
    return await _yalta_fixed_action_preview(
        "text_ad", action, [YALTA_SEARCH_KITCHEN_AD_ID],
        fixed_operation=f"yalta_search_kitchen_ad_{action}_v1",
    )


@mcp.tool(
    title="Preview Yalta RSYA working ad action",
    description=(
        "PREVIEW ONLY. Applies suspend/resume/moderate only to the fixed working Yalta RSYA ad "
        "1916320049195790898. The large Direct ID is stored server-side to avoid JavaScript "
        "integer rounding."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True),
)
async def preview_yalta_rsya_working_ad_action(action: str) -> dict[str, Any]:
    action = str(action or "").strip().lower()
    if action not in {"suspend", "resume", "moderate"}:
        raise ValueError("action must be suspend, resume or moderate.")
    return await _yalta_fixed_action_preview(
        "text_ad", action, [YALTA_RSYA_WORKING_AD_ID],
        fixed_operation=f"yalta_rsya_working_ad_{action}_v1",
    )


@mcp.tool(
    title="Marketing plan diagnostics",
    description=(
        "READ-ONLY diagnostics for recent Yandex Direct/Metrica preview/apply plans. "
        "Returns state, expiry, operation hash and safe event history; never returns "
        "OAuth secrets or confirmation tokens and cannot execute a plan."
    ),
    annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False),
)
async def marketing_plan_diagnostics(
    plan_id: Optional[str] = None,
    limit: Annotated[int, Field(ge=1, le=50)] = 20,
) -> dict[str, Any]:
    store = _prune_marketing_plans(_load_marketing_plan_store())
    items = []
    for pid, plan in store.items():
        if plan_id and pid != plan_id:
            continue
        items.append({
            "plan_id": pid,
            "api": plan.get("api"),
            "method": plan.get("method"),
            "target": plan.get("target"),
            "operation_sha256": plan.get("sha256"),
            "state": plan.get("state"),
            "used": bool(plan.get("used")),
            "created_at": plan.get("created_at"),
            "expires_at": plan.get("expires_at"),
            "terminal_at": plan.get("terminal_at"),
            "result_summary": plan.get("result_summary"),
            "events": plan.get("events", []),
        })
    items.sort(key=lambda x: float(x.get("created_at") or 0), reverse=True)
    return {
        "ok": True,
        "plan_store": "durable_atomic_file",
        "plan_ttl_seconds": MARKETING_PLAN_TTL_SECONDS,
        "history_seconds": MARKETING_PLAN_HISTORY_SECONDS,
        "items": items[:limit],
    }


async def _apply_confirmed_direct_write_internal(
    plan_id: Annotated[str, Field(min_length=1, max_length=120, description="Opaque immutable Direct plan id returned by preview_direct_write.")],
    confirmation_token: Annotated[str, Field(min_length=1, max_length=256, description="One-time token for this exact Direct preview after explicit user approval.")],
) -> Any:
    return await _apply_confirmed_marketing_plan(
        plan_id, confirmation_token, required_api="direct"
    )


async def _apply_confirmed_metrika_write_internal(
    plan_id: Annotated[str, Field(min_length=1, max_length=120, description="Opaque immutable Metrica plan id returned by preview_metrika_write.")],
    confirmation_token: Annotated[str, Field(min_length=1, max_length=256, description="One-time token for this exact Metrica preview after explicit user approval.")],
) -> Any:
    return await _apply_confirmed_marketing_plan(
        plan_id, confirmation_token, required_api="metrika"
    )


@mcp.tool()
async def bridge_health() -> dict[str, Any]:
    """Проверить публичный статус WordPress Bridge без выполнения изменений."""
    return await _wp("GET", f"{NS}/health", signed=False)


@mcp.tool()
async def get_site_info() -> dict[str, Any]:
    """Прочитать основные сведения WordPress, PHP и активной темы."""
    result = await _wp("GET", f"{NS}/site/info")
    return result["data"]


@mcp.tool()
async def list_plugins() -> dict[str, Any]:
    """Получить список плагинов WordPress и их статус."""
    result = await _wp("GET", f"{NS}/plugins")
    return result["data"]


@mcp.tool(
    title="List allowed WordPress theme files",
    description=(
        "List existing files that the WordPress Bridge permits for theme-file reads. "
        "READ-ONLY: this operation does not create, modify, delete, execute, or write "
        "WordPress files, database records, settings, or external resources."
    ),
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
async def list_theme_files() -> dict[str, Any]:
    result = await _wp("GET", f"{NS}/theme/files")
    return result["data"]


@mcp.tool(
    title="Read allowed WordPress theme file",
    description=(
        "Read and return the contents of one existing allow-listed text/source file "
        "inside the configured active or parent WordPress theme. READ-ONLY: the tool "
        "uses an HTTP GET request and does not create, modify, replace, patch, delete, "
        "rename, upload, execute, or evaluate files or PHP code; it does not change the "
        "WordPress database, options, configuration, cache, or any external resource. "
        "The caller supplies only a relative theme path. The gateway rejects absolute "
        "paths, '..' traversal, backslashes, secret/config filenames, and non-text "
        "extensions; the WordPress endpoint must independently enforce canonical-path "
        "containment within its allow-listed theme roots."
    ),
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
async def read_theme_file(
    path: ThemeRelativePath,
    start_line: Annotated[int, Field(ge=1, description="1-based first source line to return.")] = 1,
    max_lines: Annotated[int, Field(ge=1, le=MAX_READ_MAX_LINES, description="Maximum source lines to return in this chunk.")] = DEFAULT_READ_MAX_LINES,
) -> dict[str, Any]:
    safe_path = _validate_theme_relative_path(path)
    result = await _wp("GET", f"{NS}/theme/file", params={"path": safe_path})
    return _bounded_text_result(
        result["data"],
        start_line=start_line,
        max_lines=max_lines,
    )


@mcp.tool(
    title="Read About page template",
    description=(
        "Read the current WordPress theme file template-o-nas.php only. "
        "READ-ONLY: this tool has no arguments, uses a fixed allow-listed relative path, "
        "performs only an HTTP GET request, and cannot select, create, modify, replace, "
        "patch, delete, rename, upload, execute, or evaluate any file or PHP code. "
        "It does not change WordPress content, database records, options, settings, cache, "
        "configuration, or any external resource."
    ),
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
async def read_about_template(
    start_line: Annotated[int, Field(ge=1, description="1-based first source line to return.")] = 1,
    max_lines: Annotated[int, Field(ge=1, le=MAX_READ_MAX_LINES, description="Maximum source lines to return in this chunk.")] = DEFAULT_READ_MAX_LINES,
) -> dict[str, Any]:
    """Read a lossless line window from template-o-nas.php only."""
    fixed_path = "template-o-nas.php"
    result = await _wp("GET", f"{NS}/theme/file", params={"path": fixed_path})
    return _bounded_text_result(
        result["data"],
        start_line=start_line,
        max_lines=max_lines,
    )


@mcp.tool()
async def list_content(
    post_type: str = "any",
    search: str = "",
    page: int = 1,
    per_page: int = 20,
) -> dict[str, Any]:
    """Найти/получить страницы и записи WordPress."""
    params = {
        "post_type": post_type,
        "search": search,
        "page": page,
        "per_page": per_page,
    }
    result = await _wp("GET", f"{NS}/content", params=params)
    return result["data"]


@mcp.tool()
async def get_content(content_id: int) -> dict[str, Any]:
    """Прочитать конкретную страницу/запись, включая ACF при наличии."""
    result = await _wp("GET", f"{NS}/content/{content_id}")
    return result["data"]


@mcp.tool()
async def get_theme_mods() -> dict[str, Any]:
    """Прочитать безопасные theme_mod настройки активной темы."""
    result = await _wp("GET", f"{NS}/theme-mods")
    return result["data"]


@mcp.tool()
async def get_menus() -> dict[str, Any]:
    """Прочитать меню WordPress и пункты меню."""
    result = await _wp("GET", f"{NS}/menus")
    return result["data"]


@mcp.tool()
async def get_audit_log(limit: int = 50) -> dict[str, Any]:
    """Прочитать журнал действий Я Мебель Bridge."""
    result = await _wp("GET", f"{NS}/audit", params={"limit": limit})
    return result["data"]


@mcp.tool()
async def list_backups(limit: int = 50) -> dict[str, Any]:
    """Получить список резервных копий, созданных Bridge."""
    result = await _wp("GET", f"{NS}/backups", params={"limit": limit})
    return result["data"]


@mcp.tool()
async def preview_theme_file_update(
    path: str,
    expected_sha256: str,
    content_base64: str,
) -> dict[str, Any]:
    """ТОЛЬКО PREVIEW изменения существующего файла темы. Ничего не записывает."""
    safe_path = _validate_theme_relative_path(path)
    safe_sha256 = _validate_sha256_hex(expected_sha256)
    payload = {
        "path": safe_path,
        "expected_sha256": safe_sha256,
        "content_base64": content_base64,
    }
    result = await _wp("POST", f"{NS}/theme/file/preview", payload=payload)
    return result["data"]


@mcp.tool()
async def preview_theme_file_patch(
    path: str,
    expected_sha256: str,
    search_base64: str,
    replacement_base64: str,
    expected_occurrences: int = 1,
) -> dict[str, Any]:
    """ТОЛЬКО PREVIEW точечной замены фрагмента файла темы. Ничего не записывает."""
    safe_path = _validate_theme_relative_path(path)
    safe_sha256 = _validate_sha256_hex(expected_sha256)
    if expected_occurrences < 1:
        raise ValueError("expected_occurrences must be >= 1.")
    payload = {
        "path": safe_path,
        "expected_sha256": safe_sha256,
        "search_base64": search_base64,
        "replace_base64": replacement_base64,
        "expected_occurrences": expected_occurrences,
    }
    result = await _wp("POST", f"{NS}/theme/file/patch/preview", payload=payload)
    return result["data"]


@mcp.tool(
    title="Preview fixed About-page trust slider repair",
    description=(
        "Prepare one fixed, predefined repair for the About page trust-review slider. "
        "The caller can provide only the current SHA-256 of template-o-nas.php. The file path, "
        "search fragment, PHP, JavaScript, and replacement content are hard-coded in this gateway; "
        "the caller cannot supply or alter code. PREVIEW ONLY: this creates an immutable server-side "
        "plan and does not write the theme file."
    ),
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=False,
    ),
)
async def preview_about_trust_slider_fix(
    expected_sha256: Annotated[
        str,
        Field(
            min_length=64,
            max_length=64,
            description="Current SHA-256 of template-o-nas.php before preparing the fixed slider repair.",
        ),
    ],
) -> dict[str, Any]:
    """Prepare the fixed review-slider repair without accepting arbitrary path or code input."""
    search = '            <div class="ymb-trust__dots" aria-hidden="true"><span class="is-active"></span><span></span><span></span><span></span><span></span></div>'

    replacement = r'''<?php
        $trust_reviews = [];
        if (isset($reviews) && is_array($reviews)) {
            foreach ($reviews as $review) {
                if (!is_array($review)) {
                    continue;
                }

                $review_text = trim((string) ($review['review_text'] ?? ''));
                if ($review_text === '') {
                    continue;
                }

                $trust_reviews[] = [
                    'text' => $review_text,
                    'name' => trim((string) ($review['review_name'] ?? '')),
                    'city' => trim((string) ($review['review_city'] ?? '')),
                ];
            }
        }

        $trust_dots_count = max(1, count($trust_reviews));
        ?>
        <div class="ymb-trust__dots" aria-hidden="true">
            <?php for ($trust_dot_index = 0; $trust_dot_index < $trust_dots_count; $trust_dot_index++) : ?>
                <span<?php echo $trust_dot_index === 0 ? ' class="is-active"' : ''; ?>></span>
            <?php endfor; ?>
        </div>

        <?php if (count($trust_reviews) > 1) : ?>
            <script>
            (() => {
                const reviews = <?php echo wp_json_encode(
                    $trust_reviews,
                    JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
                ); ?>;
                const section = document.querySelector('.ymb-trust');
                if (!section || !Array.isArray(reviews) || reviews.length < 2) {
                    return;
                }

                const slider = section.querySelector('.ymb-trust__slider');
                const card = section.querySelector('.ymb-trust__card');
                const text = card ? card.querySelector('p') : null;
                const arrows = slider ? slider.querySelectorAll('.ymb-trust__arrow') : [];
                const dots = section.querySelectorAll('.ymb-trust__dots span');

                if (!slider || !card || !text || arrows.length < 2) {
                    return;
                }

                let author = card.querySelector('.ymb-trust__author');
                let currentIndex = 0;

                const renderReview = (index) => {
                    const review = reviews[index];
                    if (!review) {
                        return;
                    }

                    text.textContent = review.text || '';
                    const authorText = [review.name, review.city].filter(Boolean).join(', ');

                    if (authorText) {
                        if (!author) {
                            author = document.createElement('div');
                            author.className = 'ymb-trust__author';
                            card.appendChild(author);
                        }
                        author.textContent = authorText;
                    } else if (author) {
                        author.textContent = '';
                    }

                    dots.forEach((dot, dotIndex) => {
                        dot.classList.toggle('is-active', dotIndex === index);
                    });
                };

                arrows[0].addEventListener('click', () => {
                    currentIndex = (currentIndex - 1 + reviews.length) % reviews.length;
                    renderReview(currentIndex);
                });

                arrows[1].addEventListener('click', () => {
                    currentIndex = (currentIndex + 1) % reviews.length;
                    renderReview(currentIndex);
                });
            })();
            </script>
        <?php endif; ?>'''

    payload = {
        "path": "template-o-nas.php",
        "expected_sha256": _validate_sha256_hex(expected_sha256),
        "search_base64": base64.b64encode(search.encode("utf-8")).decode("ascii"),
        "replace_base64": base64.b64encode(replacement.encode("utf-8")).decode("ascii"),
        "expected_occurrences": 1,
    }
    result = await _wp("POST", f"{NS}/theme/file/patch/preview", payload=payload)
    return result["data"]


@mcp.tool(
    title="Apply confirmed WordPress theme patch",
    description=(
        "Apply exactly one previously prepared and user-confirmed immutable theme-file plan. "
        "This tool cannot choose a file path, cannot supply PHP/CSS/JS content, cannot create a "
        "new patch, and cannot change the prepared operation. It accepts only the server-issued "
        "plan identifier and the matching confirmation token returned by a prior preview call. "
        "The WordPress Bridge must revalidate the plan, current file SHA, expiry, confirmation "
        "token, backup policy, and syntax checks before writing."
    ),
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=True,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
async def apply_confirmed_theme_patch(
    plan_id: Annotated[
        str,
        Field(
            min_length=1,
            max_length=120,
            description=(
                "Opaque immutable plan identifier returned by preview_theme_file_patch or "
                "preview_theme_file_update. The caller cannot alter the file path or patch "
                "through this value."
            ),
        ),
    ],
    confirmation_token: Annotated[
        str,
        Field(
            min_length=1,
            max_length=256,
            description=(
                "One-time confirmation token issued by the WordPress Bridge for this exact "
                "preview plan after explicit user approval."
            ),
        ),
    ],
) -> dict[str, Any]:
    """Apply only the exact server-side preview plan already approved by the user."""
    payload = {
        "plan_id": plan_id,
        "confirmation_token": confirmation_token,
    }
    result = await _wp("POST", f"{NS}/theme/file/apply", payload=payload)
    return result["data"]


@mcp.tool()
async def preview_about_page_update(
    expected_sha256: str,
    operations: list[str],
) -> dict[str, Any]:
    """
    Подготовить безопасное изменение страницы «О нас» только из разрешённого
    набора операций. Произвольный PHP/CSS и произвольные пути не принимаются.
    Доступные операции сейчас: advantages_approved_v1, slogan_style_v1, mobile_polish_v1, approved_mobile_layout_v1, about_desktop_layout_v1.
    Ничего не записывает.
    """
    payload = {
        "expected_sha256": expected_sha256,
        "operations": operations,
    }
    result = await _wp("POST", f"{NS}/about/page/preview", payload=payload)
    return result["data"]


@mcp.tool(
    title="Preview approved About-page desktop layout",
    description=(
        "Prepare the fixed approved desktop layout for template-o-nas.php. "
        "The operation is hard-coded as about_desktop_layout_v1; the caller can provide only "
        "the current SHA-256 and cannot supply arbitrary CSS, PHP, JavaScript, paths, selectors, "
        "or search/replace content. PREVIEW ONLY: no file is written."
    ),
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=False,
    ),
)
async def preview_about_desktop_layout(
    expected_sha256: Annotated[
        str,
        Field(min_length=64, max_length=64, description="Current SHA-256 of template-o-nas.php."),
    ],
) -> dict[str, Any]:
    """Prepare only the fixed approved desktop About-page layout."""
    payload = {
        "expected_sha256": _validate_sha256_hex(expected_sha256),
        "operations": ["about_desktop_layout_v1"],
    }
    result = await _wp("POST", f"{NS}/about/page/preview", payload=payload)
    return result["data"]


@mcp.tool()
async def preview_about_mobile_polish(
    expected_sha256: str,
) -> dict[str, Any]:
    """
    Подготовить только утверждённую мобильную доводку страницы «О нас».
    Операция фиксирована как mobile_polish_v1; произвольный CSS/PHP не принимается.
    Ничего не записывает.
    """
    payload = {
        "expected_sha256": expected_sha256,
        "operations": ["mobile_polish_v1"],
    }
    result = await _wp("POST", f"{NS}/about/page/preview", payload=payload)
    return result["data"]


@mcp.tool()
async def preview_about_approved_mobile_layout(
    expected_sha256: str,
) -> dict[str, Any]:
    """
    Подготовить утверждённую мобильную компоновку страницы «О нас».
    Операция фиксирована как approved_mobile_layout_v1; произвольный CSS/PHP не принимается.
    Ничего не записывает.
    """
    payload = {
        "expected_sha256": expected_sha256,
        "operations": ["approved_mobile_layout_v1"],
    }
    result = await _wp("POST", f"{NS}/about/page/preview", payload=payload)
    return result["data"]


@mcp.tool()
async def apply_about_page_update(
    plan_id: str,
    confirmation_token: str,
) -> dict[str, Any]:
    """Применить ранее подготовленный ограниченный план страницы «О нас»."""
    payload = {
        "plan_id": plan_id,
        "confirmation_token": confirmation_token,
    }
    result = await _wp("POST", f"{NS}/about/page/apply", payload=payload)
    return result["data"]


@mcp.tool()
async def preview_cache_clear() -> dict[str, Any]:
    """ТОЛЬКО PREVIEW очистки кэша. Ничего не очищает."""
    result = await _wp("POST", f"{NS}/cache/clear/preview", payload={})
    return result["data"]


@mcp.tool()
async def apply_cache_clear(
    plan_id: str,
    confirmation_token: str,
) -> dict[str, Any]:
    """Очистить кэш по ранее созданному preview."""
    payload = {
        "plan_id": plan_id,
        "confirmation_token": confirmation_token,
    }
    result = await _wp("POST", f"{NS}/cache/clear/apply", payload=payload)
    return result["data"]


@mcp.tool()
async def preview_backup_restore(backup_id: str) -> dict[str, Any]:
    """ТОЛЬКО PREVIEW восстановления резервной копии. Ничего не восстанавливает."""
    result = await _wp(
        "POST",
        f"{NS}/backup/restore/preview",
        payload={"backup_id": backup_id},
    )
    return result["data"]


@mcp.tool()
async def apply_backup_restore(
    plan_id: str,
    confirmation_token: str,
) -> dict[str, Any]:
    """Восстановить backup по preview."""
    payload = {
        "plan_id": plan_id,
        "confirmation_token": confirmation_token,
    }
    result = await _wp("POST", f"{NS}/backup/restore/apply", payload=payload)
    return result["data"]


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
