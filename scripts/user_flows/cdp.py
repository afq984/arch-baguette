"""Chrome DevTools Protocol (CDP) WebSocket client, terminal tab helper, and structured errors."""

from __future__ import annotations

import json
import socket
import time
import urllib.error
from typing import Any, Callable, NoReturn

from . import log


class CDPError(RuntimeError):
    """Structured Chrome DevTools Protocol error including operation, target, step, and elapsed wait."""


class CDPTimeoutError(TimeoutError):
    """Structured Chrome DevTools Protocol timeout including operation, target, step, and elapsed wait."""


def sleep_backoff(interval: float, max_interval: float, deadline: float) -> float:
    rem = deadline - time.monotonic()
    if rem > 0:
        time.sleep(min(interval, rem))
    return min(max_interval, interval * 1.4) if interval >= 0.2 else interval


def is_ws_timeout_exc(exc: BaseException) -> bool:
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return True
    if isinstance(exc, urllib.error.URLError) and isinstance(exc.reason, (TimeoutError, socket.timeout)):
        return True
    if "Timeout" in exc.__class__.__name__:
        return True
    msg_low = str(exc).lower()
    return "timed out" in msg_low or "timeout" in msg_low


def format_cdp_error_context(
    *,
    operation: str,
    target_label: str,
    target_url: str,
    target_id: str,
    step: str,
    elapsed_sec: float,
    timeout_sec: float,
) -> str:
    return (
        f"operation={operation!r} target={target_label!r} url={target_url!r} "
        f"target_id={target_id!r} step={step!r} waited={elapsed_sec:.2f}s (timeout={timeout_sec:.1f}s)"
    )


class CDPConnection:
    """Thin synchronous Chrome DevTools Protocol client over `websocket-client`."""

    def __init__(
        self,
        ws_url: str,
        timeout: float = 45.0,
        *,
        target_label: str = "cdp-target",
        target_url: str = "",
        target_id: str = "",
        step_getter: Callable[[], str] | None = None,
        connect_fn: Callable[..., Any] | None = None,
        on_error: Callable[[], None] | None = None,
    ) -> None:
        self.default_timeout = timeout
        self.target_label = target_label
        self.target_url = target_url or ws_url
        self.target_id = (
            target_id
            or (ws_url.rstrip("/").rsplit("/", 1)[-1] if "/devtools/" in ws_url else "<unknown>")
        )
        self._step_getter = step_getter
        self._on_error = on_error
        self._next_id = 0

        t0 = time.monotonic()
        try:
            if connect_fn is None:
                import websocket  # Imported lazily so offline unit tests can run without sockets

                connect_fn = websocket.create_connection
            self.ws = connect_fn(ws_url, timeout=timeout, suppress_origin=True)
        except Exception as exc:
            self._raise_ws_exc(
                exc, "WebSocket.connect", t0, timeout,
                "CDP WebSocket connect timed out", "CDP WebSocket connect failed",
            )

    @classmethod
    def from_target(
        cls,
        tgt: dict[str, Any],
        *,
        label: str,
        timeout: float = 45.0,
        step_getter: Callable[[], str] | None = None,
        connect_fn: Callable[..., Any] | None = None,
        on_error: Callable[[], None] | None = None,
    ) -> CDPConnection:
        return cls(
            str(tgt["webSocketDebuggerUrl"]),
            timeout=timeout,
            target_label=label,
            target_url=str(tgt.get("url", "")),
            target_id=str(tgt.get("id", "")),
            step_getter=step_getter,
            connect_fn=connect_fn,
            on_error=on_error,
        )

    def current_step(self) -> str:
        return self._step_getter() if self._step_getter is not None else "<unspecified-step>"

    def error_context(self, operation: str, elapsed_sec: float, timeout_sec: float) -> str:
        return format_cdp_error_context(
            operation=operation,
            target_label=self.target_label,
            target_url=self.target_url,
            target_id=self.target_id,
            step=self.current_step(),
            elapsed_sec=elapsed_sec,
            timeout_sec=timeout_sec,
        )

    def _raise_ws_exc(
        self, exc: BaseException, op: str, t0: float, timeout: float, to_msg: str, err_msg: str
    ) -> NoReturn:
        if self._on_error is not None:
            self._on_error()
        ctx = self.error_context(op, time.monotonic() - t0, timeout)
        err_cls = CDPTimeoutError if is_ws_timeout_exc(exc) else CDPError
        prefix = to_msg if err_cls is CDPTimeoutError else err_msg
        raise err_cls(f"{prefix} ({ctx}): {type(exc).__name__}: {exc}") from exc

    def recv_frame(self, timeout: float, op_desc: str = "recv_frame") -> dict[str, Any]:
        """Receives and parses one JSON CDP frame within `timeout` seconds."""
        t0 = time.monotonic()
        deadline = t0 + timeout
        empty_frames = 0
        while True:
            rem = deadline - time.monotonic()
            if rem <= 0:
                raise CDPTimeoutError(
                    f"Timed out waiting for CDP frame ({self.error_context(op_desc, time.monotonic() - t0, timeout)})"
                )
            try:
                self.ws.settimeout(max(0.05, rem))
                raw = self.ws.recv()
            except Exception as exc:
                self._raise_ws_exc(
                    exc, f"{op_desc} (recv)", t0, timeout,
                    "Timed out waiting for CDP response", "CDP WebSocket recv failed",
                )
            if not raw:
                empty_frames += 1
                if not getattr(self.ws, "connected", True) or empty_frames >= 8:
                    if self._on_error is not None:
                        self._on_error()
                    ctx = self.error_context(f"{op_desc} (recv)", time.monotonic() - t0, timeout)
                    raise CDPError(f"CDP WebSocket closed/EOF while waiting for response ({ctx})")
                continue
            try:
                return json.loads(raw)
            except json.JSONDecodeError as exc:
                ctx = self.error_context(op_desc, time.monotonic() - t0, timeout)
                raise CDPError(f"Malformed JSON frame from CDP ({ctx}): {raw[:200]!r}") from exc

    def call(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        timeout: float | None = None,
        allow_error: bool = False,
        op_desc: str | None = None,
        *,
        session_id: str | None = None,
        on_event: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        eff_timeout = self.default_timeout if timeout is None else timeout
        self._next_id += 1
        req_id = self._next_id
        op = f"{op_desc} [{method}#{req_id}]" if op_desc else f"{method}#{req_id}"
        t0 = time.monotonic()
        deadline = t0 + eff_timeout
        req_obj: dict[str, Any] = {"id": req_id, "method": method, "params": params or {}}
        if session_id is not None:
            req_obj["sessionId"] = session_id
        try:
            self.ws.settimeout(eff_timeout)
            self.ws.send(json.dumps(req_obj))
        except Exception as exc:
            self._raise_ws_exc(
                exc, f"{op} (send)", t0, eff_timeout, "CDP send timed out", "CDP send failed"
            )

        while True:
            rem = deadline - time.monotonic()
            if rem <= 0:
                raise CDPTimeoutError(
                    f"Timed out waiting for CDP response ({self.error_context(op, time.monotonic() - t0, eff_timeout)})"
                )
            msg = self.recv_frame(rem, op_desc=op)
            if msg.get("id") == req_id:
                if "error" in msg and not allow_error:
                    ctx = self.error_context(op, time.monotonic() - t0, eff_timeout)
                    raise CDPError(f"CDP protocol error ({ctx}): {msg['error']}")
                return msg.get("result", msg)
            if on_event is not None and "id" not in msg:
                on_event(msg)

    def eval_js(
        self,
        expression: str,
        await_promise: bool = False,
        timeout: float | None = None,
        op_desc: str | None = None,
    ) -> Any:
        eff_timeout = self.default_timeout if timeout is None else timeout
        t0 = time.monotonic()
        res = self.call(
            "Runtime.evaluate",
            {"expression": expression, "returnByValue": True, "awaitPromise": await_promise},
            timeout=eff_timeout,
            op_desc=op_desc,
        )
        if "exceptionDetails" in res:
            ctx = self.error_context(op_desc or "Runtime.evaluate", time.monotonic() - t0, eff_timeout)
            raise CDPError(f"CDP JavaScript exception ({ctx}): {res['exceptionDetails']}")
        return res.get("result", {}).get("value")

    def poll_js(
        self,
        expression: str,
        done_pred: Callable[[Any], bool],
        *,
        op_desc: str,
        timeout: float = 30.0,
        interval: float = 0.5,
        max_interval: float = 2.0,
    ) -> Any:
        """Evaluates `expression` until `done_pred(val)` holds or raises `CDPTimeoutError`."""
        t0 = time.monotonic()
        deadline = t0 + timeout
        last_val: Any = None
        while time.monotonic() < deadline:
            last_val = self.eval_js(expression, op_desc=op_desc)
            if done_pred(last_val):
                return last_val
            interval = sleep_backoff(interval, max_interval, deadline)
        ctx = self.error_context(op_desc, time.monotonic() - t0, timeout)
        raise CDPTimeoutError(f"Timed out in {op_desc} ({ctx}; last state={last_val!r})")

    def close(self) -> None:
        try:
            self.ws.close()
        except Exception:
            pass


class CroshTab:
    """Drives a `chrome-untrusted://crosh/` or `chrome-untrusted://terminal/` tab via CDP."""

    def __init__(self, label: str, conn: CDPConnection) -> None:
        self.label = label
        self.conn = conn

    def get_text(self, timeout: float | None = None, *, max_lines: int | None = None) -> str:
        limit = int(max_lines) if (max_lines is not None and max_lines > 0) else 0
        js = f"""(() => {{
            const buf = window.term_?.term?.buffer?.active;
            if (!buf) return '';
            let end = buf.length - 1;
            while (end >= 0 && !(buf.getLine(end)?.translateToString(true))) end--;
            if (end < 0) return '';
            let start = {limit} > 0 ? Math.max(0, end - {limit} + 1) : 0;
            while (start > 0 && buf.getLine(start)?.isWrapped) start--;
            const lines = [];
            for (let i = start; i <= end; i++) {{
                const ln = buf.getLine(i);
                if (!ln) continue;
                const s = ln.translateToString(i === end || !buf.getLine(i + 1)?.isWrapped);
                if (ln.isWrapped && lines.length) lines[lines.length - 1] += s;
                else lines.push(s);
            }}
            return lines.join('\\n');
        }})()"""
        return self.conn.eval_js(js, timeout=timeout, op_desc=f"{self.label}.get_text (read xterm buffer)") or ""

    def send_line(self, line: str) -> None:
        """Types a command line into xterm.js and presses Enter."""
        short = line if len(line) <= 48 else f"{line[:45]}..."
        self.conn.call("Page.bringToFront", op_desc=f"{self.label}.send_line(Page.bringToFront)")
        # Feed text through xterm.js's native paste() to avoid libapps keyCode
        # collisions on ASCII punctuation (34/36/39/45/46), then send Enter.
        self.conn.eval_js(
            f"(() => {{ window.term_.term.focus(); window.term_.term.paste({json.dumps(line)}); return true; }})()",
            op_desc=f"{self.label}.send_line(xterm.paste {short!r})",
        )
        time.sleep(0.1)
        key_base = {"windowsVirtualKeyCode": 13, "nativeVirtualKeyCode": 13, "key": "Enter", "code": "Enter"}
        self.conn.call(
            "Input.dispatchKeyEvent",
            {"type": "rawKeyDown", **key_base, "text": "\r", "unmodifiedText": "\r"},
            op_desc=f"{self.label}.send_line(Enter rawKeyDown)",
        )
        self.conn.call(
            "Input.dispatchKeyEvent",
            {"type": "keyUp", **key_base},
            op_desc=f"{self.label}.send_line(Enter keyUp)",
        )

    def wait_for(
        self,
        predicate: Callable[[str], bool],
        timeout: float = 120.0,
        desc: str = "output",
        *,
        interval: float = 0.5,
        max_interval: float = 2.5,
        max_lines: int | None = None,
    ) -> str:
        t0 = time.monotonic()
        deadline = t0 + timeout
        last = ""
        while (rem := deadline - time.monotonic()) > 0:
            last = self.get_text(timeout=min(self.conn.default_timeout, max(5.0, rem)), max_lines=max_lines)
            if predicate(last):
                return last
            if deadline - time.monotonic() <= 0:
                break
            interval = sleep_backoff(interval, max_interval, deadline)
        if max_lines is not None:
            try:
                last = self.get_text(timeout=5.0) or last
            except Exception:
                pass
        ctx = self.conn.error_context(f"{self.label}.wait_for({desc})", time.monotonic() - t0, timeout)
        raise CDPTimeoutError(f"Timed out waiting for {desc} ({ctx}). Last terminal buffer:\n{last}")

    def run_crosh_cmd(self, cmd: str, timeout: float = 180.0) -> str:
        """Types `cmd` at a `crosh>` prompt and waits for the next `crosh>` prompt."""
        prev_prompts = self.get_text().count("crosh>")
        log(f"  [{self.label}] crosh> {cmd}")
        self.send_line(cmd)
        after = self.wait_for(
            lambda txt: txt.count("crosh>") > prev_prompts and txt.rstrip().endswith("crosh>"),
            timeout=timeout,
            desc=f"completion of `{cmd}`",
        )
        parts = after.split("crosh>")
        delta = (parts[-2] if len(parts) >= 2 else after).strip()
        if "ERROR - ERROR: command failed" in delta or "Error:" in delta:
            raise RuntimeError(f"Command `{cmd}` failed in {self.label}:\n{delta}")
        return delta

    def suppress_beforeunload(self) -> None:
        try:
            self.conn.eval_js(
                "window.onbeforeunload = null; "
                "if (window.BeforeUnloadEvent) { "
                "BeforeUnloadEvent.prototype.preventDefault = () => {}; "
                "Object.defineProperty(BeforeUnloadEvent.prototype, 'returnValue', { set() {} }); }",
                timeout=2.0,
                op_desc=f"{self.label}.suppress_beforeunload",
            )
        except Exception:
            pass

    def close(self) -> None:
        self.conn.close()
