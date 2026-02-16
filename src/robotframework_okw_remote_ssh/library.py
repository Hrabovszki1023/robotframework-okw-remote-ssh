from robot.api.deco import keyword, library
from okw_contract_utils import expand_mem, MatchMode, assert_match
from okw_contract_utils.tokens import is_ignore, is_empty_token
from .secrets import SecretStore
from robot.api import logger


import os
import yaml
import time

try:
    import paramiko  # type: ignore
except Exception:
    paramiko = None

@library(scope="GLOBAL")
class RemoteSshLibrary:
    """
    Standalone Robot Framework library for deterministic remote interaction.
    Contract-first: Action (Set Remote) writes last_response, Verify reads it.
    """

    def __init__(self, config_dir: str = "remotes", backend: str = "stub", secrets_path: str | None = None):
        self._sessions = {}
        self._store = {}
        self._config_dir = config_dir
        self._backend = backend.lower().strip()
        self._secrets = SecretStore(secrets_path=secrets_path)

    # -------------------------
    # Internal helpers
    # -------------------------
    def _check_ignore(self, expanded_value: str) -> bool:
        """Returns True if the value is $IGNORE (keyword should skip)."""
        if is_ignore(expanded_value):
            logger.info("IGNORED")
            return True
        return False

    def _resolve_empty_token(self, expanded_value: str) -> str:
        """Replaces $EMPTY token with empty string."""
        if is_empty_token(expanded_value):
            return ""
        return expanded_value

    def _ensure_session(self, session_name: str) -> dict:
        if session_name not in self._sessions:
            raise ValueError(f"Session '{session_name}' does not exist.")
        return self._sessions[session_name]

    def _ensure_last_response(self, session_name: str) -> dict:
        s = self._ensure_session(session_name)
        resp = s.get("last_response")
        if not resp:
            raise ValueError(f"Session '{session_name}' has no last_response. Call 'Set Remote' first.")
        return resp

    def _load_connection(self, config_ref: str) -> dict:
        # Security: no path traversal
        if "/" in config_ref or "\\" in config_ref or ".." in config_ref:
            raise RuntimeError("Invalid config_ref (path traversal not allowed).")

        path = os.path.join(self._config_dir, f"{config_ref}.yaml")
        if not os.path.exists(path):
            raise RuntimeError(f"Remote definition not found: {path}")

        with open(path, "r", encoding="utf-8") as f:
            conn = yaml.safe_load(f) or {}

        # Required fields
        for field in ["host", "username"]:
            if field not in conn or not conn[field]:
                raise RuntimeError(f"Remote definition '{config_ref}' missing required field: {field}")

        # Defaults
        conn.setdefault("port", 22)
        conn.setdefault("timeout", 10)
        conn.setdefault("encoding", "utf-8")

        # Disallow inline password in repo config
        if "password" in conn:
            raise RuntimeError(f"Remote definition '{config_ref}' must not contain 'password'.")

        auth = conn.get("auth") or {}
        if not isinstance(auth, dict):
            raise RuntimeError(f"Remote definition '{config_ref}' has invalid 'auth' section.")

        auth_type = auth.get("type")
        if auth_type != "password":
            raise RuntimeError(f"Remote definition '{config_ref}' auth.type must be 'password' (MVP).")

        secret_id = auth.get("secret_id")
        if not secret_id:
            raise RuntimeError(f"Remote definition '{config_ref}' auth.secret_id is required.")

        # Resolve password from local secrets file (outside repo)
        password = self._secrets.get_password(str(secret_id))
        conn["password"] = password  # stored only in memory

        return conn

    def _connect_paramiko(self, conn: dict):
        if paramiko is None:
            raise RuntimeError("Paramiko backend requested but paramiko is not installed.")

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(
                hostname=conn["host"],
                port=int(conn.get("port", 22)),
                username=conn["username"],
                password=conn.get("password"),     # from secret store
                timeout=float(conn.get("timeout", 10)),
                banner_timeout=float(conn.get("timeout", 10)),
                auth_timeout=float(conn.get("timeout", 10)),
            )
        except Exception as e:
            # Sanitized error: no password, no full kwargs dump
            raise RuntimeError(
                f"SSH connection failed for user '{conn.get('username')}' on host '{conn.get('host')}'."
            ) from e

        return client
        
    def _exec_paramiko(self, client, command: str, timeout: float, encoding: str = "utf-8"):
        start = time.time()

        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)

        out = stdout.read().decode(encoding, errors="replace")
        err = stderr.read().decode(encoding, errors="replace")

        exit_code = stdout.channel.recv_exit_status()
        dur_ms = int((time.time() - start) * 1000)

        return out, err, exit_code, dur_ms
        
    def _fmt_block(self, title: str, value: str, max_len: int = 8000) -> str:
        if value is None:
            value = ""
        s = str(value)
        if len(s) > max_len:
            s = s[:max_len] + "\n... [TRUNCATED]"
        return f"{title}:\n{s}"
        
    def _get_response_field(self, session_name: str, field: str):
        resp = self._ensure_last_response(session_name)
        if field not in resp:
            raise ValueError(f"Unknown response field: {field}")
        return resp[field]

    # -------------------------
    # Session lifecycle
    # -------------------------
    @keyword("Open Remote Session")
    def open_remote_session(self, session_name: str, config_ref: str):
        if session_name in self._sessions:
            raise ValueError(f"Session '{session_name}' already exists.")

        conn = self._load_connection(config_ref)

        client = None
        if self._backend == "paramiko":
            client = self._connect_paramiko(conn)

        self._sessions[session_name] = {
            "config_ref": config_ref,
            "connection": conn,
            "connected": True,
            "client": client,          # <-- IMPORTANT
            "last_response": None,
        }

    @keyword("Close Remote Session")
    def close_remote_session(self, session_name: str):
        s = self._ensure_session(session_name)
        client = s.get("client")
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
        del self._sessions[session_name]

    # -------------------------
    # Action
    # -------------------------
    @keyword("Set Remote")
    def set_remote(self, session_name: str, command: str):
        return self._set_remote(session_name, command, ignore_exit_code=False)


    @keyword("Set Remote And Continue")
    def set_remote_and_continue(self, session_name: str, command: str):
        return self._set_remote(session_name, command, ignore_exit_code=True)


    def _set_remote(self, session_name: str, command: str, ignore_exit_code: bool):
        s = self._ensure_session(session_name)
        conn = s.get("connection", {})

        expanded_command = expand_mem(command, self._store)

        if self._check_ignore(expanded_command):
            return s.get("last_response")

        out = ""
        err = ""
        code = 0
        dur_ms = 0

        if self._backend == "paramiko":
            client = s.get("client")
            if client is None:
                raise RuntimeError(
                    f"Session '{session_name}' has no paramiko client."
                )

            out, err, code, dur_ms = self._exec_paramiko(
                client,
                expanded_command,
                float(conn.get("timeout", 10)),
            )
        else:
            # stub
            out = expanded_command
            err = ""
            code = 0
            dur_ms = 0

        # Normalize output (Windows CRLF fix)
        out = out.replace("\r\n", "\n").rstrip()
        err = err.replace("\r\n", "\n").rstrip()

        response = {
            "command": expanded_command,
            "stdout": out,
            "stderr": err,
            "exit_code": code,
            "duration_ms": dur_ms,
        }
        s["last_response"] = response

        # ASR logging
        msg = "\n".join([
            self._fmt_block("command", response["command"], max_len=2000),
            self._fmt_block("stdout", response["stdout"]),
            self._fmt_block("stderr", response["stderr"]),
            f"exit_code: {response['exit_code']}",
            f"duration_ms: {response['duration_ms']}",
        ])
        logger.info(msg)

        # Fail-fast behaviour
        if not ignore_exit_code and code != 0:
            raise AssertionError(
                f"Remote command failed with exit_code={code}."
            )

        return response


    # -------------------------
    # Verify (reads last_response only)
    # -------------------------
    @keyword("Verify Remote Response")
    def verify_remote_response(self, session_name: str, expected: str):
        actual = str(self._get_response_field(session_name, "stdout") or "")
        expected_expanded = expand_mem(expected, self._store)
        if self._check_ignore(expected_expanded):
            return
        expected_expanded = self._resolve_empty_token(expected_expanded)
        assert_match(actual, expected_expanded, MatchMode.EXACT, context=f"[{session_name}] stdout")

    @keyword("Verify Remote Response WCM")
    def verify_remote_response_wcm(self, session_name: str, pattern: str):
        actual = str(self._get_response_field(session_name, "stdout") or "")
        pattern_expanded = expand_mem(pattern, self._store)
        if self._check_ignore(pattern_expanded):
            return
        pattern_expanded = self._resolve_empty_token(pattern_expanded)
        assert_match(actual, pattern_expanded, MatchMode.WCM, context=f"[{session_name}] stdout")

    @keyword("Verify Remote Response REGX")
    def verify_remote_response_regx(self, session_name: str, regex: str):
        actual = str(self._get_response_field(session_name, "stdout") or "")
        regex_expanded = expand_mem(regex, self._store)
        if self._check_ignore(regex_expanded):
            return
        regex_expanded = self._resolve_empty_token(regex_expanded)
        assert_match(actual, regex_expanded, MatchMode.REGX, context=f"[{session_name}] stdout")

    @keyword("Verify Remote Stderr")
    def verify_remote_stderr(self, session_name: str, expected: str = "$EMPTY"):
        actual = str(self._get_response_field(session_name, "stderr") or "")
        expected_expanded = expand_mem(expected, self._store)
        if self._check_ignore(expected_expanded):
            return
        expected_expanded = self._resolve_empty_token(expected_expanded)
        assert_match(actual, expected_expanded, MatchMode.EXACT, context=f"[{session_name}] stderr")

    @keyword("Verify Remote Stderr WCM")
    def verify_remote_stderr_wcm(self, session_name: str, pattern: str = "$EMPTY"):
        actual = str(self._get_response_field(session_name, "stderr") or "")
        pattern_expanded = expand_mem(pattern, self._store)
        if self._check_ignore(pattern_expanded):
            return
        pattern_expanded = self._resolve_empty_token(pattern_expanded)
        assert_match(actual, pattern_expanded, MatchMode.WCM, context=f"[{session_name}] stderr")

    @keyword("Verify Remote Stderr REGX")
    def verify_remote_stderr_regx(self, session_name: str, regex: str = "$EMPTY"):
        actual = str(self._get_response_field(session_name, "stderr") or "")
        regex_expanded = expand_mem(regex, self._store)
        if self._check_ignore(regex_expanded):
            return
        regex_expanded = self._resolve_empty_token(regex_expanded)
        assert_match(actual, regex_expanded, MatchMode.REGX, context=f"[{session_name}] stderr")

    @keyword("Verify Remote Exit Code")
    def verify_remote_exit_code(self, session_name: str, expected_exit_code: str):
        expanded = expand_mem(str(expected_exit_code), self._store)
        if self._check_ignore(expanded):
            return
        actual = self._get_response_field(session_name, "exit_code")
        if int(actual) != int(expanded):
            raise AssertionError(
                f"[{session_name}] exit_code mismatch. Expected {int(expanded)}, got {actual}."
            )

    def _parse_duration_expr(self, expr: str):
        s = expr.strip()

        if ".." in s:
            a, b = s.split("..", 1)
            return ("range", int(a.strip()), int(b.strip()))

        for op in (">=", "<=", "==", ">", "<"):
            if s.startswith(op):
                return (op, int(s[len(op):].strip()))

        # fallback: exact
        return ("==", int(s))

    @keyword("Verify Remote Duration")
    def verify_remote_duration(self, session_name: str, expr: str):
        expanded = expand_mem(expr, self._store)
        if self._check_ignore(expanded):
            return
        actual = int(self._get_response_field(session_name, "duration_ms"))
        parsed = self._parse_duration_expr(expanded)

        if parsed[0] == "range":
            _, lo, hi = parsed
            if not (lo <= actual <= hi):
                raise AssertionError(f"[{session_name}] duration_ms {actual} not in range {lo}..{hi}.")
            return

        op, expected = parsed
        ok = (
            (op == "==" and actual == expected) or
            (op == ">"  and actual >  expected) or
            (op == ">=" and actual >= expected) or
            (op == "<"  and actual <  expected) or
            (op == "<=" and actual <= expected)
        )
        if not ok:
            raise AssertionError(f"[{session_name}] duration_ms check failed: {actual} {op} {expected}.")


    # -------------------------
    # Memorize
    # -------------------------
    @keyword("Memorize Remote Response Field")
    def memorize_remote_response_field(self, session_name: str, field: str, key: str):
        resp = self._ensure_last_response(session_name)
        if field not in resp:
            raise ValueError(f"Unknown response field: {field}")
        self._store[key] = resp[field]
