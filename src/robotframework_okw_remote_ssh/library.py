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
    """Standalone Robot Framework library for deterministic remote interaction via SSH.

    = Overview =

    This library provides session-based remote command execution and structured
    verification keywords. It follows the OKW contract-first design: action
    keywords (``Set Remote``) write to ``last_response``, verification keywords
    read from it.

    = Session Management =

    Multiple sessions can be opened concurrently, each referenced by an abstract
    session name (e.g. ``r1``). Connection details are loaded from YAML files
    in the configured ``config_dir`` directory (default: ``remotes/``).

    = Value Expansion =

    All command, expected, and expr parameters support ``$MEM{KEY}`` expansion.
    Missing keys cause immediate FAIL.

    = OKW Global Tokens =

    | *Token*    | *Supported* | *Behavior*                                           |
    | $IGNORE    | Yes         | Skips execution or verification (PASS, no SSH call)  |
    | $EMPTY     | Yes         | Asserts that the checked field is empty               |
    | $DELETE    | No          | Not implemented in this library                      |

    = Token Evaluation Order =

    1. Robot variable expansion (e.g. ``${IGNORE}`` -> ``$IGNORE``)
    2. OKW value expansion (``$MEM{KEY}`` -> stored value)
    3. Token parsing (``$IGNORE``, ``$EMPTY``)
    4. Keyword execution / verification

    = Secrets =

    Passwords are never stored in the repository. They are resolved from a local
    secrets file (default: ``~/.okw/secrets.yaml``). Remote YAML configs reference
    secrets via ``auth.secret_id``.

    = Examples =

    | Open Remote Session    | r1    | myserver        |
    | Set Remote             | r1    | whoami          |
    | Verify Remote Response | r1    | expecteduser    |
    | Close Remote Session   | r1    |                 |
    """

    ROBOT_LIBRARY_DOC_FORMAT = 'ROBOT'

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
        """Opens a named SSH session using a remote definition file.

        Arguments:
        - ``session_name``: Abstract session identifier (e.g. ``r1``).
        - ``config_ref``: Base name of the YAML config file in the config directory
          (without ``.yaml`` extension). Resolved as ``<config_dir>/<config_ref>.yaml``.

        Behavior:
        - Loads connection details from the YAML file.
        - Resolves the password from the local secrets file via ``auth.secret_id``.
        - Establishes the SSH connection (paramiko backend) or creates a stub session.
        - Fails if the session name already exists, the config file is missing,
          or required fields (``host``, ``username``) are absent.

        Remote definition template (``remotes/<config_ref>.yaml``):
        | *Attribute*       | *Required* | *Default* | *Description*                          |
        | host              | Yes        |           | Hostname or IP address                 |
        | port              | No         | 22        | SSH port                               |
        | username          | Yes        |           | SSH username                           |
        | timeout           | No         | 10        | Connection and command timeout (sec)   |
        | encoding          | No         | utf-8     | Output encoding                        |
        | auth.type         | Yes        | password  | Authentication type (MVP: password)    |
        | auth.secret_id    | Yes        |           | Reference to ``~/.okw/secrets.yaml``   |

        YAML example (``remotes/myserver.yaml``):
        | host: "192.168.1.100"
        | port: 22
        | username: "testuser"
        | timeout: 10
        | encoding: "utf-8"
        | auth:
        |   type: password
        |   secret_id: "myserver/testuser"

        The password is resolved from the local secrets file (``~/.okw/secrets.yaml``):
        | secrets:
        |   myserver/testuser:
        |     password: "your_password_here"

        *Note:* The ``password`` field must never appear in the remote YAML file itself.
        Passwords are always resolved from the secrets file outside the repository.

        Example (`open_session.robot`):
        | =Setting= | =Value=                                            |
        | Library   | robotframework_okw_remote_ssh.RemoteSshLibrary     |
        |           | backend=paramiko                                   |
        |           |                                                    |
        | =Test Cases=  |           |            |                       |
        | Connect To Build Server   |            |                       |
        |     Open Remote Session   | r1         | buildserver01          |
        |     Set Remote            | r1         | whoami                 |
        |     Verify Remote Response | r1        | jenkins                |
        |     Close Remote Session  | r1         |                        |
        """
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
        """Closes an open SSH session and releases all resources.

        Arguments:
        - ``session_name``: The session identifier to close (e.g. ``r1``).

        Behavior:
        - Closes the underlying SSH connection (if paramiko backend).
        - Removes the session from the internal session registry.
        - Fails if the session does not exist.

        Example (`close_session.robot`):
        | =Setting= | =Value=                                            |
        | Library   | robotframework_okw_remote_ssh.RemoteSshLibrary     |
        |           |                                                    |
        | =Test Cases=  |            |            |                      |
        | Session Lifecycle          |            |                      |
        |     Open Remote Session    | r1         | myserver             |
        |     Set Remote             | r1         | uptime               |
        |     Verify Remote Response | r1         | up                   |
        |     Close Remote Session   | r1         |                      |
        """
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
        """Executes a command on the remote host. Fails on nonzero exit code.

        Arguments:
        - ``session_name``: The session to execute on (e.g. ``r1``).
        - ``command``: The shell command to execute. Supports ``$MEM{KEY}`` expansion.

        Behavior:
        - Expands ``$MEM{KEY}`` placeholders in the command.
        - If the expanded command is ``$IGNORE``: no SSH call is made,
          ``last_response`` remains unchanged, keyword returns PASS.
        - Executes the command via SSH (or stub backend).
        - Normalizes stdout/stderr (``\\r\\n`` -> ``\\n``, rstrip).
        - Stores the result in ``last_response`` (command, stdout, stderr,
          exit_code, duration_ms).
        - Logs all response fields in a single keyword step (ASR logging).
        - Raises ``AssertionError`` if ``exit_code != 0``.

        Example (`set_remote.robot`):
        | =Setting= | =Value=                                            |
        | Library   | robotframework_okw_remote_ssh.RemoteSshLibrary     |
        |           |                                                    |
        | =Variable= | =Value=                                          |
        | ${IGNORE}  | $IGNORE                                          |
        |           |                                                    |
        | =Test Cases=  |           |                |                   |
        | Execute Command And Verify |               |                   |
        |     Open Remote Session    | r1            | myserver          |
        |     Set Remote             | r1            | whoami            |
        |     Verify Remote Response | r1            | testuser          |
        |     Close Remote Session   | r1            |                   |
        |           |                |                |                   |
        | Skip With Ignore Token     |               |                   |
        |     Open Remote Session    | r1            | myserver          |
        |     Set Remote             | r1            | echo first        |
        |     Set Remote             | r1            | ${IGNORE}         |
        |     # last_response is still "echo first"  |                   |
        |     Verify Remote Response | r1            | first             |
        |     Close Remote Session   | r1            |                   |
        """
        return self._set_remote(session_name, command, ignore_exit_code=False)

    @keyword("Set Remote And Continue")
    def set_remote_and_continue(self, session_name: str, command: str):
        """Executes a command on the remote host. Does *not* fail on nonzero exit code.

        Arguments:
        - ``session_name``: The session to execute on (e.g. ``r1``).
        - ``command``: The shell command to execute. Supports ``$MEM{KEY}`` expansion.

        Behavior:
        - Same as ``Set Remote``, but never raises on nonzero ``exit_code``.
        - Useful for commands that are expected to fail (e.g. testing error paths).
        - ``$IGNORE`` token handling is identical to ``Set Remote``.

        Example (`set_remote_and_continue.robot`):
        | =Setting= | =Value=                                            |
        | Library   | robotframework_okw_remote_ssh.RemoteSshLibrary     |
        |           |                                                    |
        | =Test Cases=  |           |                    |               |
        | Tolerate Nonzero Exit Code |                   |               |
        |     Open Remote Session    | r1               | myserver       |
        |     Set Remote And Continue | r1              | exit 1         |
        |     Verify Remote Exit Code | r1              | 1              |
        |     Verify Remote Stderr    | r1              |                |
        |     Close Remote Session    | r1              |                |
        """
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
        """Verifies that stdout of the last command matches the expected value (EXACT match).

        Arguments:
        - ``session_name``: The session to verify (e.g. ``r1``).
        - ``expected``: The expected stdout value. Supports ``$MEM{KEY}`` expansion.

        Special tokens:
        - ``$IGNORE``: Skips verification (PASS).
        - ``$EMPTY``: Asserts that stdout is empty.

        Example (`verify_response.robot`):
        | =Setting= | =Value=                                            |
        | Library   | robotframework_okw_remote_ssh.RemoteSshLibrary     |
        |           |                                                    |
        | =Test Cases=  |           |                     |              |
        | Verify Stdout Exact Match  |                    |              |
        |     Open Remote Session    | r1                | myserver      |
        |     Set Remote             | r1                | hostname      |
        |     Verify Remote Response | r1                | buildserver01 |
        |     Close Remote Session   | r1                |               |
        """
        actual = str(self._get_response_field(session_name, "stdout") or "")
        expected_expanded = expand_mem(expected, self._store)
        if self._check_ignore(expected_expanded):
            return
        expected_expanded = self._resolve_empty_token(expected_expanded)
        assert_match(actual, expected_expanded, MatchMode.EXACT, context=f"[{session_name}] stdout")

    @keyword("Verify Remote Response WCM")
    def verify_remote_response_wcm(self, session_name: str, pattern: str):
        """Verifies that stdout of the last command contains the pattern (wildcard/contains match).

        Arguments:
        - ``session_name``: The session to verify (e.g. ``r1``).
        - ``pattern``: The wildcard pattern to match against stdout.
          Supports ``$MEM{KEY}`` expansion.

        Special tokens:
        - ``$IGNORE``: Skips verification (PASS).
        - ``$EMPTY``: Asserts that stdout is empty.

        Example (`verify_response_wcm.robot`):
        | =Setting= | =Value=                                            |
        | Library   | robotframework_okw_remote_ssh.RemoteSshLibrary     |
        |           |                                                    |
        | =Test Cases=  |           |                          |         |
        | Verify Stdout Contains Substring |                   |         |
        |     Open Remote Session          | r1               | myserver |
        |     Set Remote                   | r1               | uname -a |
        |     Verify Remote Response WCM   | r1               | Linux    |
        |     Close Remote Session         | r1               |          |
        """
        actual = str(self._get_response_field(session_name, "stdout") or "")
        pattern_expanded = expand_mem(pattern, self._store)
        if self._check_ignore(pattern_expanded):
            return
        pattern_expanded = self._resolve_empty_token(pattern_expanded)
        assert_match(actual, pattern_expanded, MatchMode.WCM, context=f"[{session_name}] stdout")

    @keyword("Verify Remote Response REGX")
    def verify_remote_response_regx(self, session_name: str, regex: str):
        """Verifies that stdout of the last command matches a regular expression.

        Arguments:
        - ``session_name``: The session to verify (e.g. ``r1``).
        - ``regex``: The regular expression pattern to match against stdout.
          Supports ``$MEM{KEY}`` expansion.

        Special tokens:
        - ``$IGNORE``: Skips verification (PASS).
        - ``$EMPTY``: Asserts that stdout is empty.

        Example (`verify_response_regx.robot`):
        | =Setting= | =Value=                                            |
        | Library   | robotframework_okw_remote_ssh.RemoteSshLibrary     |
        |           |                                                    |
        | =Test Cases=  |           |                           |        |
        | Verify Stdout Matches Regex |                         |        |
        |     Open Remote Session     | r1                     | myserver |
        |     Set Remote              | r1                     | date +%Y-%m-%d |
        |     Verify Remote Response REGX | r1                 | ^\\d{4}-\\d{2}-\\d{2}$ |
        |     Close Remote Session    | r1                     |         |
        """
        actual = str(self._get_response_field(session_name, "stdout") or "")
        regex_expanded = expand_mem(regex, self._store)
        if self._check_ignore(regex_expanded):
            return
        regex_expanded = self._resolve_empty_token(regex_expanded)
        assert_match(actual, regex_expanded, MatchMode.REGX, context=f"[{session_name}] stdout")

    @keyword("Verify Remote Stderr")
    def verify_remote_stderr(self, session_name: str, expected: str = "$EMPTY"):
        """Verifies that stderr of the last command matches the expected value (EXACT match).

        Arguments:
        - ``session_name``: The session to verify (e.g. ``r1``).
        - ``expected``: The expected stderr value (default: ``$EMPTY``).
          Supports ``$MEM{KEY}`` expansion.

        Default semantics:
        - When called without ``expected``, asserts that stderr is empty.

        Special tokens:
        - ``$IGNORE``: Skips verification (PASS).
        - ``$EMPTY``: Asserts that stderr is empty.

        Example (`verify_stderr.robot`):
        | =Setting= | =Value=                                            |
        | Library   | robotframework_okw_remote_ssh.RemoteSshLibrary     |
        |           |                                                    |
        | =Test Cases=  |           |                          |         |
        | Assert No Stderr Output  |                           |         |
        |     Open Remote Session  | r1                       | myserver |
        |     Set Remote           | r1                       | echo ok  |
        |     Verify Remote Stderr | r1                       |          |
        |     Close Remote Session | r1                       |          |
        |           |               |                          |         |
        | Assert Stderr Contains Error Message |               |         |
        |     Open Remote Session  | r1                       | myserver |
        |     Set Remote And Continue | r1                    | ls /nonexistent |
        |     Verify Remote Stderr | r1 | No such file or directory      |
        |     Close Remote Session | r1                       |          |
        """
        actual = str(self._get_response_field(session_name, "stderr") or "")
        expected_expanded = expand_mem(expected, self._store)
        if self._check_ignore(expected_expanded):
            return
        expected_expanded = self._resolve_empty_token(expected_expanded)
        assert_match(actual, expected_expanded, MatchMode.EXACT, context=f"[{session_name}] stderr")

    @keyword("Verify Remote Stderr WCM")
    def verify_remote_stderr_wcm(self, session_name: str, pattern: str = "$EMPTY"):
        """Verifies that stderr of the last command contains the pattern (wildcard/contains match).

        Arguments:
        - ``session_name``: The session to verify (e.g. ``r1``).
        - ``pattern``: The wildcard pattern to match against stderr (default: ``$EMPTY``).
          Supports ``$MEM{KEY}`` expansion.

        Default semantics:
        - When called without ``pattern``, asserts that stderr is empty.

        Special tokens:
        - ``$IGNORE``: Skips verification (PASS).
        - ``$EMPTY``: Asserts that stderr is empty.

        Example (`verify_stderr_wcm.robot`):
        | =Setting= | =Value=                                            |
        | Library   | robotframework_okw_remote_ssh.RemoteSshLibrary     |
        |           |                                                    |
        | =Test Cases=  |           |                              |     |
        | Stderr Contains Warning Substring |                      |     |
        |     Open Remote Session       | r1                      | myserver |
        |     Set Remote And Continue   | r1                      | make build |
        |     Verify Remote Stderr WCM  | r1                      | *warning* |
        |     Close Remote Session      | r1                      |      |
        """
        actual = str(self._get_response_field(session_name, "stderr") or "")
        pattern_expanded = expand_mem(pattern, self._store)
        if self._check_ignore(pattern_expanded):
            return
        pattern_expanded = self._resolve_empty_token(pattern_expanded)
        assert_match(actual, pattern_expanded, MatchMode.WCM, context=f"[{session_name}] stderr")

    @keyword("Verify Remote Stderr REGX")
    def verify_remote_stderr_regx(self, session_name: str, regex: str = "$EMPTY"):
        """Verifies that stderr of the last command matches a regular expression.

        Arguments:
        - ``session_name``: The session to verify (e.g. ``r1``).
        - ``regex``: The regular expression pattern to match against stderr
          (default: ``$EMPTY``). Supports ``$MEM{KEY}`` expansion.

        Default semantics:
        - When called without ``regex``, asserts that stderr is empty.

        Special tokens:
        - ``$IGNORE``: Skips verification (PASS).
        - ``$EMPTY``: Asserts that stderr is empty.

        Example (`verify_stderr_regx.robot`):
        | =Setting= | =Value=                                            |
        | Library   | robotframework_okw_remote_ssh.RemoteSshLibrary     |
        |           |                                                    |
        | =Test Cases=  |           |                              |     |
        | Stderr Matches Error Pattern |                           |     |
        |     Open Remote Session      | r1                       | myserver |
        |     Set Remote And Continue  | r1                       | python3 broken.py |
        |     Verify Remote Stderr REGX | r1                      | .*Error.* |
        |     Close Remote Session     | r1                       |      |
        """
        actual = str(self._get_response_field(session_name, "stderr") or "")
        regex_expanded = expand_mem(regex, self._store)
        if self._check_ignore(regex_expanded):
            return
        regex_expanded = self._resolve_empty_token(regex_expanded)
        assert_match(actual, regex_expanded, MatchMode.REGX, context=f"[{session_name}] stderr")

    @keyword("Verify Remote Exit Code")
    def verify_remote_exit_code(self, session_name: str, expected_exit_code: str):
        """Verifies the exit code of the last command (numeric exact compare).

        Arguments:
        - ``session_name``: The session to verify (e.g. ``r1``).
        - ``expected_exit_code``: The expected exit code as string or integer.
          Supports ``$MEM{KEY}`` expansion.

        Special tokens:
        - ``$IGNORE``: Skips verification (PASS).

        Example (`verify_exit_code.robot`):
        | =Setting= | =Value=                                            |
        | Library   | robotframework_okw_remote_ssh.RemoteSshLibrary     |
        |           |                                                    |
        | =Test Cases=  |           |                          |         |
        | Verify Successful Command |                          |         |
        |     Open Remote Session     | r1                    | myserver |
        |     Set Remote              | r1                    | echo ok  |
        |     Verify Remote Exit Code | r1                    | 0        |
        |     Close Remote Session    | r1                    |          |
        |           |                  |                       |         |
        | Verify Expected Failure     |                        |         |
        |     Open Remote Session     | r1                    | myserver |
        |     Set Remote And Continue | r1                    | exit 42  |
        |     Verify Remote Exit Code | r1                    | 42       |
        |     Close Remote Session    | r1                    |          |
        """
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
        """Verifies the execution duration (in milliseconds) of the last command.

        Arguments:
        - ``session_name``: The session to verify (e.g. ``r1``).
        - ``expr``: A comparison expression or range. Supports ``$MEM{KEY}`` expansion.

        Supported expressions:
        | *Syntax*  | *Meaning*                           |
        | >=100     | Duration is at least 100 ms         |
        | <=5000    | Duration is at most 5000 ms         |
        | >0        | Duration is greater than 0 ms       |
        | <10000    | Duration is less than 10000 ms      |
        | ==500     | Duration is exactly 500 ms          |
        | 100..5000 | Duration is between 100 and 5000 ms |

        Special tokens:
        - ``$IGNORE``: Skips verification (PASS).

        Example (`verify_duration.robot`):
        | =Setting= | =Value=                                            |
        | Library   | robotframework_okw_remote_ssh.RemoteSshLibrary     |
        |           |                                                    |
        | =Test Cases=  |           |                           |        |
        | Command Completes Within Timeout |                    |        |
        |     Open Remote Session     | r1                     | myserver |
        |     Set Remote              | r1                     | sleep 1 |
        |     Verify Remote Duration  | r1                     | >=1000  |
        |     Verify Remote Duration  | r1                     | 500..3000 |
        |     Close Remote Session    | r1                     |         |
        """
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
        """Stores a field from the last response into the internal value store for later ``$MEM{KEY}`` expansion.

        Arguments:
        - ``session_name``: The session to read from (e.g. ``r1``).
        - ``field``: The response field to store. One of: ``command``, ``stdout``,
          ``stderr``, ``exit_code``, ``duration_ms``.
        - ``key``: The key name for ``$MEM{KEY}`` references in subsequent keywords.

        Behavior:
        - Reads the specified field from ``last_response``.
        - Stores the value in the internal store under the given key.
        - Fails if no ``last_response`` exists or the field name is unknown.

        Example (`memorize_field.robot`):
        | =Setting= | =Value=                                            |
        | Library   | robotframework_okw_remote_ssh.RemoteSshLibrary     |
        |           |                                                    |
        | =Test Cases=  |           |                           |        |
        | Store And Reuse Hostname  |                           |        |
        |     Open Remote Session          | r1                | myserver |
        |     Set Remote                   | r1                | hostname |
        |     Memorize Remote Response Field | r1              | stdout   | HOST |
        |     Set Remote                   | r1                | ping -c1 $MEM{HOST} |
        |     Verify Remote Exit Code      | r1                | 0        |
        |     Close Remote Session         | r1                |          |
        """
        resp = self._ensure_last_response(session_name)
        if field not in resp:
            raise ValueError(f"Unknown response field: {field}")
        self._store[key] = resp[field]
