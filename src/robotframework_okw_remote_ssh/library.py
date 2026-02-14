from robot.api.deco import keyword, library
from okw_contract_utils import expand_mem, MatchMode, assert_match


@library(scope="GLOBAL")
class RemoteSshLibrary:
    """
    Standalone Robot Framework library for deterministic remote interaction.
    Contract-first: Action (Set Remote) writes last_response, Verify reads it.
    """

    def __init__(self):
        self._sessions: dict[str, dict] = {}
        self._store: dict[str, object] = {}

    # -------------------------
    # Internal helpers
    # -------------------------
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

    # -------------------------
    # Session lifecycle
    # -------------------------
    @keyword("Open Remote Session")
    def open_remote_session(self, session_name: str, config_ref: str):
        if session_name in self._sessions:
            raise ValueError(f"Session '{session_name}' already exists.")
        self._sessions[session_name] = {
            "config_ref": config_ref,
            "connected": True,   # placeholder for later paramiko client
            "last_response": None,
        }

    @keyword("Close Remote Session")
    def close_remote_session(self, session_name: str):
        self._ensure_session(session_name)
        del self._sessions[session_name]

    # -------------------------
    # Action
    # -------------------------
    @keyword("Set Remote")
    def set_remote(self, session_name: str, command: str):
        """
        Executes a command (synchronously) and stores the structured response in last_response.
        Applies $MEM{KEY} expansion before execution.
        """
        s = self._ensure_session(session_name)

        expanded_command = expand_mem(command, self._store)

        # STUB التنفيذ: replace with Paramiko backend later
        response = {
            "command": expanded_command,
            "stdout": expanded_command,  # for contract tests
            "stderr": "",
            "exit_code": 0,
            "duration_ms": 0,
        }
        s["last_response"] = response

    # -------------------------
    # Verify (reads last_response only)
    # -------------------------
    @keyword("Verify Remote Response")
    def verify_remote_response(self, session_name: str, expected: str):
        resp = self._ensure_last_response(session_name)
        actual = resp.get("stdout", "") or ""
        expected_expanded = expand_mem(expected, self._store)
        assert_match(actual, expected_expanded, MatchMode.EXACT, context=f"[{session_name}] stdout")

    @keyword("Verify Remote Response WCM")
    def verify_remote_response_wcm(self, session_name: str, expected: str):
        resp = self._ensure_last_response(session_name)
        actual = resp.get("stdout", "") or ""
        expected_expanded = expand_mem(expected, self._store)
        assert_match(actual, expected_expanded, MatchMode.WCM, context=f"[{session_name}] stdout")

    @keyword("Verify Remote Response REGX")
    def verify_remote_response_regx(self, session_name: str, pattern: str):
        resp = self._ensure_last_response(session_name)
        actual = resp.get("stdout", "") or ""
        pattern_expanded = expand_mem(pattern, self._store)
        assert_match(actual, pattern_expanded, MatchMode.REGX, context=f"[{session_name}] stdout")

    @keyword("Verify Remote Exit Code")
    def verify_remote_exit_code(self, session_name: str, expected_exit_code: int):
        resp = self._ensure_last_response(session_name)
        actual = resp.get("exit_code", None)
        if actual != int(expected_exit_code):
            raise AssertionError(
                f"[{session_name}] exit_code mismatch. Expected {int(expected_exit_code)}, got {actual}."
            )

    # -------------------------
    # Memorize
    # -------------------------
    @keyword("Memorize Remote Response Field")
    def memorize_remote_response_field(self, session_name: str, field: str, key: str):
        resp = self._ensure_last_response(session_name)
        if field not in resp:
            raise ValueError(f"Unknown response field: {field}")
        self._store[key] = resp[field]
