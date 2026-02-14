from robot.api.deco import keyword, library


@library(scope="GLOBAL")
class RemoteSshLibrary:
    """
    Standalone Robot Framework library for deterministic SSH interaction.
    """

    def __init__(self):
        self._sessions = {}

    @keyword("Connect Remote")
    def connect_remote(self, session_name: str, config_ref: str):
        """
        Opens an SSH session and stores it under session_name.
        """
        if session_name in self._sessions:
            raise ValueError(f"Session '{session_name}' already exists.")

        # TODO: Implement real SSH connection using paramiko
        self._sessions[session_name] = {
            "config_ref": config_ref,
            "connected": True,
            "last_response": None,
        }

    @keyword("Execute Remote")
    def execute_remote(self, session_name: str, command: str):
        """
        Executes a command synchronously on the remote host.
        """
        if session_name not in self._sessions:
            raise ValueError(f"Session '{session_name}' does not exist.")

        # TODO: Real execution via paramiko
        response = {
            "stdout": f"Executed: {command}",
            "stderr": "",
            "exit_code": 0,
        }

        self._sessions[session_name]["last_response"] = response

    @keyword("Close Remote")
    def close_remote(self, session_name: str):
        """
        Closes the given SSH session.
        """
        if session_name not in self._sessions:
            raise ValueError(f"Session '{session_name}' does not exist.")

        del self._sessions[session_name]
