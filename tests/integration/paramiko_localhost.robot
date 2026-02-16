*** Settings ***
Library    robotframework_okw_remote_ssh.RemoteSshLibrary    backend=paramiko

*** Test Cases ***
Windows Localhost SSH
    Open Remote Session    r1    localhost
    Set Remote             r1    cmd /c echo hello
    Verify Remote Response WCM    r1    hello
    Close Remote Session   r1
