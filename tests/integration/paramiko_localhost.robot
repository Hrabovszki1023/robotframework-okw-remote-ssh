*** Settings ***
Library    robotframework_okw_remote_ssh.RemoteSshLibrary    backend=paramiko

*** Test Cases ***
Windows Localhost SSH
    Open Remote Session    r1    localhost
    Execute Remote         r1    powershell -Command "Write-Output hello"
    Verify Remote Response    r1    hello
    Close Remote Session   r1
