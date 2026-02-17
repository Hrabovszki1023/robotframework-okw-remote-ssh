*** Settings ***
Documentation     Live SSH integration test.
...               Requires a real SSH server. Configure via:
...               ~/.okw/configs/testhost.yaml  (host, port, username)
...               ~/.okw/secrets.yaml           (password or key_file)
...
...               Run:  python -m robot tests/install/test_ssh_live.robot

Library           robotframework_okw_remote_ssh    backend=paramiko

*** Variables ***
${SESSION}    testhost
${CONFIG}     testhost

*** Test Cases ***
Open Session And Execute Command
    [Documentation]    Opens a real SSH session, runs a command, verifies output.
    Open Remote Session    ${SESSION}    ${CONFIG}
    Set Remote             ${SESSION}    echo Hello from OKW
    Verify Remote Response    ${SESSION}    Hello from OKW
    Verify Remote Stderr   ${SESSION}
    Verify Remote Exit Code    ${SESSION}    0
    Close Remote Session   ${SESSION}

Verify Exit Code On Failing Command
    [Documentation]    Runs a command that fails, verifies exit code.
    Open Remote Session    ${SESSION}    ${CONFIG}
    Set Remote And Continue    ${SESSION}    exit 42
    Verify Remote Exit Code    ${SESSION}    42
    Close Remote Session    ${SESSION}

WCM And REGX Matching
    [Documentation]    Tests wildcard and regex matching against real stdout.
    Open Remote Session    ${SESSION}    ${CONFIG}
    Set Remote             ${SESSION}    echo "Date: 23.10.1963"
    Verify Remote Response WCM     ${SESSION}    *??.??.????*
    Verify Remote Response REGX    ${SESSION}    Date:\\s+\\d{2}\\.\\d{2}\\.\\d{4}
    Close Remote Session    ${SESSION}

File Transfer Round Trip
    [Documentation]    Uploads a file, verifies existence, downloads, removes.
    Open Remote Session    ${SESSION}    ${CONFIG}

    # Create a local temp file
    Set Remote    ${SESSION}    echo "OKW test content" > /tmp/okw_upload_test.txt

    # Verify it exists
    Verify Remote File Exists    ${SESSION}    /tmp/okw_upload_test.txt    YES

    # Remove and verify gone
    Remove Remote File    ${SESSION}    /tmp/okw_upload_test.txt
    Verify Remote File Exists    ${SESSION}    /tmp/okw_upload_test.txt    NO

    Close Remote Session    ${SESSION}
