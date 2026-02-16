*** Settings ***
Library    robotframework_okw_remote_ssh.RemoteSshLibrary

*** Variables ***
${IGNORE}         $IGNORE
${EMPTY_TOKEN}    $EMPTY

*** Test Cases ***
Value Expansion Should Work
    Open Remote Session    r1    dummy
    Set Remote    r1    abc
    Memorize Remote Response Field    r1    stdout    MYKEY
    Set Remote    r1    prefix-$MEM{MYKEY}-suffix
    Verify Remote Response    r1    prefix-abc-suffix
    Close Remote Session    r1

Value Expansion Should Fail On Missing Key
    Open Remote Session    r1    dummy
    Run Keyword And Expect Error    *    Set Remote    r1    test-$MEM{UNKNOWN}
    Close Remote Session    r1

Open Remote Session Should Fail On Unknown Config
    Run Keyword And Expect Error    *    Open Remote Session    rX    unknown_config

Open Remote Session Should Fail On Invalid Name
    Run Keyword And Expect Error    *    Open Remote Session    rX    ../hack

Open Remote Session Should Fail On Missing Host
    Run Keyword And Expect Error    *    Open Remote Session    rX    missing_host

Verify Stderr Should Work
    Open Remote Session    r1    dummy
    Set Remote             r1    abc
    # Stub sets stderr empty -> verify empty (default: no expected arg)
    Verify Remote Stderr   r1
    Close Remote Session   r1

Verify Exit Code Should Work
    Open Remote Session    r1    dummy
    Set Remote             r1    abc
    Verify Remote Exit Code    r1    0
    Close Remote Session   r1

Verify Duration Should Work
    Open Remote Session    r1    dummy
    Set Remote             r1    abc
    Verify Remote Duration    r1    >=0
    Close Remote Session   r1

Ignore Token Should Skip Set Remote
    Open Remote Session    r1    dummy
    Set Remote             r1    abc
    Verify Remote Response    r1    abc

    # $IGNORE skips the next action, last_response unchanged
    Set Remote             r1    ${IGNORE}

    # last_response should still be the previous successful command
    Verify Remote Response    r1    abc
    Close Remote Session   r1

Ignore Token Should Skip Verify Response
    Open Remote Session    r1    dummy
    Set Remote             r1    abc
    # $IGNORE skips verification -> PASS regardless of actual value
    Verify Remote Response    r1    ${IGNORE}
    Close Remote Session   r1

Ignore Token Should Skip Verify Exit Code
    Open Remote Session    r1    dummy
    Set Remote             r1    abc
    Verify Remote Exit Code    r1    ${IGNORE}
    Close Remote Session   r1

Ignore Token Should Skip Verify Duration
    Open Remote Session    r1    dummy
    Set Remote             r1    abc
    Verify Remote Duration    r1    ${IGNORE}
    Close Remote Session   r1

Empty Token Should Verify Stderr Empty
    Open Remote Session    r1    dummy
    Set Remote             r1    abc
    Verify Remote Stderr   r1    ${EMPTY_TOKEN}
    Close Remote Session   r1

Verify Stderr With Empty String Should Work
    Open Remote Session    r1    dummy
    Set Remote             r1    abc
    # Robot ${EMPTY} = "" -> EXACT match against "" -> PASS (stderr is empty)
    Verify Remote Stderr   r1    ${EMPTY}
    Close Remote Session   r1

Verify Response Should Work
    Open Remote Session    r1    dummy
    Set Remote             r1    hello world
    Verify Remote Response    r1    hello world
    Close Remote Session   r1

Verify Response WCM Should Work
    Open Remote Session    r1    dummy
    Set Remote             r1    hello world
    Verify Remote Response WCM    r1    world
    Close Remote Session   r1

Verify Response REGX Should Work
    Open Remote Session    r1    dummy
    Set Remote             r1    hello world 42
    Verify Remote Response REGX    r1    world\\s+\\d+
    Close Remote Session   r1

Verify Stderr WCM Should Work
    Open Remote Session    r1    dummy
    Set Remote             r1    abc
    # Stub stderr is empty -> WCM match against empty string
    Verify Remote Stderr WCM    r1    ${EMPTY}
    Close Remote Session   r1

Verify Stderr REGX Should Work
    Open Remote Session    r1    dummy
    Set Remote             r1    abc
    # Stub stderr is empty -> REGX match against ^$
    Verify Remote Stderr REGX    r1    ^$
    Close Remote Session   r1

Set Remote And Continue Should Not Fail On Nonzero Exit
    [Documentation]    Stub always returns exit_code=0, so this just verifies the keyword exists and works.
    Open Remote Session    r1    dummy
    Set Remote And Continue    r1    abc
    Verify Remote Exit Code    r1    0
    Close Remote Session   r1
