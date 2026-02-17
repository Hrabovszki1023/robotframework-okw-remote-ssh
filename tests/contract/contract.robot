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
    Verify Remote Response WCM    r1    *world
    Close Remote Session   r1

Verify Response WCM Question Mark Should Work
    Open Remote Session    r1    dummy
    Set Remote             r1    Date: 23.10.1963
    Verify Remote Response WCM    r1    Date: ??.??.????
    Close Remote Session   r1

Verify Response REGX Should Work
    Open Remote Session    r1    dummy
    Set Remote             r1    hello world 42
    Verify Remote Response REGX    r1    world\\s+\\d+
    Close Remote Session   r1

Verify Stderr WCM Should Work
    Open Remote Session    r1    dummy
    Set Remote             r1    abc
    # Stub stderr is empty -> WCM empty pattern matches empty string
    Verify Remote Stderr WCM    r1    ${EMPTY}
    Close Remote Session   r1

Verify Response WCM Combined Should Work
    Open Remote Session    r1    dummy
    Set Remote             r1    Name Hans Mueller Datum 23.10.1963 Ort Graz
    Verify Remote Response WCM    r1    *Hans Mueller* ??.??.???? *
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

# ---- File Transfer Keywords ----

Put Remote File Should Work
    [Documentation]    Stub simulates upload; last_response contains transfer metrics.
    Open Remote Session    r1    dummy
    Put Remote File    r1    ${CURDIR}/fixtures/testfile.txt    /tmp/testfile.txt
    Close Remote Session   r1

Get Remote File Should Work
    [Documentation]    Stub simulates download; last_response contains transfer metrics.
    Open Remote Session    r1    dummy
    Get Remote File    r1    /tmp/testfile.txt    ${OUTPUTDIR}/downloaded.txt
    Close Remote Session   r1

Put Remote Directory Should Work
    [Documentation]    Stub simulates recursive directory upload.
    Open Remote Session    r1    dummy
    Put Remote Directory    r1    ${CURDIR}/fixtures    /tmp/fixtures
    Close Remote Session   r1

Get Remote Directory Should Work
    [Documentation]    Stub simulates recursive directory download.
    Open Remote Session    r1    dummy
    Get Remote Directory    r1    /tmp/fixtures    ${OUTPUTDIR}/downloaded_dir
    Close Remote Session   r1

Verify Remote File Exists Should Work
    [Documentation]    Stub always passes for Verify Remote File Exists.
    Open Remote Session    r1    dummy
    Verify Remote File Exists    r1    /tmp/testfile.txt
    Close Remote Session   r1

Verify Remote Directory Exists Should Work
    [Documentation]    Stub always passes for Verify Remote Directory Exists.
    Open Remote Session    r1    dummy
    Verify Remote Directory Exists    r1    /tmp/fixtures
    Close Remote Session   r1

Remove Remote File Should Work
    [Documentation]    Stub logs the removal action.
    Open Remote Session    r1    dummy
    Remove Remote File    r1    /tmp/testfile.txt
    Close Remote Session   r1

Remove Remote Directory Should Work
    [Documentation]    Stub logs the removal action.
    Open Remote Session    r1    dummy
    Remove Remote Directory    r1    /tmp/fixtures
    Close Remote Session   r1

Ignore Token Should Skip Put Remote File
    Open Remote Session    r1    dummy
    Put Remote File    r1    ${IGNORE}    /tmp/ignored.txt
    Close Remote Session   r1

Ignore Token Should Skip Get Remote File
    Open Remote Session    r1    dummy
    Get Remote File    r1    ${IGNORE}    ${OUTPUTDIR}/ignored.txt
    Close Remote Session   r1

Ignore Token Should Skip Verify Remote File Exists
    Open Remote Session    r1    dummy
    Verify Remote File Exists    r1    ${IGNORE}
    Close Remote Session   r1

Ignore Token Should Skip Remove Remote File
    Open Remote Session    r1    dummy
    Remove Remote File    r1    ${IGNORE}
    Close Remote Session   r1

Ignore Token Should Skip Put Remote Directory
    Open Remote Session    r1    dummy
    Put Remote Directory    r1    ${IGNORE}    /tmp/ignored_dir
    Close Remote Session   r1

Ignore Token Should Skip Remove Remote Directory
    Open Remote Session    r1    dummy
    Remove Remote Directory    r1    ${IGNORE}
    Close Remote Session   r1

Put Remote File Should Store Last Response
    [Documentation]    Verifies that Put Remote File stores transfer metrics in last_response.
    Open Remote Session    r1    dummy
    Put Remote File    r1    ${CURDIR}/fixtures/testfile.txt    /tmp/testfile.txt
    Memorize Remote Response Field    r1    action    PUT_ACTION
    Set Remote    r1    $MEM{PUT_ACTION}
    Verify Remote Response    r1    put_file
    Close Remote Session   r1
