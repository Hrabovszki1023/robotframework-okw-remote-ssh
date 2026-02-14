*** Settings ***
Library    robotframework_okw_remote_ssh.RemoteSshLibrary

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
