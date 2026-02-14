*** Settings ***
Library    robotframework_okw_remote_ssh.RemoteSshLibrary

*** Test Cases ***
Library Should Load
    Connect Remote    test    dummy_config
    Execute Remote    test    echo hello
    Close Remote      test
