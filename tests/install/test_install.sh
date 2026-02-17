#!/usr/bin/env bash
# ===========================================================================
# Install-Smoke-Test for robotframework-okw-remote-ssh
# Run this on a CLEAN machine (fresh VM / container) to verify that
# pip install from PyPI works and the library loads correctly.
#
# Prerequisites: Python >= 3.9, pip
# Usage:         bash test_install.sh
# ===========================================================================
set -euo pipefail

echo "============================================"
echo " OKW Remote SSH – Install Smoke Test"
echo "============================================"

# --- 1. Show Python version ---
echo ""
echo "[1/6] Python version:"
python3 --version

# --- 2. Create fresh virtualenv ---
echo ""
echo "[2/6] Creating fresh virtualenv..."
python3 -m venv /tmp/okw-test-venv
source /tmp/okw-test-venv/bin/activate

# --- 3. Install from PyPI ---
echo ""
echo "[3/6] Installing robotframework-okw-remote-ssh from PyPI..."
pip install --upgrade pip
pip install robotframework-okw-remote-ssh
echo ""
echo "Installed packages:"
pip list | grep -iE "okw|robot|paramiko|pyyaml"

# --- 4. Verify library import ---
echo ""
echo "[4/6] Verifying Python import..."
python3 -c "
from robotframework_okw_remote_ssh.library import RemoteSshLibrary
lib = RemoteSshLibrary()
print(f'  Library class: {lib.__class__.__name__}')
print(f'  Backend:       {lib._backend}')
print('  Import OK')
"

# --- 5. Verify Robot Framework can discover the library ---
echo ""
echo "[5/6] Verifying Robot Framework discovery..."
python3 -c "
from robot.utils import find_file
import robotframework_okw_remote_ssh
print(f'  Package location: {robotframework_okw_remote_ssh.__file__}')
print('  RF discovery OK')
"

# --- 6. Run minimal robot test ---
echo ""
echo "[6/6] Running minimal Robot Framework test..."

TMPDIR=$(mktemp -d)
cat > "$TMPDIR/smoke.robot" << 'ROBOT'
*** Settings ***
Library    robotframework_okw_remote_ssh

*** Variables ***
${IGNORE}    $IGNORE

*** Test Cases ***
Library Loads Successfully
    Log    OKW Remote SSH library loaded

Ignore Token Skips Execution
    Set Remote    stub_session    $IGNORE
    Log    IGNORE token handled correctly
ROBOT

python3 -m robot --outputdir "$TMPDIR/results" "$TMPDIR/smoke.robot"

# --- Cleanup ---
deactivate
rm -rf /tmp/okw-test-venv "$TMPDIR"

echo ""
echo "============================================"
echo " ALL CHECKS PASSED"
echo "============================================"
