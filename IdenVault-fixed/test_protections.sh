#!/bin/bash
set -e

# Setup test environment
echo "[*] Setting up test environment..."
mkdir -p /tmp/idenvault_test
rm -rf /tmp/idenvault_test/*

# Assume IdenVault binary is on Desktop
IV_BIN="$HOME/Área de trabalho/IdenVault"

echo "[*] Testing Vault Creation..."
# Create a normal vault (no password) to easily test FUSE and WORM
# vault-create <name> <path> <type>
echo -e "0\n" | "$IV_BIN" vault-create test_vault /tmp/idenvault_test/vault_dir normal > /dev/null

echo "[*] Extracting Vault ID..."
# List vaults and grep for test_vault to get its ID
VAULT_ID=$("$IV_BIN" vault-list | grep test_vault | awk '{print $2}')
echo "Vault ID is: $VAULT_ID"

echo "[*] Testing WORM Protections via FUSE..."
# Mount the vault
"$IV_BIN" mount-fuse $VAULT_ID "" > /dev/null

# The mount point is in ~/.local/share/idenvault/test_vault
MNT="$HOME/.local/share/idenvault/test_vault"
sleep 1 # wait for mount

echo "[*] Writing initial file (allowed)..."
echo "secret data" > "$MNT/secret.txt"
cat "$MNT/secret.txt"

echo "[*] Activating WORM: --no-write"
"$IV_BIN" worm-protect $VAULT_ID --no-write > /dev/null

echo "[*] Testing Write Block..."
if echo "new data" > "$MNT/secret.txt" 2>/dev/null; then
    echo "ERROR: Write succeeded when it should have been blocked!"
    exit 1
else
    echo "SUCCESS: Write blocked by WORM."
fi

echo "[*] Activating WORM: --protect-delete"
"$IV_BIN" worm-protect $VAULT_ID --protect-delete > /dev/null

echo "[*] Testing Delete Block..."
if rm "$MNT/secret.txt" 2>/dev/null; then
    echo "ERROR: Delete succeeded when it should have been blocked!"
    exit 1
else
    echo "SUCCESS: Delete blocked by WORM."
fi

echo "[*] Activating WORM: --protect-rename"
"$IV_BIN" worm-protect $VAULT_ID --protect-rename > /dev/null

echo "[*] Testing Rename Block..."
if mv "$MNT/secret.txt" "$MNT/hacked.txt" 2>/dev/null; then
    echo "ERROR: Rename succeeded when it should have been blocked!"
    exit 1
else
    echo "SUCCESS: Rename blocked by WORM."
fi

echo "[*] Activating WORM: --protect-read"
"$IV_BIN" worm-protect $VAULT_ID --protect-read > /dev/null

echo "[*] Testing Read Block..."
if cat "$MNT/secret.txt" > /dev/null 2>&1; then
    echo "ERROR: Read succeeded when it should have been blocked!"
    exit 1
else
    echo "SUCCESS: Read blocked by WORM."
fi

echo "[*] Unmounting..."
"$IV_BIN" umount-fuse $VAULT_ID > /dev/null
sleep 1

echo "[*] All WORM tests passed!"
