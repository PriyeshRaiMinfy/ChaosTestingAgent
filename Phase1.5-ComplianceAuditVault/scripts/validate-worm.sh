#!/usr/bin/env bash
# Post-deploy smoke test: proves the WORM vault actually denies illegal operations.
# Run AFTER cdk deploy VaultAccountStack
set -euo pipefail

BUCKET="${1:?Usage: validate-worm.sh <bucket-name>}"
TEST_FILE="/tmp/worm-test-$(date +%s).txt"
echo "test content" > "$TEST_FILE"

echo "=== WORM Vault Validation ==="
echo "Bucket: $BUCKET"
echo ""

# Test 1: Unencrypted write should FAIL
echo "[TEST 1] Attempting unencrypted PutObject (should be DENIED)..."
if aws s3 cp "$TEST_FILE" "s3://$BUCKET/test/unencrypted.txt" 2>/dev/null; then
    echo "  FAIL — unencrypted write was allowed!"
    exit 1
else
    echo "  PASS — unencrypted write denied"
fi

# Test 2: KMS-encrypted write should SUCCEED
echo "[TEST 2] Attempting KMS-encrypted PutObject (should SUCCEED)..."
if aws s3 cp "$TEST_FILE" "s3://$BUCKET/test/encrypted.txt" \
    --sse aws:kms 2>/dev/null; then
    echo "  PASS — KMS-encrypted write succeeded"
else
    echo "  FAIL — KMS-encrypted write was denied!"
    exit 1
fi

# Test 3: Object should have COMPLIANCE lock
echo "[TEST 3] Checking Object Lock retention on uploaded object..."
RETENTION=$(aws s3api get-object-retention \
    --bucket "$BUCKET" \
    --key "test/encrypted.txt" \
    --query 'Retention.Mode' --output text 2>/dev/null || echo "NONE")

if [ "$RETENTION" = "COMPLIANCE" ]; then
    echo "  PASS — Object Lock mode is COMPLIANCE"
else
    echo "  FAIL — Expected COMPLIANCE, got: $RETENTION"
    exit 1
fi

# Test 4: Attempt to delete locked object should FAIL
echo "[TEST 4] Attempting to delete locked object (should be DENIED)..."
if aws s3 rm "s3://$BUCKET/test/encrypted.txt" 2>/dev/null; then
    echo "  FAIL — delete was allowed on locked object!"
    exit 1
else
    echo "  PASS — delete denied on locked object"
fi

echo ""
echo "=== ALL TESTS PASSED — Vault is immutable ==="
rm -f "$TEST_FILE"
