#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="backend/app/continuous_compliance"

if [ ! -d "$BASE_DIR" ]; then
  echo "ERROR: $BASE_DIR not found"
  exit 1
fi

echo "[+] Replacing invalid backend.app imports in active Python files..."

find "$BASE_DIR" \
  -type f \
  -name "*.py" \
  ! -name "*.bak.*" \
  -exec sed -i 's/from backend\.app\./from app./g' {} \;

find "$BASE_DIR" \
  -type f \
  -name "*.py" \
  ! -name "*.bak.*" \
  -exec sed -i 's/import backend\.app\./import app./g' {} \;

echo "[+] Validating active files only..."

if find "$BASE_DIR" \
  -type f \
  -name "*.py" \
  ! -name "*.bak.*" \
  -exec grep -H "backend.app" {} \; | grep .; then
  echo "[!] Remaining invalid imports detected in active files."
  exit 1
fi

echo "[+] Import correction completed successfully."
