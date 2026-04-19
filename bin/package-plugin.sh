#!/usr/bin/env bash

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD_DIR="${ROOT_DIR}/build"
OUTPUT_FILE="${BUILD_DIR}/wp-2fa-guardian.zip"
STAGE_DIR="${BUILD_DIR}/stage"
PACKAGE_DIR="${STAGE_DIR}/wp-2fa-guardian"

mkdir -p "${BUILD_DIR}"
rm -f "${OUTPUT_FILE}"
rm -rf "${STAGE_DIR}"
mkdir -p "${PACKAGE_DIR}"

rsync -a "${ROOT_DIR}/" "${PACKAGE_DIR}/" \
  --exclude='.git/' \
  --exclude='build/' \
  --exclude='.DS_Store' \
  --exclude='**/.DS_Store' \
  --exclude='.github/' \
  --exclude='tests/' \
  --exclude='bin/' \
  --exclude='vendor/' \
  --exclude='composer.lock' \
  --exclude='phpunit.xml.dist' \
  --exclude='.gitattributes' \
  --exclude='.gitignore' \
  --exclude='README.md'

cd "${STAGE_DIR}"

zip -r "${OUTPUT_FILE}" "wp-2fa-guardian"

echo "Created ${OUTPUT_FILE}"
