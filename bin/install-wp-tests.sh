#!/usr/bin/env bash

set -eu

if [ $# -lt 3 ]; then
  echo "Usage: $0 <db_name> <db_user> <db_pass> [db_host] [wp_version] [tests_dir]"
  exit 1
fi

DB_NAME=$1
DB_USER=$2
DB_PASS=$3
DB_HOST=${4-localhost}
WP_VERSION=${5-latest}
WP_TESTS_DIR=${6-/tmp/wordpress-tests-lib}
WP_CORE_DIR=/tmp/wordpress

download() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$1" -o "$2"
  else
    wget -q "$1" -O "$2"
  fi
}

mkdir -p "$WP_TESTS_DIR"
mkdir -p "$WP_CORE_DIR"

if [ ! -f "$WP_CORE_DIR/wp-load.php" ]; then
  archive=/tmp/wordpress.tar.gz
  if [ "$WP_VERSION" = "latest" ]; then
    download https://wordpress.org/latest.tar.gz "$archive"
  else
    download "https://wordpress.org/wordpress-${WP_VERSION}.tar.gz" "$archive"
  fi

  tar -xzf "$archive" -C /tmp
fi

if [ ! -f "$WP_TESTS_DIR/includes/functions.php" ]; then
  svn export --quiet https://develop.svn.wordpress.org/trunk/tests/phpunit/includes/ "$WP_TESTS_DIR/includes/"
  svn export --quiet https://develop.svn.wordpress.org/trunk/tests/phpunit/data/ "$WP_TESTS_DIR/data/"
fi

cat > "$WP_TESTS_DIR/wp-tests-config.php" <<EOF
<?php
define( 'DB_NAME', '${DB_NAME}' );
define( 'DB_USER', '${DB_USER}' );
define( 'DB_PASSWORD', '${DB_PASS}' );
define( 'DB_HOST', '${DB_HOST}' );
define( 'DB_CHARSET', 'utf8' );
define( 'DB_COLLATE', '' );

\$table_prefix = 'wptests_';

define( 'ABSPATH', '${WP_CORE_DIR}/' );
define( 'WP_TESTS_DOMAIN', 'example.org' );
define( 'WP_TESTS_EMAIL', 'admin@example.org' );
define( 'WP_TESTS_TITLE', 'WordPress Test Site' );
define( 'WP_PHP_BINARY', 'php' );

define( 'WPLANG', '' );
define( 'WP_DEBUG', true );
define( 'WP_DEBUG_LOG', true );
define( 'WP_DEBUG_DISPLAY', false );

require_once ABSPATH . 'wp-settings.php';
EOF

if [ ! -f "$WP_CORE_DIR/wp-config.php" ]; then
  cp "$WP_TESTS_DIR/wp-tests-config.php" "$WP_CORE_DIR/wp-config.php"
fi
