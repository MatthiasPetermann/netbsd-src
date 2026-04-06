#!/bin/sh
set -eu

mantis_version=2.28.1
mantis_url="https://sourceforge.net/projects/mantisbt/files/mantis-stable/${mantis_version}/mantisbt-${mantis_version}.tar.gz/download"
mantis_sha256=688572cf4a3c99327b8f92b79442e51d887d75218a690d5f1ac34a90af752e85
tarball="/tmp/mantisbt-release-${mantis_version}.tar.gz"
app_root=/var/www/mantisbt

install -d -m 0755 -o fpm -g www "${app_root}"

if [ ! -f "${app_root}/core/constant_inc.php" ] || ! grep -q "MANTIS_VERSION.*${mantis_version}" "${app_root}/core/constant_inc.php"; then
  rm -f "${tarball}"
  ftp -o "${tarball}" "${mantis_url}"

  downloaded_sha256=$(sha256 -q "${tarball}")
  if [ "${downloaded_sha256}" != "${mantis_sha256}" ]; then
    echo "unexpected SHA256 for ${tarball}" >&2
    exit 1
  fi

  rm -rf "${app_root}"/* "${app_root}"/.[!.]* "${app_root}"/..?*
  tar -xzf "${tarball}" --strip-components=1 -C "${app_root}"
  rm -f "${tarball}"
fi

if [ ! -f "${app_root}/vendor/autoload.php" ]; then
  echo "missing ${app_root}/vendor/autoload.php in release archive" >&2
  exit 1
fi

install -d -m 0755 -o fpm -g www "${app_root}/config"
chown -R fpm:www "${app_root}" /var/db/mantisbt

if [ -f "${app_root}/config/config_inc.php" ]; then
  chmod 0640 "${app_root}/config/config_inc.php"
fi
