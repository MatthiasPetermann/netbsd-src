#!/bin/sh
set -eu

data_dir=/var/postgresql/data
secrets_dir=/var/db/mantisbt-secrets

install -d -m 0700 -o pgsql -g pgsql "${data_dir}"
install -d -m 0700 -o root -g wheel "${secrets_dir}"

if [ ! -s "${data_dir}/PG_VERSION" ]; then
  su -m pgsql -c "/usr/pkg/bin/initdb -D ${data_dir}"
fi

cat > "${data_dir}/postgresql.auto.conf" <<'EOF'
# managed by cellman mantisbt example
listen_addresses = '*'
password_encryption = 'scram-sha-256'
log_destination = 'stderr'
logging_collector = off
max_connections = 20
shared_buffers = '128MB'
EOF
chown pgsql:pgsql "${data_dir}/postgresql.auto.conf"
chmod 0600 "${data_dir}/postgresql.auto.conf"

cat > "${data_dir}/pg_hba.conf" <<'EOF'
local   all             pgsql                                   trust
local   all             all                                     scram-sha-256
host    all             all             127.0.0.1/32            scram-sha-256
host    all             all             ::1/128                 scram-sha-256
EOF
chown pgsql:pgsql "${data_dir}/pg_hba.conf"
chmod 0600 "${data_dir}/pg_hba.conf"

if [ ! -s "${secrets_dir}/db-password" ]; then
  umask 077
  hexdump -n 20 -v -e '/1 "%02x"' /dev/urandom > "${secrets_dir}/db-password"
  chown pgsql:pgsql "${secrets_dir}/db-password"
  chmod 0600 "${secrets_dir}/db-password"
fi

db_password=$(tr -d '\n' < "${secrets_dir}/db-password")

started_here=NO
if ! su -m pgsql -c "/usr/pkg/bin/pg_isready -q -p 5432 -d postgres"; then
  su -m pgsql -c "/usr/pkg/bin/pg_ctl -D ${data_dir} -w -t 20 -o '-h 127.0.0.1 -p 5432' start"
  started_here=YES
fi

su -m pgsql -c "/usr/pkg/bin/psql -v ON_ERROR_STOP=1 -d postgres" <<EOF
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'mantisbt') THEN
    CREATE ROLE mantisbt LOGIN PASSWORD '${db_password}';
  ELSE
    ALTER ROLE mantisbt LOGIN PASSWORD '${db_password}';
  END IF;
END
\$\$;
EOF

if ! su -m pgsql -c "/usr/pkg/bin/psql -d postgres -tAc \"SELECT 1 FROM pg_database WHERE datname='mantisbt'\"" | grep -q 1; then
  su -m pgsql -c "/usr/pkg/bin/createdb -O mantisbt mantisbt"
fi

if [ "${started_here}" = "YES" ]; then
  su -m pgsql -c "/usr/pkg/bin/pg_ctl -D ${data_dir} -m fast -w stop"
else
  su -m pgsql -c "/usr/pkg/bin/psql -v ON_ERROR_STOP=1 -d postgres -c 'SELECT pg_reload_conf();'" >/dev/null
fi
