#!/bin/sh
set -eu

[ -f /var/www/web/.bootstrapped ] || touch /var/www/web/.bootstrapped
