#!/bin/sh
set -eu

if [ ! -f /var/lib/luanti/games/mineclonia/game.conf ]; then
  rm -rf /tmp/cellman-mineclonia-extract
  mkdir -p /tmp/cellman-mineclonia-extract
  ftp -o /tmp/cellman-mineclonia.zip https://content.luanti.org/packages/ryvnf/mineclonia/download/
  unzip -q /tmp/cellman-mineclonia.zip -d /tmp/cellman-mineclonia-extract

  game_src=
  for d in /tmp/cellman-mineclonia-extract/*; do
    [ -f "$d/game.conf" ] && game_src="$d" && break
  done

  if [ -n "$game_src" ]; then
    rm -rf /var/lib/luanti/games/mineclonia
    mv "$game_src" /var/lib/luanti/games/mineclonia
    rm -f /tmp/cellman-mineclonia.zip
    rm -rf /tmp/cellman-mineclonia-extract
  fi
fi
