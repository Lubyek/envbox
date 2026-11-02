#!/usr/bin/env bash
here=$(dirname "$(readlink -f "$0")")
unset PYTHONHOME PYTHONPATH
exec /usr/bin/python3 -I "$here/usr/share/envbox/envbox.py" "$@"
