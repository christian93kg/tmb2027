#!/usr/bin/env bash
# Re-encrypt the editable source into the committed, password-gated index.html.
#
#   ./publish.sh                 # prompts for the password (hidden, not in shell history)
#   ./publish.sh 'the-password'  # password as arg (ends up in shell history)
#   TMB_SITE_PASSWORD=... ./publish.sh
#
# Then review index.html and:  git add index.html && git commit && git push
set -euo pipefail
cd "$(dirname "$0")"

if [ -n "${1:-}" ]; then
  export TMB_SITE_PASSWORD="$1"
fi

python3 encrypt.py src/index.html index.html

echo
echo "Done. Next:  git add index.html && git commit -m 'Re-encrypt site' && git push"
