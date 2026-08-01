#!/bin/sh

set -e

repo_root=$(pwd)
index_bare="$repo_root/tmp/index-bare"
registry_api_url=${LOCAL_REGISTRY_API_URL:-http://127.0.0.1:8888}
mkdir -p "$repo_root/tmp"
index_tmp=$(mktemp -d "$repo_root/tmp/index-tmp.XXXXXX")
trap 'rm -rf "$index_tmp"' EXIT

if [ -d "$index_bare" ]; then
    echo "Updating existing repository in tmp/index-bare..."
    git clone -q "$index_bare" "$index_tmp"
else
    echo "Initializing repository in tmp/index-bare..."
    git init -q --bare --initial-branch=master "$index_bare"
    git init -q --initial-branch=master "$index_tmp"
fi

cd "$index_tmp"
cat > config.json <<-EOF
{
  "dl": "http://127.0.0.1:8888/api/v1/crates",
  "api": "${registry_api_url%/}/"
}
EOF
git add config.json
if git diff --cached --quiet; then
    echo "Local registry config is already up to date."
else
    git commit -qm 'Configure local registry'
    if ! git remote get-url origin >/dev/null 2>&1; then
        git remote add origin "file://$index_bare"
    fi
    git push -q origin master -u >/dev/null
fi
cd "$repo_root"

# Allow the index to be exported via HTTP during local development
touch "$index_bare/git-daemon-export-ok"

cat - <<-EOF
Your local git index is ready to go!

Please refer to https://github.com/rust-lang/crates.io/blob/master/docs/CONTRIBUTING.md for more info!
EOF
