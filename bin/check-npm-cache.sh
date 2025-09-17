#!/usr/bin/env bash

echo "🔍 Scanning for compromised NPM packages..."

# Allow optional base directory argument
BASE_DIR="."
if [ -n "$1" ]; then
  BASE_DIR="$1"
  # Normalize to absolute path if possible
  if [ -d "$BASE_DIR" ]; then
    BASE_DIR=$(cd "$BASE_DIR" && pwd)
  else
    echo "❌ Provided path '$BASE_DIR' is not a directory or doesn't exist." >&2
    exit 2
  fi
fi

echo "🔎 Base directory: $BASE_DIR"

# Define compromised packages and versions (indexed arrays for macOS bash compatibility)
compromised_keys=(
  "ansi-regex"
  "ansi-styles"
  "backslash"
  "chalk"
  "chalk-template"
  "color-convert"
  "color-name"
  "color-string"
  "debug"
  "error-ex"
  "has-ansi"
  "is-arrayish"
  "proto-tinker-wc"
  "simple-swizzle"
  "slice-ansi"
  "strip-ansi"
  "supports-color"
  "supports-hyperlinks"
  "wrap-ansi"
  "angulartics2"
  "@ctrl/deluge"
  "@ctrl/golang-template"
  "@ctrl/magnet-link"
  "@ctrl/ngx-codemirror"
  "@ctrl/ngx-csv"
  "@ctrl/ngx-emoji-mart"
  "@ctrl/ngx-rightclick"
  "@ctrl/qbittorrent"
  "@ctrl/react-adsense"
  "@ctrl/shared-torrent"
  "@ctrl/tinycolor"
  "@ctrl/torrent-file"
  "@ctrl/transmission"
  "@ctrl/ts-base32"
  "encounter-playground"
  "json-rules-engine-simplified"
  "koa2-swagger-ui"
  "@nativescript-community/gesturehandler"
  "@nativescript-community/sentry"
  "@nativescript-community/text"
  "@nativescript-community/ui-collectionview"
  "@nativescript-community/ui-drawer"
  "@nativescript-community/ui-image"
  "@nativescript-community/ui-material-bottomsheet"
  "@nativescript-community/ui-material-core"
  "@nativescript-community/ui-material-core-tabs"
  "ngx-color"
  "ngx-toastr"
  "ngx-trend"
  "react-complaint-image"
  "react-jsonschema-form-conditionals"
  "react-jsonschema-form-extras"
  "rxnt-authentication"
  "rxnt-healthchecks-nestjs"
  "rxnt-kue"
  "swc-plugin-component-annotate"
  "ts-gaussian"
)

compromised_versions=(
  "6.2.1"
  "6.2.2"
  "0.2.1"
  "5.6.1"
  "1.1.1"
  "3.1.1"
  "2.0.1"
  "2.1.1"
  "4.4.2"
  "1.3.3"
  "6.0.1"
  "0.3.3"
  "0.1.87"
  "0.2.3"
  "7.1.1"
  "7.1.1"
  "10.2.1"
  "4.1.1"
  "9.0.1"
  "14.1.2"
  "7.2.2"
  "1.4.3"
  "4.0.4"
  "7.0.2"
  "6.0.2"
  "9.2.2"
  "4.0.2"
  "9.7.2"
  "2.0.2"
  "6.3.2"
  "4.1.1,4.1.2"
  "4.1.2"
  "7.3.1"
  "4.0.2"
  "0.0.5"
  "0.2.4,0.2.1"
  "5.11.2,5.11.1"
  "2.0.35"
  "4.6.43"
  "1.6.13"
  "6.0.6"
  "0.1.30"
  "4.5.6"
  "7.2.72"
  "7.2.76"
  "7.2.76"
  "10.0.2"
  "19.0.2"
  "8.0.1"
  "0.0.35"
  "0.3.21"
  "1.0.4"
  "0.0.6"
  "1.0.5"
  "1.0.7"
  "1.9.2"
  "3.0.6"
)

declare -a findings=()

declare -a findings=()

scan_file() {
  local file="$1"
  for i in "${!compromised_keys[@]}"; do
    pkg="${compromised_keys[$i]}"
    version="${compromised_versions[$i]}"
    if grep -q "$pkg" "$file" && grep -q "$version" "$file"; then
      findings+=("Found $pkg@$version in $file")
    fi
  done
}

scan_npm_cache() {
  local cache_dir="$1"
  for i in "${!compromised_keys[@]}"; do
    pkg="${compromised_keys[$i]}"
    version="${compromised_versions[$i]}"
    while IFS= read -r match; do
      findings+=("Found $pkg@$version in cached file: $match")
    done < <(find "$cache_dir" -type f -exec grep -l "$pkg@$version" {} + 2>/dev/null)
  done
}

scan_nvm_versions() {
  local nvm_dir="${NVM_DIR:-$HOME/.nvm}"
  if [ ! -d "$nvm_dir" ]; then return; fi

  echo "🧠 Scanning NVM-managed Node versions..."
  count=0
  find "$nvm_dir/versions/node" -type d \( -name "node_modules" -o -name ".npm" \) | while read -r dir; do
    scan_npm_cache "$dir"
    count=$((count + 1))
    if (( count % 5 == 0 )); then
      echo "  ...scanned $count NVM directories"
    fi
  done
}

scan_dockerfiles() {
  echo "🐳 Scanning Dockerfiles..."
  count=0
  while IFS= read -r file; do
    scan_file "$file"
    count=$((count + 1))
    if (( count % 5 == 0 )); then
      echo "  ...scanned $count Dockerfiles"
    fi
  done < <(find "$BASE_DIR" -type f -iname "Dockerfile")
}

scan_ci_configs() {
  echo "⚙️ Scanning CI/CD config files..."
  count=0
  while IFS= read -r file; do
    scan_file "$file"
    count=$((count + 1))
    if (( count % 5 == 0 )); then
      echo "  ...scanned $count CI config files"
    fi
  done < <(find "$BASE_DIR" -type f \( -name "*.yml" -o -name "*.yaml" \) -path "*/.github/*" -o -path "*/.gitlab/*")
}

scan_vendored_dirs() {
  echo "📁 Scanning vendored folders..."
  for dir in vendor third_party static assets; do
    [ -d "$dir" ] || continue
    while IFS= read -r file; do
      scan_file "$file"
    done < <(find "$dir" -type f \( -name "*.js" -o -name "*.json" -o -name "*.tgz" \))
  done
}

scan_lockfile_resolved() {
  local file="$1"
  for i in "${!compromised_keys[@]}"; do
    pkg="${compromised_keys[$i]}"
    version="${compromised_versions[$i]}"
    # Match resolved tarball URLs for compromised versions
    if grep -q "$pkg/-/$pkg-$version.tgz" "$file"; then
      findings+=("Resolved $pkg@$version in $file")
    fi
  done
}

echo "🔒 Scanning project lockfiles and package.json..."
count=0
while IFS= read -r file; do
  scan_lockfile_resolved "$file"  # new accurate match
  count=$((count + 1))
  if (( count % 10 == 0 )); then
    echo "  ...scanned $count files"
  fi
done < <(find . -type f \( -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" \))

# Global caches
echo "📦 Scanning global npm caches..."
[ -d "$HOME/.npm/_cacache" ] && scan_npm_cache "$HOME/.npm/_cacache"
[ -d "$HOME/.npm-packages" ] && scan_npm_cache "$HOME/.npm-packages"

echo "📦 Scanning Yarn global cache..."
if command -v yarn >/dev/null 2>&1; then
  yarn_cache=$(yarn cache dir 2>/dev/null)
  [ -n "$yarn_cache" ] && [ -d "$yarn_cache" ] && scan_npm_cache "$yarn_cache"
fi

echo "📦 Scanning pnpm global store..."
if command -v pnpm >/dev/null 2>&1; then
  pnpm_cache=$(pnpm store path 2>/dev/null)
  [ -n "$pnpm_cache" ] && [ -d "$pnpm_cache" ] && scan_npm_cache "$pnpm_cache"
fi

scan_nvm_versions
scan_dockerfiles
scan_ci_configs
scan_vendored_dirs

echo ""
echo "📊 Summary of Findings:"
if [ ${#findings[@]} -eq 0 ]; then
  echo "✅ No compromised packages found."
else
  declare -A grouped
  declare -A remediation

  # Group findings by remediation directory
  for line in "${findings[@]}"; do
    file=$(echo "$line" | awk -F'in ' '{print $2}')
    dir=$(dirname "$file")

    # Trim path before node_modules if present
    if [[ "$dir" == *"/node_modules/"* ]]; then
      dir="${dir%%/node_modules/*}"
    elif [[ "$dir" == *"/node_modules" ]]; then
      dir="${dir%/node_modules}"
    fi

    # Walk up to find the remediation root
    while [ "$dir" != "/" ]; do
      if [ -f "$dir/package-lock.json" ]; then
        remediation["$dir"]="npm"
        break
      elif [ -f "$dir/yarn.lock" ]; then
        remediation["$dir"]="yarn"
        break
      elif [ -f "$dir/pnpm-lock.yaml" ]; then
        remediation["$dir"]="pnpm"
        break
      fi
      dir=$(dirname "$dir")
    done

    grouped["$dir"]+="$line"$'\n'
  done

  # Print grouped findings
  for dir in "${!grouped[@]}"; do
    echo "📁 $dir"
    echo "${grouped[$dir]}"
  done

  echo ""
  echo "🛠️ Suggested Remediation Commands:"
  for dir in "${!remediation[@]}"; do
    tool="${remediation[$dir]}"
    echo "💡 cd \"$dir\" && rm -rf node_modules ${tool}-lock.yaml yarn.lock package-lock.json && $tool install"
  done
fi
