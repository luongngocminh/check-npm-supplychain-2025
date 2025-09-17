# NPM Cache Scanner (Go Version)

A fast, concurrent Go-based scanner to detect compromised NPM packages in your projects and caches. This replaces the bash script with better performance, cross-platform support, and concurrent scanning.

## Features

- 🚀 **Concurrent scanning** - Uses worker pools for fast parallel processing
- 🔍 **Comprehensive detection** - Scans lockfiles, Dockerfiles, CI configs, vendored dirs, and caches
- 🖥️ **Cross-platform** - Works on macOS, Linux, and Windows with platform-specific optimizations
- ⚙️ **Configurable** - CLI flags to control scanning scope and behavior
- 📊 **Project-focused reporting** - Groups findings by project with detailed statistics
- 🎯 **Smart package manager detection** - Automatically detects npm, yarn, pnpm projects
- 🪟 **Enhanced Windows support** - Detects Windows-specific npm cache locations and nvm-windows installations

## Installation

### Pre-built binaries (Recommended)
Check the `bin/` directory for pre-built binaries:
- `check-npm-cache-linux` - Linux x64
- `check-npm-cache-windows.exe` - Windows x64  
- `check-npm-cache-macos-intel` - macOS Intel
- `check-npm-cache-macos-arm64` - macOS Apple Silicon

Simply download and run the appropriate binary for your platform - no additional dependencies required!

### Build from source

**Prerequisites:** You need Go 1.16 or later to build from source.

#### Install Go (if building from source)

**macOS:**
```bash
# Using Homebrew
brew install go

# Or download from https://golang.org/dl/
```

**Linux:**
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install golang-go

# CentOS/RHEL/Fedora
sudo dnf install golang
# or: sudo yum install golang

# Or download from https://golang.org/dl/
```

**Windows:**
- Download installer from [https://golang.org/dl/](https://golang.org/dl/)
- Run the `.msi` installer
- Or use Chocolatey: `choco install golang`
- Or use Scoop: `scoop install go`

Verify installation:
```bash
go version
```

#### Build commands
```bash
# Build for current platform
go build -o check-npm-cache main.go

# Cross-platform builds
GOOS=linux GOARCH=amd64 go build -o bin/check-npm-cache-linux main.go
GOOS=windows GOARCH=amd64 go build -o bin/check-npm-cache-windows.exe main.go
GOOS=darwin GOARCH=amd64 go build -o bin/check-npm-cache-macos-intel main.go
GOOS=darwin GOARCH=arm64 go build -o bin/check-npm-cache-macos-arm64 main.go
```

## Usage

### Basic usage

**macOS/Linux (using pre-built binaries):**
```bash
# Scan current directory
./bin/check-npm-cache-macos-arm64    # For Apple Silicon Macs
./bin/check-npm-cache-macos-intel    # For Intel Macs
./bin/check-npm-cache-linux          # For Linux

# Scan specific directory  
./bin/check-npm-cache-macos-arm64 -dir /path/to/project

# Verbose output
./bin/check-npm-cache-macos-arm64 -verbose

# Only scan repository files (skip global caches)
./bin/check-npm-cache-macos-arm64 -repo-only
```

**Windows (Command Prompt):**
```cmd
REM Scan current directory
bin\check-npm-cache-windows.exe

REM Scan specific directory
bin\check-npm-cache-windows.exe -dir C:\path\to\project

REM Verbose output
bin\check-npm-cache-windows.exe -verbose

REM Only scan repository files (skip global caches)
bin\check-npm-cache-windows.exe -repo-only
```

**Windows (PowerShell):**
```powershell
# Scan current directory
.\bin\check-npm-cache-windows.exe

# Scan specific directory
.\bin\check-npm-cache-windows.exe -dir C:\path\to\project

# Verbose output
.\bin\check-npm-cache-windows.exe -verbose

# Only scan repository files (skip global caches)
.\bin\check-npm-cache-windows.exe -repo-only
```

**If you built from source:**
```bash
# Use your custom binary name
./check-npm-cache -dir /path/to/project
```

### CLI Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-dir` | Base directory to scan | `.` (current directory) |
| `-no-global` | Skip global npm/yarn/pnpm cache scanning | `false` |
| `-no-nvm` | Skip NVM directory scanning | `false` |
| `-repo-only` | Only scan repository files (implies -no-global -no-nvm) | `false` |
| `-workers` | Number of concurrent workers | `2x CPU cores` |
| `-verbose` | Show detailed progress and findings | `false` |

### Verbose Output
When using `-verbose`, the scanner shows detailed progress:
```bash
./check-npm-cache -verbose
```

Example verbose output:
```
🔒 Scanning project lockfiles and package.json...
  📄 Found lockfile: /path/to/package-lock.json
  📄 Found lockfile: /path/to/yarn.lock
🐳 Scanning Dockerfiles...
  🐳 Found Dockerfile: /path/to/Dockerfile
📦 Scanning global npm caches...
  🏠 Home directory: /Users/developer
  📦 Scanning npm _cacache: /Users/developer/.npm/_cacache
  📦 Scanning yarn cache: /Users/developer/.cache/yarn
```

## Performance comparison

- **Bash script**: Sequential processing, ~30-60 seconds for large projects
- **Go version**: Concurrent processing, ~2-5 seconds for the same projects

---

## 🚨 What It Detects

The scanner monitors **58 compromised NPM packages**:

| Package | Version(s) | Category |
|---------|------------|----------|
| ansi-regex | 6.2.1 | Terminal/ANSI |
| ansi-styles | 6.2.2 | Terminal/ANSI |
| backslash | 0.2.1 | Utilities |
| chalk | 5.6.1 | Terminal/Colors |
| chalk-template | 1.1.1 | Terminal/Colors |
| color-convert | 3.1.1 | Colors |
| color-name | 2.0.1 | Colors |
| color-string | 2.1.1 | Colors |
| debug | 4.4.2 | Debugging |
| error-ex | 1.3.3 | Error handling |
| has-ansi | 6.0.1 | Terminal/ANSI |
| is-arrayish | 0.3.3 | Type checking |
| proto-tinker-wc | 0.1.87 | Utilities |
| simple-swizzle | 0.2.3 | Colors |
| slice-ansi | 7.1.1 | Terminal/ANSI |
| strip-ansi | 7.1.1 | Terminal/ANSI |
| supports-color | 10.2.1 | Terminal/Colors |
| supports-hyperlinks | 4.1.1 | Terminal |
| wrap-ansi | 9.0.1 | Terminal/ANSI |
| angulartics2 | 14.1.2 | Angular |
| @ctrl/deluge | 7.2.2 | BitTorrent |
| @ctrl/golang-template | 1.4.3 | Templates |
| @ctrl/magnet-link | 4.0.4 | BitTorrent |
| @ctrl/ngx-codemirror | 7.0.2 | Angular/Editor |
| @ctrl/ngx-csv | 6.0.2 | Angular/CSV |
| @ctrl/ngx-emoji-mart | 9.2.2 | Angular/UI |
| @ctrl/ngx-rightclick | 4.0.2 | Angular/UI |
| @ctrl/qbittorrent | 9.7.2 | BitTorrent |
| @ctrl/react-adsense | 2.0.2 | React/Ads |
| @ctrl/shared-torrent | 6.3.2 | BitTorrent |
| @ctrl/tinycolor | 4.1.1, 4.1.2 | Colors |
| @ctrl/torrent-file | 4.1.2 | BitTorrent |
| @ctrl/transmission | 7.3.1 | BitTorrent |
| @ctrl/ts-base32 | 4.0.2 | Encoding |
| encounter-playground | 0.0.5 | Healthcare |
| json-rules-engine-simplified | 0.2.4, 0.2.1 | Rules Engine |
| koa2-swagger-ui | 5.11.2, 5.11.1 | API Documentation |
| @nativescript-community/gesturehandler | 2.0.35 | NativeScript/UI |
| @nativescript-community/sentry | 4.6.43 | NativeScript/Monitoring |
| @nativescript-community/text | 1.6.13 | NativeScript/UI |
| @nativescript-community/ui-collectionview | 6.0.6 | NativeScript/UI |
| @nativescript-community/ui-drawer | 0.1.30 | NativeScript/UI |
| @nativescript-community/ui-image | 4.5.6 | NativeScript/UI |
| @nativescript-community/ui-material-bottomsheet | 7.2.72 | NativeScript/Material |
| @nativescript-community/ui-material-core | 7.2.76 | NativeScript/Material |
| @nativescript-community/ui-material-core-tabs | 7.2.76 | NativeScript/Material |
| ngx-color | 10.0.2 | Angular/Colors |
| ngx-toastr | 19.0.2 | Angular/Notifications |
| ngx-trend | 8.0.1 | Angular/Charts |
| react-complaint-image | 0.0.35 | React/Images |
| react-jsonschema-form-conditionals | 0.3.21 | React/Forms |
| react-jsonschema-form-extras | 1.0.4 | React/Forms |
| rxnt-authentication | 0.0.6 | Healthcare/Auth |
| rxnt-healthchecks-nestjs | 1.0.5 | Healthcare/Monitoring |
| rxnt-kue | 1.0.7 | Healthcare/Queue |
| swc-plugin-component-annotate | 1.9.2 | Build Tools |
| ts-gaussian | 3.0.6 | Math/Statistics |

*[These packages are from the September 2025 supply chain attack](https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages)*

---

## 📁 What It Scans

### 🔒 Repository Files (in specified directory)
- **Lockfiles**: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` - Scans resolved tarball URLs
- **Dockerfiles**: Any file named `Dockerfile` - Scans for package references
- **CI/CD configs**: `.yml`/`.yaml` files in `.github/` or `.gitlab/` directories
- **Vendored folders**: `vendor/`, `third_party/`, `static/`, `assets/` - Scans `.js`, `.json`, `.tgz` files

### 📦 Global Caches (unless disabled with flags)

#### NPM
**macOS/Linux:**
- `~/.npm/_cacache` - NPM's content-addressable cache
- `~/.npm-packages` - Global NPM packages

**Windows:**
- `%APPDATA%\npm-cache` - NPM cache (Windows-specific location)
- `%LOCALAPPDATA%\npm-cache` - Alternative NPM cache location
- `%USERPROFILE%\.npm\_cacache` - Fallback for WSL/Git Bash environments
- `%USERPROFILE%\.npm-packages` - Global NPM packages

#### Yarn
- Auto-detected via `yarn cache dir` command
- **macOS/Linux**: Typically `~/.cache/yarn` or `~/.yarn/cache`
- **Windows**: Typically `%LOCALAPPDATA%\Yarn\Cache` or `%APPDATA%\Local\Yarn\Cache`

#### pnpm
- Auto-detected via `pnpm store path` command  
- **macOS/Linux**: Typically `~/.pnpm-store` or `~/.local/share/pnpm/store`
- **Windows**: Typically `%LOCALAPPDATA%\pnpm\store` or `%APPDATA%\pnpm-store`

#### NVM (Node Version Manager)
**macOS/Linux (nvm):**
- `$NVM_DIR/versions/node/*/node_modules` - Node version-specific modules
- `$NVM_DIR/versions/node/*/.npm` - Version-specific NPM caches
- Defaults to `~/.nvm` if `$NVM_DIR` not set

**Windows (nvm-windows):**
- `%NVM_HOME%\v*/node_modules` - Node version-specific modules  
- `%NVM_HOME%\v*\.npm` - Version-specific NPM caches
- Defaults to `%APPDATA%\nvm` if `%NVM_HOME%` not set

## 📊 Example Output

The scanner provides a detailed project-focused report:

```
🔍 Scanning for compromised NPM packages...
🔎 Base directory: /Users/developer/projects
🔧 Workers: 16
🔒 Scanning project lockfiles and package.json...
🐳 Scanning Dockerfiles...
⚙️ Scanning CI/CD config files...
📁 Scanning vendored folders...
📦 Scanning global npm caches...

📊 Scan completed in 1.2s

📊 Summary of Findings:
Found 5 compromised package references across 2 projects:

🏗️  Project: /Users/developer/projects/webapp
   📦 Package Manager: npm
   🚨 Issues Found: 3
   📋 Lockfile references: 2
   📄 File references: 1
   📋 Affected packages:
      • chalk (5.6.1)
      • debug (4.4.2)

🏗️  Project: /Users/developer/projects/api-server
   📦 Package Manager: yarn
   🚨 Issues Found: 2
   📋 Lockfile references: 2
   📋 Affected packages:
      • @ctrl/tinycolor (4.1.1, 4.1.2)

📋 Final Report:
   Total compromised references: 5
   Affected projects: 2
   Projects by package manager:
      • npm: 1
      • yarn: 1
```

## � Why Use This Scanner?

- **Fast & concurrent** — Uses Go's goroutines for parallel processing
- **Zero dependencies** — Single binary, no external tools required
- **Cross-platform** — Same binary works on macOS, Linux, and Windows
- **Comprehensive** — Scans lockfiles, caches, Dockerfiles, and CI configs
- **Project-focused** — Groups findings by project for easier analysis
- **Smart detection** — Auto-detects package managers and yarn/pnpm cache locations

## Acknowledgements
- Thanks to the original bash script author, joeskeen, for the initial idea and logic https://gist.github.com/joeskeen/202fe9f6d7a2f624097962507c5ab681