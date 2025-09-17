package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// CompromisedPackage represents a package and its compromised versions
type CompromisedPackage struct {
	Name     string
	Versions []string
}

// Finding represents a discovered compromised package
type Finding struct {
	Package string
	Version string
	File    string
	Type    string // "file", "cache", "resolved"
}

// Scanner configuration
type ScanConfig struct {
	BaseDir    string
	NoGlobal   bool
	NoNVM      bool
	RepoOnly   bool
	MaxWorkers int
	Verbose    bool
}

var compromisedPackages = []CompromisedPackage{
	{"ansi-regex", []string{"6.2.1"}},
	{"ansi-styles", []string{"6.2.2"}},
	{"backslash", []string{"0.2.1"}},
	{"chalk", []string{"5.6.1"}},
	{"chalk-template", []string{"1.1.1"}},
	{"color-convert", []string{"3.1.1"}},
	{"color-name", []string{"2.0.1"}},
	{"color-string", []string{"2.1.1"}},
	{"debug", []string{"4.4.2"}},
	{"error-ex", []string{"1.3.3"}},
	{"has-ansi", []string{"6.0.1"}},
	{"is-arrayish", []string{"0.3.3"}},
	{"proto-tinker-wc", []string{"0.1.87"}},
	{"simple-swizzle", []string{"0.2.3"}},
	{"slice-ansi", []string{"7.1.1"}},
	{"strip-ansi", []string{"7.1.1"}},
	{"supports-color", []string{"10.2.1"}},
	{"supports-hyperlinks", []string{"4.1.1"}},
	{"wrap-ansi", []string{"9.0.1"}},

	// Original packages updated
	{"angulartics2", []string{"14.1.1", "14.1.2"}},
	{"@ctrl/deluge", []string{"7.2.1", "7.2.2"}},
	{"@ctrl/golang-template", []string{"1.4.2", "1.4.3"}},
	{"@ctrl/magnet-link", []string{"4.0.3", "4.0.4"}},
	{"@ctrl/ngx-codemirror", []string{"7.0.1", "7.0.2"}},
	{"@ctrl/ngx-csv", []string{"6.0.1", "6.0.2"}},
	{"@ctrl/ngx-emoji-mart", []string{"9.2.1", "9.2.2"}},
	{"@ctrl/ngx-rightclick", []string{"4.0.1", "4.0.2"}},
	{"@ctrl/qbittorrent", []string{"9.7.1", "9.7.2"}},
	{"@ctrl/react-adsense", []string{"2.0.1", "2.0.2"}},
	{"@ctrl/shared-torrent", []string{"6.3.1", "6.3.2"}},
	{"@ctrl/tinycolor", []string{"4.1.1", "4.1.2"}},
	{"@ctrl/torrent-file", []string{"4.1.1", "4.1.2"}},
	{"@ctrl/transmission", []string{"7.3.1"}},
	{"@ctrl/ts-base32", []string{"4.0.1", "4.0.2"}},
	{"encounter-playground", []string{"0.0.2", "0.0.3", "0.0.4", "0.0.5"}},
	{"json-rules-engine-simplified", []string{"0.2.1", "0.2.4"}},
	{"koa2-swagger-ui", []string{"5.11.1", "5.11.2"}},
	{"ngx-color", []string{"10.0.1", "10.0.2"}},
	{"ngx-toastr", []string{"19.0.1", "19.0.2"}},
	{"ngx-trend", []string{"8.0.1"}},
	{"react-complaint-image", []string{"0.0.32", "0.0.35"}},
	{"react-jsonschema-form-conditionals", []string{"0.3.18", "0.3.21"}},
	{"react-jsonschema-form-extras", []string{"1.0.4"}},
	{"rxnt-authentication", []string{"0.0.3", "0.0.4", "0.0.5", "0.0.6"}},
	{"rxnt-healthchecks-nestjs", []string{"1.0.2", "1.0.3", "1.0.4", "1.0.5"}},
	{"rxnt-kue", []string{"1.0.4", "1.0.5", "1.0.6", "1.0.7"}},
	{"swc-plugin-component-annotate", []string{"1.9.1", "1.9.2"}},
	{"ts-gaussian", []string{"3.0.5", "3.0.6"}},

	// New packages from your list
	{"@ahmedhfarag/ngx-perfect-scrollbar", []string{"20.0.20"}},
	{"@ahmedhfarag/ngx-virtual-scroller", []string{"4.0.4"}},
	{"@art-ws/common", []string{"2.0.28"}},
	{"@art-ws/config-eslint", []string{"2.0.4", "2.0.5"}},
	{"@art-ws/config-ts", []string{"2.0.7", "2.0.8"}},
	{"@art-ws/db-context", []string{"2.0.24"}},
	{"@art-ws/di-node", []string{"2.0.13"}},
	{"@art-ws/di", []string{"2.0.28", "2.0.32"}},
	{"@art-ws/eslint", []string{"1.0.5", "1.0.6"}},
	{"@art-ws/fastify-http-server", []string{"2.0.24", "2.0.27"}},
	{"@art-ws/http-server", []string{"2.0.21", "2.0.25"}},
	{"@art-ws/openapi", []string{"0.1.9", "0.1.12"}},
	{"@art-ws/package-base", []string{"1.0.5", "1.0.6"}},
	{"@art-ws/prettier", []string{"1.0.5", "1.0.6"}},
	{"@art-ws/slf", []string{"2.0.15", "2.0.22"}},
	{"@art-ws/ssl-info", []string{"1.0.9", "1.0.10"}},
	{"@art-ws/web-app", []string{"1.0.3", "1.0.4"}},
	{"@crowdstrike/commitlint", []string{"8.1.1", "8.1.2"}},
	{"@crowdstrike/falcon-shoelace", []string{"0.4.1", "0.4.2"}},
	{"@crowdstrike/foundry-js", []string{"0.19.1", "0.19.2"}},
	{"@crowdstrike/glide-core", []string{"0.34.2", "0.34.3"}},
	{"@crowdstrike/logscale-dashboard", []string{"1.205.1", "1.205.2"}},
	{"@crowdstrike/logscale-file-editor", []string{"1.205.1", "1.205.2"}},
	{"@crowdstrike/logscale-parser-edit", []string{"1.205.1", "1.205.2"}},
	{"@crowdstrike/logscale-search", []string{"1.205.1", "1.205.2"}},
	{"@crowdstrike/tailwind-toucan-base", []string{"5.0.1", "5.0.2"}},
	{"@hestjs/core", []string{"0.2.1"}},
	{"@hestjs/cqrs", []string{"0.1.6"}},
	{"@hestjs/demo", []string{"0.1.2"}},
	{"@hestjs/eslint-config", []string{"0.1.2"}},
	{"@hestjs/logger", []string{"0.1.6"}},
	{"@hestjs/scalar", []string{"0.1.7"}},
	{"@hestjs/validation", []string{"0.1.6"}},
	{"@nativescript-community/arraybuffers", []string{"1.1.6", "1.1.7", "1.1.8"}},
	{"@nativescript-community/gesturehandler", []string{"2.0.35"}},
	{"@nativescript-community/perms", []string{"3.0.5", "3.0.6", "3.0.7", "3.0.8"}},
	{"@nativescript-community/sentry", []string{"4.6.43"}},
	{"@nativescript-community/sqlite", []string{"3.5.2", "3.5.3", "3.5.4", "3.5.5"}},
	{"@nativescript-community/text", []string{"1.6.9", "1.6.10", "1.6.11", "1.6.12", "1.6.13"}},
	{"@nativescript-community/typeorm", []string{"0.2.30", "0.2.31", "0.2.32", "0.2.33"}},
	{"@nativescript-community/ui-collectionview", []string{"6.0.6"}},
	{"@nativescript-community/ui-document-picker", []string{"1.1.27", "1.1.28"}},
	{"@nativescript-community/ui-drawer", []string{"0.1.30"}},
	{"@nativescript-community/ui-image", []string{"4.5.6"}},
	{"@nativescript-community/ui-label", []string{"1.3.35", "1.3.36", "1.3.37"}},
	{"@nativescript-community/ui-material-bottom-navigation", []string{"7.2.72", "7.2.73", "7.2.74", "7.2.75"}},
	{"@nativescript-community/ui-material-bottomsheet", []string{"7.2.72"}},
	{"@nativescript-community/ui-material-core-tabs", []string{"7.2.72", "7.2.73", "7.2.74", "7.2.75", "7.2.76"}},
	{"@nativescript-community/ui-material-core", []string{"7.2.72", "7.2.73", "7.2.74", "7.2.75", "7.2.76"}},
	{"@nativescript-community/ui-material-ripple", []string{"7.2.72", "7.2.73", "7.2.74", "7.2.75"}},
	{"@nativescript-community/ui-material-tabs", []string{"7.2.72", "7.2.73", "7.2.74", "7.2.75"}},
	{"@nativescript-community/ui-pager", []string{"14.1.36", "14.1.37", "14.1.38"}},
	{"@nativescript-community/ui-pulltorefresh", []string{"2.5.4", "2.5.5", "2.5.6", "2.5.7"}},
	{"@nexe/config-manager", []string{"0.1.1"}},
	{"@nexe/eslint-config", []string{"0.1.1"}},
	{"@nexe/logger", []string{"0.1.3"}},
	{"@nstudio/angular", []string{"20.0.4", "20.0.5", "20.0.6"}},
	{"@nstudio/focus", []string{"20.0.4", "20.0.5", "20.0.6"}},
	{"@nstudio/nativescript-checkbox", []string{"2.0.6", "2.0.7", "2.0.8", "2.0.9"}},
	{"@nstudio/nativescript-loading-indicator", []string{"5.0.1", "5.0.2", "5.0.3", "5.0.4"}},
	{"@nstudio/ui-collectionview", []string{"5.1.11", "5.1.12", "5.1.13", "5.1.14"}},
	{"@nstudio/web-angular", []string{"20.0.4"}},
	{"@nstudio/web", []string{"20.0.4"}},
	{"@nstudio/xplat-utils", []string{"20.0.5", "20.0.6", "20.0.7"}},
	{"@nstudio/xplat", []string{"20.0.5", "20.0.6", "20.0.7"}},
	{"@operato/board", []string{"9.0.36", "9.0.37", "9.0.38", "9.0.39", "9.0.40", "9.0.41", "9.0.42", "9.0.43", "9.0.44", "9.0.45", "9.0.46"}},
	{"@operato/data-grist", []string{"9.0.29", "9.0.35", "9.0.36", "9.0.37"}},
	{"@operato/graphql", []string{"9.0.22", "9.0.35", "9.0.36", "9.0.37", "9.0.38", "9.0.39", "9.0.40", "9.0.41", "9.0.42", "9.0.43", "9.0.44", "9.0.45", "9.0.46"}},
	{"@operato/headroom", []string{"9.0.2", "9.0.35", "9.0.36", "9.0.37"}},
	{"@operato/help", []string{"9.0.35", "9.0.36", "9.0.37", "9.0.38", "9.0.39", "9.0.40", "9.0.41", "9.0.42", "9.0.43", "9.0.44", "9.0.45", "9.0.46"}},
	{"@operato/i18n", []string{"9.0.35", "9.0.36", "9.0.37"}},
	{"@operato/input", []string{"9.0.27", "9.0.35", "9.0.36", "9.0.37", "9.0.38", "9.0.39", "9.0.40", "9.0.41", "9.0.42", "9.0.43", "9.0.44", "9.0.45", "9.0.46", "9.0.47", "9.0.48"}},
	{"@operato/layout", []string{"9.0.35", "9.0.36", "9.0.37"}},
	{"@operato/popup", []string{"9.0.22", "9.0.35", "9.0.36", "9.0.37", "9.0.38", "9.0.39", "9.0.40", "9.0.41", "9.0.42", "9.0.43", "9.0.44", "9.0.45", "9.0.46", "9.0.49"}},
	{"@operato/pull-to-refresh", []string{"9.0.36", "9.0.37", "9.0.38", "9.0.39", "9.0.40", "9.0.41", "9.0.42"}},
	{"@operato/shell", []string{"9.0.22", "9.0.35", "9.0.36", "9.0.37", "9.0.38", "9.0.39"}},
	{"@operato/styles", []string{"9.0.2", "9.0.35", "9.0.36", "9.0.37"}},
	{"@operato/utils", []string{"9.0.22", "9.0.35", "9.0.36", "9.0.37", "9.0.38", "9.0.39", "9.0.40", "9.0.41", "9.0.42", "9.0.43", "9.0.44", "9.0.45", "9.0.46", "9.0.49"}},
	{"@teselagen/bio-parsers", []string{"0.4.30"}},
	{"@teselagen/bounce-loader", []string{"0.3.16", "0.3.17"}},
	{"@teselagen/file-utils", []string{"0.3.22"}},
	{"@teselagen/liquibase-tools", []string{"0.4.1"}},
	{"@teselagen/ove", []string{"0.7.40"}},
	{"@teselagen/range-utils", []string{"0.3.14", "0.3.15"}},
	{"@teselagen/react-list", []string{"0.8.19", "0.8.20"}},
	{"@teselagen/react-table", []string{"6.10.19", "6.10.20", "6.10.22"}},
	{"@teselagen/sequence-utils", []string{"0.3.34"}},
	{"@teselagen/ui", []string{"0.9.10"}},
	{"@thangved/callback-window", []string{"1.1.4"}},
	{"@things-factory/attachment-base", []string{"9.0.43", "9.0.44", "9.0.45", "9.0.46", "9.0.47", "9.0.48", "9.0.49", "9.0.50"}},
	{"@things-factory/auth-base", []string{"9.0.43", "9.0.44", "9.0.45"}},
	{"@things-factory/email-base", []string{"9.0.42", "9.0.43", "9.0.44", "9.0.45", "9.0.46", "9.0.47", "9.0.48", "9.0.49", "9.0.50", "9.0.51", "9.0.52", "9.0.53", "9.0.54"}},
	{"@things-factory/env", []string{"9.0.42", "9.0.43", "9.0.44", "9.0.45"}},
	{"@things-factory/integration-base", []string{"9.0.43", "9.0.44", "9.0.45"}},
	{"@things-factory/integration-marketplace", []string{"9.0.43", "9.0.44", "9.0.45"}},
	{"@things-factory/shell", []string{"9.0.43", "9.0.44", "9.0.45"}},
	{"@tnf-dev/api", []string{"1.0.8"}},
	{"@tnf-dev/core", []string{"1.0.8"}},
	{"@tnf-dev/js", []string{"1.0.8"}},
	{"@tnf-dev/mui", []string{"1.0.8"}},
	{"@tnf-dev/react", []string{"1.0.8"}},
	{"@ui-ux-gang/devextreme-angular-rpk", []string{"24.1.7"}},
	{"@yoobic/design-system", []string{"6.5.17"}},
	{"@yoobic/jpeg-camera-es6", []string{"1.0.13"}},
	{"@yoobic/yobi", []string{"8.7.53"}},
	{"airchief", []string{"0.3.1"}},
	{"airpilot", []string{"0.8.8"}},
	{"browser-webdriver-downloader", []string{"3.0.8"}},
	{"capacitor-notificationhandler", []string{"0.0.2", "0.0.3"}},
	{"capacitor-plugin-healthapp", []string{"0.0.2", "0.0.3"}},
	{"capacitor-plugin-ihealth", []string{"1.1.8", "1.1.9"}},
	{"capacitor-plugin-vonage", []string{"1.0.2", "1.0.3"}},
	{"capacitorandroidpermissions", []string{"0.0.4", "0.0.5"}},
	{"config-cordova", []string{"0.8.5"}},
	{"cordova-plugin-voxeet2", []string{"1.0.24"}},
	{"cordova-voxeet", []string{"1.0.32"}},
	{"create-hest-app", []string{"0.1.9"}},
	{"db-evo", []string{"1.1.4", "1.1.5"}},
	{"devextreme-angular-rpk", []string{"21.2.8"}},
	{"ember-browser-services", []string{"5.0.2", "5.0.3"}},
	{"ember-headless-form-yup", []string{"1.0.1"}},
	{"ember-headless-form", []string{"1.1.2", "1.1.3"}},
	{"ember-headless-table", []string{"2.1.5", "2.1.6"}},
	{"ember-url-hash-polyfill", []string{"1.0.12", "1.0.13"}},
	{"ember-velcro", []string{"2.2.1", "2.2.2"}},
	{"eslint-config-crowdstrike-node", []string{"4.0.3", "4.0.4"}},
	{"eslint-config-crowdstrike", []string{"11.0.2", "11.0.3"}},
	{"eslint-config-teselagen", []string{"6.1.7", "6.1.8"}},
	{"globalize-rpk", []string{"1.7.4"}},
	{"graphql-sequelize-teselagen", []string{"5.3.8", "5.3.9"}},
	{"html-to-base64-image", []string{"1.0.2"}},
	{"jumpgate", []string{"0.0.2"}},
	{"mcfly-semantic-release", []string{"1.3.1"}},
	{"mcp-knowledge-base", []string{"0.0.2"}},
	{"mcp-knowledge-graph", []string{"1.2.1"}},
	{"mobioffice-cli", []string{"1.0.3"}},
	{"monorepo-next", []string{"13.0.1", "13.0.2"}},
	{"mstate-angular", []string{"0.4.4"}},
	{"mstate-cli", []string{"0.4.7"}},
	{"mstate-dev-react", []string{"1.1.1"}},
	{"mstate-react", []string{"1.6.5"}},
	{"ng2-file-upload", []string{"7.0.2", "7.0.3", "8.0.1", "8.0.2", "8.0.3", "9.0.1"}},
	{"ngx-bootstrap", []string{"18.1.4", "19.0.3", "19.0.4", "20.0.3", "20.0.4", "20.0.5"}},
	{"ngx-ws", []string{"1.1.5", "1.1.6"}},
	{"oradm-to-gql", []string{"35.0.14", "35.0.15"}},
	{"oradm-to-sqlz", []string{"1.1.2"}},
	{"ove-auto-annotate", []string{"0.0.9", "0.0.10"}},
	{"pm2-gelf-json", []string{"1.0.4", "1.0.5"}},
	{"printjs-rpk", []string{"1.6.1"}},
	{"react-jsonschema-rxnt-extras", []string{"0.4.9"}},
	{"remark-preset-lint-crowdstrike", []string{"4.0.1", "4.0.2"}},
	{"tbssnch", []string{"1.0.2"}},
	{"teselagen-interval-tree", []string{"1.1.2"}},
	{"tg-client-query-builder", []string{"2.14.4", "2.14.5"}},
	{"tg-redbird", []string{"1.3.1", "1.3.2"}},
	{"tg-seq-gen", []string{"1.0.9", "1.0.10"}},
	{"thangved-react-grid", []string{"1.0.3"}},
	{"ts-imports", []string{"1.0.1", "1.0.2"}},
	{"tvi-cli", []string{"0.1.5"}},
	{"ve-bamreader", []string{"0.2.6", "0.2.7"}},
	{"ve-editor", []string{"1.0.1", "1.0.2"}},
	{"verror-extra", []string{"6.0.1"}},
	{"voip-callkit", []string{"1.0.2", "1.0.3"}},
	{"wdio-web-reporter", []string{"0.1.3"}},
	{"yargs-help-output", []string{"5.0.3"}},
	{"yoo-styles", []string{"6.0.326"}},
}

func main() {
	config := ScanConfig{}

	flag.StringVar(&config.BaseDir, "dir", ".", "Base directory to scan (default: current directory)")
	flag.BoolVar(&config.NoGlobal, "no-global", false, "Skip global cache scanning")
	flag.BoolVar(&config.NoNVM, "no-nvm", false, "Skip NVM directory scanning")
	flag.BoolVar(&config.RepoOnly, "repo-only", false, "Only scan repository files (skip all global caches)")
	flag.IntVar(&config.MaxWorkers, "workers", runtime.NumCPU()*2, "Number of concurrent workers")
	flag.BoolVar(&config.Verbose, "verbose", false, "Verbose output")
	flag.Parse()

	// Handle repo-only flag
	if config.RepoOnly {
		config.NoGlobal = true
		config.NoNVM = true
	}

	// Validate and normalize base directory
	absPath, err := filepath.Abs(config.BaseDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Error resolving path '%s': %v\n", config.BaseDir, err)
		os.Exit(1)
	}

	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "❌ Directory '%s' does not exist\n", absPath)
		os.Exit(1)
	}
	config.BaseDir = absPath

	fmt.Println("🔍 Scanning for compromised NPM packages...")
	fmt.Printf("🔎 Base directory: %s\n", config.BaseDir)
	fmt.Printf("🔧 Workers: %d\n", config.MaxWorkers)

	start := time.Now()
	findings := scanForCompromisedPackages(config)
	duration := time.Since(start)

	fmt.Printf("\n📊 Scan completed in %v\n", duration)
	printResults(findings, config)
}

func scanForCompromisedPackages(config ScanConfig) []Finding {
	var findings []Finding
	var mutex sync.Mutex

	// Create worker pool
	jobs := make(chan func(), 1000)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < config.MaxWorkers; i++ {
		go func() {
			for job := range jobs {
				job()
			}
		}()
	}

	addFinding := func(finding Finding) {
		mutex.Lock()
		findings = append(findings, finding)
		mutex.Unlock()
	}

	// Scan repository files
	fmt.Println("🔒 Scanning project lockfiles and package.json...")
	scanLockfiles(config.BaseDir, jobs, &wg, addFinding, config.Verbose)

	fmt.Println("🐳 Scanning Dockerfiles...")
	scanDockerfiles(config.BaseDir, jobs, &wg, addFinding, config.Verbose)

	fmt.Println("⚙️ Scanning CI/CD config files...")
	scanCIConfigs(config.BaseDir, jobs, &wg, addFinding, config.Verbose)

	fmt.Println("📁 Scanning vendored folders...")
	scanVendoredDirs(config.BaseDir, jobs, &wg, addFinding, config.Verbose)

	// Scan global caches if not disabled
	if !config.NoGlobal {
		fmt.Println("📦 Scanning global npm caches...")
		scanGlobalCaches(jobs, &wg, addFinding, config.Verbose)
	}

	if !config.NoNVM {
		fmt.Println("🧠 Scanning NVM-managed Node versions...")
		scanNVMVersions(jobs, &wg, addFinding, config.Verbose)
	}

	// Wait for all jobs to complete
	wg.Wait()
	close(jobs)

	return findings
}

func scanLockfiles(baseDir string, jobs chan<- func(), wg *sync.WaitGroup, addFinding func(Finding), verbose bool) {
	lockfilePatterns := []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}
	fileCount := 0

	for _, pattern := range lockfilePatterns {
		filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}

			if info.Name() == pattern {
				fileCount++
				if verbose {
					fmt.Printf("  📄 Found lockfile: %s\n", path)
				}
				wg.Add(1)
				jobs <- func() {
					defer wg.Done()
					scanLockfileResolved(path, addFinding, verbose)
				}
			}
			return nil
		})
	}
}

func scanLockfileResolved(filePath string, addFinding func(Finding), verbose bool) {
	file, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer file.Close()

	// Determine lockfile type
	filename := filepath.Base(filePath)

	switch filename {
	case "package-lock.json":
		scanPackageLockJson(file, filePath, addFinding, verbose)
	case "yarn.lock":
		scanYarnLock(file, filePath, addFinding, verbose)
	case "pnpm-lock.yaml":
		scanPnpmLock(file, filePath, addFinding, verbose)
	}
}

func scanPackageLockJson(file *os.File, filePath string, addFinding func(Finding), verbose bool) {
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		for _, pkg := range compromisedPackages {
			for _, version := range pkg.Versions {
				// Match resolved tarball URLs in package-lock.json
				// Handle scoped packages correctly
				packageName := pkg.Name
				tarballName := packageName
				if strings.HasPrefix(packageName, "@") {
					parts := strings.Split(packageName, "/")
					if len(parts) == 2 {
						tarballName = parts[1] // Remove scope for tarball name
					}
				}

				pattern := fmt.Sprintf("%s/-/%s-%s.tgz", packageName, tarballName, version)
				if strings.Contains(line, pattern) {
					addFinding(Finding{
						Package: pkg.Name,
						Version: version,
						File:    filePath,
						Type:    "resolved",
					})
					if verbose {
						fmt.Printf("  Found resolved %s@%s in %s\n", pkg.Name, version, filePath)
					}
				}
			}
		}
	}
}

func scanYarnLock(file *os.File, filePath string, addFinding func(Finding), verbose bool) {
	scanner := bufio.NewScanner(file)
	currentPackage := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Track current package context
		for _, pkg := range compromisedPackages {
			// Check for package declaration lines like: "package@version":
			if strings.HasPrefix(line, "\"") && strings.Contains(line, pkg.Name) && strings.Contains(line, "@") {
				if strings.HasSuffix(line, "\":") || strings.HasSuffix(line, "\", ") {
					currentPackage = pkg.Name
					// Extract version from package@version declaration
					for _, version := range pkg.Versions {
						if strings.Contains(line, fmt.Sprintf("%s@%s", pkg.Name, version)) {
							addFinding(Finding{
								Package: pkg.Name,
								Version: version,
								File:    filePath,
								Type:    "resolved",
							})
							if verbose {
								fmt.Printf("  Found resolved %s@%s in %s\n", pkg.Name, version, filePath)
							}
							break
						}
					}
				}
			}
		}

		// Check for version field when we're in the right package context
		if currentPackage != "" && strings.HasPrefix(line, "version ") {
			for _, pkg := range compromisedPackages {
				if pkg.Name == currentPackage {
					for _, version := range pkg.Versions {
						if strings.Contains(line, fmt.Sprintf("\"%s\"", version)) {
							addFinding(Finding{
								Package: pkg.Name,
								Version: version,
								File:    filePath,
								Type:    "resolved",
							})
							if verbose {
								fmt.Printf("  Found resolved %s@%s in %s\n", pkg.Name, version, filePath)
							}
							break
						}
					}
				}
			}
		}

		// Reset context when we hit a new package or end of block
		if strings.HasSuffix(line, "\":") && !strings.Contains(line, currentPackage) {
			currentPackage = ""
		}
	}
}

func scanPnpmLock(file *os.File, filePath string, addFinding func(Finding), verbose bool) {
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		for _, pkg := range compromisedPackages {
			for _, version := range pkg.Versions {
				// pnpm-lock.yaml format patterns:
				// In dependencies section: 'package': version or "package": "version"
				// In packages section: /package/version: or /@scope/package/version:
				patterns := []string{
					// Dependencies section patterns
					fmt.Sprintf("'%s': %s", pkg.Name, version),
					fmt.Sprintf("\"%s\": \"%s\"", pkg.Name, version),
					fmt.Sprintf("'%s': '%s'", pkg.Name, version),
					fmt.Sprintf("%s: %s", pkg.Name, version),
					// Packages section patterns
					fmt.Sprintf("/%s/%s:", pkg.Name, version),
					// Also check for @package@version format
					fmt.Sprintf("%s@%s", pkg.Name, version),
				}

				for _, pattern := range patterns {
					if strings.Contains(line, pattern) {
						addFinding(Finding{
							Package: pkg.Name,
							Version: version,
							File:    filePath,
							Type:    "resolved",
						})
						if verbose {
							fmt.Printf("  Found resolved %s@%s in %s\n", pkg.Name, version, filePath)
						}
						break
					}
				}
			}
		}
	}
}

func scanDockerfiles(baseDir string, jobs chan<- func(), wg *sync.WaitGroup, addFinding func(Finding), verbose bool) {
	dockerfileCount := 0
	filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		if strings.ToLower(info.Name()) == "dockerfile" {
			dockerfileCount++
			if verbose {
				fmt.Printf("  🐳 Found Dockerfile: %s\n", path)
			}
			wg.Add(1)
			jobs <- func() {
				defer wg.Done()
				scanFile(path, addFinding, verbose)
			}
		}
		return nil
	})
	if verbose && dockerfileCount == 0 {
		fmt.Printf("  ℹ️  No Dockerfiles found in %s\n", baseDir)
	}
}

func scanCIConfigs(baseDir string, jobs chan<- func(), wg *sync.WaitGroup, addFinding func(Finding), verbose bool) {
	ciConfigCount := 0
	filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		// Check if it's a YAML file in CI directories
		if (strings.HasSuffix(info.Name(), ".yml") || strings.HasSuffix(info.Name(), ".yaml")) &&
			(strings.Contains(path, "/.github/") || strings.Contains(path, "/.gitlab/")) {
			ciConfigCount++
			if verbose {
				fmt.Printf("  ⚙️ Found CI config: %s\n", path)
			}
			wg.Add(1)
			jobs <- func() {
				defer wg.Done()
				scanFile(path, addFinding, verbose)
			}
		}
		return nil
	})
	if verbose && ciConfigCount == 0 {
		fmt.Printf("  ℹ️  No CI/CD config files found in %s\n", baseDir)
	}
}

func scanVendoredDirs(baseDir string, jobs chan<- func(), wg *sync.WaitGroup, addFinding func(Finding), verbose bool) {
	vendoredDirs := []string{"vendor", "third_party", "static", "assets"}
	foundDirs := 0

	for _, dir := range vendoredDirs {
		vendorPath := filepath.Join(baseDir, dir)
		if _, err := os.Stat(vendorPath); err == nil {
			foundDirs++
			if verbose {
				fmt.Printf("  📁 Scanning vendored directory: %s\n", vendorPath)
			}
			fileCount := 0
			filepath.Walk(vendorPath, func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return nil
				}

				ext := strings.ToLower(filepath.Ext(info.Name()))
				if ext == ".js" || ext == ".json" || ext == ".tgz" {
					fileCount++
					if verbose && fileCount <= 5 {
						fmt.Printf("    📄 Scanning: %s\n", path)
					} else if verbose && fileCount == 6 {
						fmt.Printf("    ... (scanning more files)\n")
					}
					wg.Add(1)
					jobs <- func() {
						defer wg.Done()
						scanFile(path, addFinding, verbose)
					}
				}
				return nil
			})
		}
	}
	if verbose && foundDirs == 0 {
		fmt.Printf("  ℹ️  No vendored directories found in %s\n", baseDir)
	}
}

func scanGlobalCaches(jobs chan<- func(), wg *sync.WaitGroup, addFinding func(Finding), verbose bool) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		if verbose {
			fmt.Printf("  ❌ Could not get home directory: %v\n", err)
		}
		return
	}

	if verbose {
		fmt.Printf("  🏠 Home directory: %s\n", homeDir)
	}

	yarnCache := getYarnCacheDir()
	pnpmStore := getPnpmStoreDir()

	var cacheDirs []string
	if runtime.GOOS == "windows" {
		// Windows npm cache locations
		appDataRoaming := os.Getenv("APPDATA")
		appDataLocal := os.Getenv("LOCALAPPDATA")

		cacheDirs = []string{
			filepath.Join(appDataRoaming, "npm-cache"),
			filepath.Join(appDataLocal, "npm-cache"),
			filepath.Join(homeDir, ".npm", "_cacache"), // Fallback for WSL/Git Bash
			filepath.Join(homeDir, ".npm-packages"),
			yarnCache,
			pnpmStore,
		}
	} else {
		// Unix-like systems
		cacheDirs = []string{
			filepath.Join(homeDir, ".npm", "_cacache"),
			filepath.Join(homeDir, ".npm-packages"),
			yarnCache,
			pnpmStore,
		}
	}

	var cacheNames []string
	if runtime.GOOS == "windows" {
		cacheNames = []string{"npm APPDATA cache", "npm LOCALAPPDATA cache", "npm _cacache", "npm-packages", "yarn cache", "pnpm store"}
	} else {
		cacheNames = []string{"npm _cacache", "npm-packages", "yarn cache", "pnpm store"}
	}

	for i, cacheDir := range cacheDirs {
		if cacheDir != "" {
			if _, err := os.Stat(cacheDir); err == nil {
				if verbose {
					fmt.Printf("  📦 Scanning %s: %s\n", cacheNames[i], cacheDir)
				}
				wg.Add(1)
				jobs <- func() {
					defer wg.Done()
					scanCacheDir(cacheDir, addFinding, verbose)
				}
			}
		}
	}
}

func scanNVMVersions(jobs chan<- func(), wg *sync.WaitGroup, addFinding func(Finding), verbose bool) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		if verbose {
			fmt.Printf("  ❌ Could not get home directory: %v\n", err)
		}
		return
	}

	var nvmDir, versionsDir string

	if runtime.GOOS == "windows" {
		// Windows typically uses nvm-windows which stores in APPDATA
		appData := os.Getenv("APPDATA")
		nvmDir = os.Getenv("NVM_HOME") // nvm-windows uses NVM_HOME
		if nvmDir == "" && appData != "" {
			nvmDir = filepath.Join(appData, "nvm")
		}
		if nvmDir != "" {
			versionsDir = nvmDir // nvm-windows stores versions directly in NVM_HOME
		}
	} else {
		// Unix-like systems
		nvmDir = os.Getenv("NVM_DIR")
		if nvmDir == "" {
			nvmDir = filepath.Join(homeDir, ".nvm")
		}
		versionsDir = filepath.Join(nvmDir, "versions", "node")
	}

	if verbose {
		fmt.Printf("  🔍 NVM directory: %s\n", nvmDir)
	}

	if versionsDir == "" || nvmDir == "" {
		if verbose {
			fmt.Printf("  ❌ NVM directory not configured\n")
		}
		return
	}

	if _, err := os.Stat(versionsDir); err != nil {
		if verbose {
			fmt.Printf("  ❌ NVM versions directory not found: %s\n", versionsDir)
		}
		return
	}

	filepath.Walk(versionsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.IsDir() {
			return nil
		}

		if info.Name() == "node_modules" || info.Name() == ".npm" {
			wg.Add(1)
			jobs <- func() {
				defer wg.Done()
				scanCacheDir(path, addFinding, verbose)
			}
		}
		return nil
	})
}

func scanFile(filePath string, addFinding func(Finding), verbose bool) {
	file, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		for _, pkg := range compromisedPackages {
			if strings.Contains(line, pkg.Name) {
				for _, version := range pkg.Versions {
					if strings.Contains(line, version) {
						addFinding(Finding{
							Package: pkg.Name,
							Version: version,
							File:    filePath,
							Type:    "file",
						})
						if verbose {
							fmt.Printf("  Found %s@%s in %s\n", pkg.Name, version, filePath)
						}
					}
				}
			}
		}
	}
}

func scanCacheDir(cacheDir string, addFinding func(Finding), verbose bool) {
	filepath.Walk(cacheDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		for _, pkg := range compromisedPackages {
			for _, version := range pkg.Versions {
				pattern := fmt.Sprintf("%s@%s", pkg.Name, version)
				if strings.Contains(path, pattern) {
					addFinding(Finding{
						Package: pkg.Name,
						Version: version,
						File:    path,
						Type:    "cache",
					})
					if verbose {
						fmt.Printf("  Found %s@%s in cache: %s\n", pkg.Name, version, path)
					}
				}
			}
		}
		return nil
	})
}

func getYarnCacheDir() string {
	// Try to get yarn cache directory by executing yarn cache dir
	cmd := exec.Command("yarn", "cache", "dir")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func getPnpmStoreDir() string {
	// Try to get pnpm store directory by executing pnpm store path
	cmd := exec.Command("pnpm", "store", "path")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

// isRoot checks if a path is a root directory (cross-platform)
func isRoot(path string) bool {
	if runtime.GOOS == "windows" {
		// On Windows, check if it's a drive root like "C:\" or "C:/"
		if len(path) == 3 && path[1] == ':' && (path[2] == '\\' || path[2] == '/') {
			return true
		}
		if len(path) == 2 && path[1] == ':' {
			return true
		}
	}
	// On Unix-like systems
	return path == "/"
}

func printResults(findings []Finding, config ScanConfig) {
	fmt.Println("\n📊 Summary of Findings:")

	if len(findings) == 0 {
		fmt.Println("✅ No compromised packages found.")
		return
	}

	// Group findings by project directory and package manager
	type findingDetail struct {
		Package string
		Version string
		File    string
		Type    string
		Line    int // Not used yet, but can be extended
	}

	projectGroups := make(map[string][]findingDetail)
	projectTools := make(map[string]string)
	findingTypes := make(map[string]map[string]int)

	for _, finding := range findings {
		dir := filepath.Dir(finding.File)
		if strings.Contains(dir, "/node_modules/") {
			parts := strings.Split(dir, "/node_modules/")
			dir = parts[0]
		} else if strings.HasSuffix(dir, "/node_modules") {
			dir = strings.TrimSuffix(dir, "/node_modules")
		}
		projectRoot := dir
		for !isRoot(projectRoot) && projectRoot != "." {
			if _, err := os.Stat(filepath.Join(projectRoot, "package-lock.json")); err == nil {
				projectTools[projectRoot] = "npm"
				break
			} else if _, err := os.Stat(filepath.Join(projectRoot, "yarn.lock")); err == nil {
				projectTools[projectRoot] = "yarn"
				break
			} else if _, err := os.Stat(filepath.Join(projectRoot, "pnpm-lock.yaml")); err == nil {
				projectTools[projectRoot] = "pnpm"
				break
			} else if _, err := os.Stat(filepath.Join(projectRoot, "package.json")); err == nil {
				projectTools[projectRoot] = "unknown"
				break
			}
			projectRoot = filepath.Dir(projectRoot)
		}
		projectGroups[projectRoot] = append(projectGroups[projectRoot], findingDetail{
			Package: finding.Package,
			Version: finding.Version,
			File:    finding.File,
			Type:    finding.Type,
			Line:    0, // Not tracked yet
		})
		if _, exists := findingTypes[projectRoot]; !exists {
			findingTypes[projectRoot] = make(map[string]int)
		}
		findingTypes[projectRoot][finding.Type]++
	}

	// Prepare report lines
	var reportLines []string
	reportLines = append(reportLines, fmt.Sprintf("Found %d compromised package references across %d projects:\n", len(findings), len(projectGroups)))

	for projectRoot, projectFindings := range projectGroups {
		tool := projectTools[projectRoot]
		if tool == "" {
			tool = "unknown"
		}
		reportLines = append(reportLines, fmt.Sprintf("🏗️  Project: %s", projectRoot))
		reportLines = append(reportLines, fmt.Sprintf("   📦 Package Manager: %s", tool))
		reportLines = append(reportLines, fmt.Sprintf("   🚨 Issues Found: %d", len(projectFindings)))

		// Show breakdown by type
		types := findingTypes[projectRoot]
		if types["resolved"] > 0 {
			reportLines = append(reportLines, fmt.Sprintf("   📋 Lockfile references: %d", types["resolved"]))
		}
		if types["file"] > 0 {
			reportLines = append(reportLines, fmt.Sprintf("   📄 File references: %d", types["file"]))
		}
		if types["cache"] > 0 {
			reportLines = append(reportLines, fmt.Sprintf("   💾 Cache entries: %d", types["cache"]))
		}

		// List affected packages with locations
		reportLines = append(reportLines, "   📋 Affected packages:")
		packageMap := make(map[string]map[string][]findingDetail) // pkg -> version -> []findingDetail
		for _, d := range projectFindings {
			if _, ok := packageMap[d.Package]; !ok {
				packageMap[d.Package] = make(map[string][]findingDetail)
			}
			packageMap[d.Package][d.Version] = append(packageMap[d.Package][d.Version], d)
		}
		for pkg, versions := range packageMap {
			for version, details := range versions {
				for _, d := range details {
					loc := d.File
					if d.Line > 0 {
						loc = fmt.Sprintf("%s:%d", d.File, d.Line)
					}
					reportLines = append(reportLines, fmt.Sprintf("      • %s@%s in %s [%s]", pkg, version, loc, d.Type))
				}
			}
		}
		reportLines = append(reportLines, "")
	}

	// Final summary
	reportLines = append(reportLines, "📋 Final Report:")
	reportLines = append(reportLines, fmt.Sprintf("   Total compromised references: %d", len(findings)))
	reportLines = append(reportLines, fmt.Sprintf("   Affected projects: %d", len(projectGroups)))

	// Count by package manager
	toolCounts := make(map[string]int)
	for _, tool := range projectTools {
		toolCounts[tool]++
	}
	reportLines = append(reportLines, "   Projects by package manager:")
	for tool, count := range toolCounts {
		reportLines = append(reportLines, fmt.Sprintf("      • %s: %d", tool, count))
	}

	// Write detailed report to file (in current working directory)
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Could not get current working directory: %v\n", err)
		return
	}
	reportPath := filepath.Join(cwd, "scan-report.txt")
	f, err := os.Create(reportPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Could not write report to %s: %v\n", reportPath, err)
		return
	}
	defer f.Close()

	// Add timestamp to file report
	f.WriteString("NPM Supply Chain Scan Report\n")
	f.WriteString(fmt.Sprintf("Generated: %s\n", time.Now().Format("2006-01-02 15:04:05 MST")))
	f.WriteString(fmt.Sprintf("Scan Directory: %s\n\n", config.BaseDir))
	f.WriteString(strings.Repeat("=", 80) + "\n\n")

	for _, line := range reportLines {
		f.WriteString(line + "\n")
	}

	// Print summary to stdout (less verbose)
	fmt.Printf("Found %d compromised package references across %d projects\n", len(findings), len(projectGroups))

	// Count by package manager for console summary
	if len(toolCounts) > 0 {
		fmt.Printf("Projects by package manager: ")
		first := true
		for tool, count := range toolCounts {
			if !first {
				fmt.Printf(", ")
			}
			fmt.Printf("%s: %d", tool, count)
			first = false
		}
		fmt.Println()
	}

	fmt.Printf("\n📝 Full detailed report written to %s\n", reportPath)
}
