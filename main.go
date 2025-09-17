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
	{"angulartics2", []string{"14.1.2"}},
	{"@ctrl/deluge", []string{"7.2.2"}},
	{"@ctrl/golang-template", []string{"1.4.3"}},
	{"@ctrl/magnet-link", []string{"4.0.4"}},
	{"@ctrl/ngx-codemirror", []string{"7.0.2"}},
	{"@ctrl/ngx-csv", []string{"6.0.2"}},
	{"@ctrl/ngx-emoji-mart", []string{"9.2.2"}},
	{"@ctrl/ngx-rightclick", []string{"4.0.2"}},
	{"@ctrl/qbittorrent", []string{"9.7.2"}},
	{"@ctrl/react-adsense", []string{"2.0.2"}},
	{"@ctrl/shared-torrent", []string{"6.3.2"}},
	{"@ctrl/tinycolor", []string{"4.1.1", "4.1.2"}},
	{"@ctrl/torrent-file", []string{"4.1.2"}},
	{"@ctrl/transmission", []string{"7.3.1"}},
	{"@ctrl/ts-base32", []string{"4.0.2"}},
	{"encounter-playground", []string{"0.0.5"}},
	{"json-rules-engine-simplified", []string{"0.2.4", "0.2.1"}},
	{"koa2-swagger-ui", []string{"5.11.2", "5.11.1"}},
	{"@nativescript-community/gesturehandler", []string{"2.0.35"}},
	{"@nativescript-community/sentry", []string{"4.6.43"}},
	{"@nativescript-community/text", []string{"1.6.13"}},
	{"@nativescript-community/ui-collectionview", []string{"6.0.6"}},
	{"@nativescript-community/ui-drawer", []string{"0.1.30"}},
	{"@nativescript-community/ui-image", []string{"4.5.6"}},
	{"@nativescript-community/ui-material-bottomsheet", []string{"7.2.72"}},
	{"@nativescript-community/ui-material-core", []string{"7.2.76"}},
	{"@nativescript-community/ui-material-core-tabs", []string{"7.2.76"}},
	{"ngx-color", []string{"10.0.2"}},
	{"ngx-toastr", []string{"19.0.2"}},
	{"ngx-trend", []string{"8.0.1"}},
	{"react-complaint-image", []string{"0.0.35"}},
	{"react-jsonschema-form-conditionals", []string{"0.3.21"}},
	{"react-jsonschema-form-extras", []string{"1.0.4"}},
	{"rxnt-authentication", []string{"0.0.6"}},
	{"rxnt-healthchecks-nestjs", []string{"1.0.5"}},
	{"rxnt-kue", []string{"1.0.7"}},
	{"swc-plugin-component-annotate", []string{"1.9.2"}},
	{"ts-gaussian", []string{"3.0.6"}},
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

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		for _, pkg := range compromisedPackages {
			for _, version := range pkg.Versions {
				// Match resolved tarball URLs
				pattern := fmt.Sprintf("%s/-/%s-%s.tgz", pkg.Name, pkg.Name, version)
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

	cacheDirs := []string{
		filepath.Join(homeDir, ".npm", "_cacache"),
		filepath.Join(homeDir, ".npm-packages"),
		yarnCache,
		pnpmStore,
	}

	cacheNames := []string{"npm _cacache", "npm-packages", "yarn cache", "pnpm store"}

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

	nvmDir := os.Getenv("NVM_DIR")
	if nvmDir == "" {
		nvmDir = filepath.Join(homeDir, ".nvm")
	}

	if verbose {
		fmt.Printf("  🔍 NVM directory: %s\n", nvmDir)
	}

	versionsDir := filepath.Join(nvmDir, "versions", "node")
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

func printResults(findings []Finding, config ScanConfig) {
	fmt.Println("\n📊 Summary of Findings:")

	if len(findings) == 0 {
		fmt.Println("✅ No compromised packages found.")
		return
	}

	// Group findings by project directory and package manager
	projectGroups := make(map[string][]Finding)
	projectTools := make(map[string]string)
	packageCount := make(map[string]int)
	findingTypes := make(map[string]map[string]int)

	for _, finding := range findings {
		dir := filepath.Dir(finding.File)

		// Trim path before node_modules if present
		if strings.Contains(dir, "/node_modules/") {
			parts := strings.Split(dir, "/node_modules/")
			dir = parts[0]
		} else if strings.HasSuffix(dir, "/node_modules") {
			dir = strings.TrimSuffix(dir, "/node_modules")
		}

		// Walk up to find project root
		projectRoot := dir
		for projectRoot != "/" && projectRoot != "." {
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

		projectGroups[projectRoot] = append(projectGroups[projectRoot], finding)

		// Count findings by type per project
		if _, exists := findingTypes[projectRoot]; !exists {
			findingTypes[projectRoot] = make(map[string]int)
		}
		findingTypes[projectRoot][finding.Type]++
		packageCount[projectRoot]++
	}

	// Print detailed findings
	fmt.Printf("Found %d compromised package references across %d projects:\n\n", len(findings), len(projectGroups))

	for projectRoot, projectFindings := range projectGroups {
		tool := projectTools[projectRoot]
		if tool == "" {
			tool = "unknown"
		}

		fmt.Printf("🏗️  Project: %s\n", projectRoot)
		fmt.Printf("   📦 Package Manager: %s\n", tool)
		fmt.Printf("   🚨 Issues Found: %d\n", len(projectFindings))

		// Show breakdown by type
		types := findingTypes[projectRoot]
		if types["resolved"] > 0 {
			fmt.Printf("   📋 Lockfile references: %d\n", types["resolved"])
		}
		if types["file"] > 0 {
			fmt.Printf("   📄 File references: %d\n", types["file"])
		}
		if types["cache"] > 0 {
			fmt.Printf("   💾 Cache entries: %d\n", types["cache"])
		}

		// List affected packages
		uniquePackages := make(map[string][]string)
		for _, finding := range projectFindings {
			uniquePackages[finding.Package] = append(uniquePackages[finding.Package], finding.Version)
		}

		fmt.Printf("   📋 Affected packages:\n")
		for pkg, versions := range uniquePackages {
			// Remove duplicates from versions
			versionSet := make(map[string]bool)
			for _, v := range versions {
				versionSet[v] = true
			}
			uniqueVersions := make([]string, 0, len(versionSet))
			for v := range versionSet {
				uniqueVersions = append(uniqueVersions, v)
			}
			fmt.Printf("      • %s (%s)\n", pkg, strings.Join(uniqueVersions, ", "))
		}
		fmt.Println()
	}

	// Final summary
	fmt.Println("📋 Final Report:")
	fmt.Printf("   Total compromised references: %d\n", len(findings))
	fmt.Printf("   Affected projects: %d\n", len(projectGroups))

	// Count by package manager
	toolCounts := make(map[string]int)
	for _, tool := range projectTools {
		toolCounts[tool]++
	}
	fmt.Println("   Projects by package manager:")
	for tool, count := range toolCounts {
		fmt.Printf("      • %s: %d\n", tool, count)
	}
}
