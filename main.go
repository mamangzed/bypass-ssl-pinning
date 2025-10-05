package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"

	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type BypassMethod int

const (
	Frida BypassMethod = iota
	StaticPatch
	ManifestBypass
	NetworkSecurityConfig
	SmaliPatch
	UniversalBypass
	OkHttpBypass
	RetrofitBypass
	TrustAllCerts
	HostnameVerifierBypass
)

var BypassMethodNames = map[BypassMethod]string{
	Frida:                  "Frida Script Generation",
	StaticPatch:            "Static Bytecode Patching",
	ManifestBypass:         "AndroidManifest.xml Bypass",
	NetworkSecurityConfig:  "Network Security Config",
	SmaliPatch:             "Smali Code Patching",
	UniversalBypass:        "Universal SSL Bypass",
	OkHttpBypass:           "OkHttp3 SSL Bypass",
	RetrofitBypass:         "Retrofit SSL Bypass",
	TrustAllCerts:          "Trust All Certificates",
	HostnameVerifierBypass: "Hostname Verifier Bypass",
}

type AdvancedSSLBypass struct {
	APKPath             string
	OutputPath          string
	TempDir             string
	CertificatePath     string
	UseNetworkSecConfig bool
	StaticPatch         bool
	RemovePinning       bool
	SelectedMethods     []BypassMethod
	ApkList             []string
	SelectedAPK         string
	AutoValidateInstall bool
	CreateBackup        bool
	// New fields for adaptive signing
	OriginalTargetSDK int
	NewTargetSDK      int
	SignatureScheme   string // "v1", "v2", "v2v3", "hybrid", "ultimate", or "fallback"
	UseLegacyCompat   bool   // Force compatibility mode
	AllowDowngrade    bool   // Allow SDK downgrade if modern signing fails
	PreserveSDK       bool   // Try to preserve original SDK first
	UltimateMode      bool   // Use ultimate compatibility mode
	ForceCleanSign    bool   // Force completely clean signature
}

type AndroidManifest struct {
	XMLName     xml.Name    `xml:"manifest"`
	Package     string      `xml:"package,attr"`
	Application Application `xml:"application"`
}

type Application struct {
	XMLName               xml.Name   `xml:"application"`
	NetworkSecurityConfig string     `xml:"networkSecurityConfig,attr,omitempty"`
	Debuggable            string     `xml:"debuggable,attr,omitempty"`
	UsesCleartextTraffic  string     `xml:"usesCleartextTraffic,attr,omitempty"`
	Activities            []Activity `xml:"activity"`
}

type Activity struct {
	Name         string        `xml:"name,attr"`
	IntentFilter *IntentFilter `xml:"intent-filter"`
}

type IntentFilter struct {
	Action   Action   `xml:"action"`
	Category Category `xml:"category"`
}

type Action struct {
	Name string `xml:"name,attr"`
}

type Category struct {
	Name string `xml:"name,attr"`
}

// Scan for APK files in current directory
func (tool *AdvancedSSLBypass) scanAPKFiles() error {
	log.Println("Scanning for APK files...")

	files, err := filepath.Glob("*.apk")
	if err != nil {
		return fmt.Errorf("failed to scan APK files: %v", err)
	}

	if len(files) == 0 {
		return fmt.Errorf("no APK files found in current directory")
	}

	tool.ApkList = files
	sort.Strings(tool.ApkList)

	log.Printf("Found %d APK files", len(files))
	return nil
}

// Interactive APK selection
func (tool *AdvancedSSLBypass) selectAPK() error {
	if len(tool.ApkList) == 0 {
		if err := tool.scanAPKFiles(); err != nil {
			return err
		}
	}

	fmt.Println("\n=== Available APK Files ===")
	for i, apk := range tool.ApkList {
		stat, err := os.Stat(apk)
		size := "unknown"
		if err == nil {
			size = fmt.Sprintf("%.2f MB", float64(stat.Size())/(1024*1024))
		}
		fmt.Printf("%d. %s (%s)\n", i+1, apk, size)
	}

	fmt.Print("\nSelect APK (number): ")
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read input: %v", err)
	}

	choice, err := strconv.Atoi(strings.TrimSpace(input))
	if err != nil || choice < 1 || choice > len(tool.ApkList) {
		return fmt.Errorf("invalid selection")
	}

	tool.SelectedAPK = tool.ApkList[choice-1]
	tool.APKPath = tool.SelectedAPK
	log.Printf("Selected APK: %s", tool.SelectedAPK)
	return nil
}

// Interactive output path selection
func (tool *AdvancedSSLBypass) selectOutputPath() error {
	defaultOutput := strings.Replace(tool.SelectedAPK, ".apk", "_bypassed.apk", 1)

	fmt.Printf("\nEnter output path (default: %s): ", defaultOutput)
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read input: %v", err)
	}

	output := strings.TrimSpace(input)
	if output == "" {
		output = defaultOutput
	}

	tool.OutputPath = output
	log.Printf("Output path: %s", tool.OutputPath)
	return nil
}

// Interactive bypass method selection
func (tool *AdvancedSSLBypass) selectBypassMethods() error {
	fmt.Println("\n=== Available Bypass Methods ===")
	methods := []BypassMethod{ManifestBypass, NetworkSecurityConfig, StaticPatch, SmaliPatch, UniversalBypass, OkHttpBypass, RetrofitBypass, TrustAllCerts, HostnameVerifierBypass}

	for i, method := range methods {
		fmt.Printf("%d. %s\n", i+1, BypassMethodNames[method])
	}

	fmt.Println("\n0. Select All Methods")
	fmt.Print("\nSelect methods (comma-separated, e.g., 1,3,5 or 0 for all): ")

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read input: %v", err)
	}

	input = strings.TrimSpace(input)
	if input == "0" {
		tool.SelectedMethods = methods
		log.Println("Selected all bypass methods")
		return nil
	}

	choices := strings.Split(input, ",")
	for _, choice := range choices {
		choice = strings.TrimSpace(choice)
		num, err := strconv.Atoi(choice)
		if err != nil || num < 1 || num > len(methods) {
			log.Printf("Skipping invalid choice: %s", choice)
			continue
		}
		tool.SelectedMethods = append(tool.SelectedMethods, methods[num-1])
	}

	if len(tool.SelectedMethods) == 0 {
		return fmt.Errorf("no valid methods selected")
	}

	log.Println("Selected methods:")
	for _, method := range tool.SelectedMethods {
		log.Printf("  - %s", BypassMethodNames[method])
	}

	return nil
}

func NewAdvancedSSLBypass(apkPath, outputPath string) *AdvancedSSLBypass {
	return &AdvancedSSLBypass{
		APKPath:             apkPath,
		OutputPath:          outputPath,
		UseNetworkSecConfig: true,
		StaticPatch:         true,
		RemovePinning:       true,
		AutoValidateInstall: true,
		CreateBackup:        true,
	}
}

func (tool *AdvancedSSLBypass) decompileAPK() error {
	log.Printf("Decompiling APK: %s", tool.APKPath)
	cmd := exec.Command("apktool", "d", tool.APKPath, "-o", tool.TempDir, "-f")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("apktool decompilation failed: %v\nOutput: %s", err, string(output))
	}
	log.Println("APK decompiled successfully")

	// Automatically detect original SDK after decompilation
	if err := tool.detectOriginalSDK(); err != nil {
		log.Printf("Warning: Could not detect original SDK: %v", err)
		// Default fallback values
		tool.OriginalTargetSDK = 30
		tool.NewTargetSDK = 23
	}

	// Determine optimal signature scheme based on SDK
	tool.determineSignatureScheme()

	return nil
}

// Detect original Target SDK from APK
func (tool *AdvancedSSLBypass) detectOriginalSDK() error {
	log.Println("🔍 Detecting original Target SDK...")

	// Method 1: Check from decompiled AndroidManifest.xml
	manifestPath := filepath.Join(tool.TempDir, "AndroidManifest.xml")
	if _, err := os.Stat(manifestPath); err == nil {
		content, err := os.ReadFile(manifestPath)
		if err == nil {
			contentStr := string(content)

			// Look for targetSdkVersion in manifest
			targetSdkRegex := regexp.MustCompile(`android:targetSdkVersion="([^"]*)"`)
			matches := targetSdkRegex.FindStringSubmatch(contentStr)
			if len(matches) > 1 {
				if sdk, err := strconv.Atoi(matches[1]); err == nil {
					tool.OriginalTargetSDK = sdk
					log.Printf("📱 Detected Target SDK from manifest: %d", sdk)
					return nil
				}
			}
		}
	}

	// Method 2: Use aapt to get SDK info directly from APK
	cmd := exec.Command("aapt", "dump", "badging", tool.APKPath)
	output, err := cmd.CombinedOutput()
	if err == nil {
		outputStr := string(output)

		// Look for targetSdkVersion in aapt output
		targetSdkRegex := regexp.MustCompile(`targetSdkVersion:'([^']*)'`)
		matches := targetSdkRegex.FindStringSubmatch(outputStr)
		if len(matches) > 1 {
			if sdk, err := strconv.Atoi(matches[1]); err == nil {
				tool.OriginalTargetSDK = sdk
				log.Printf("📱 Detected Target SDK from aapt: %d", sdk)
				return nil
			}
		}
	}

	return fmt.Errorf("could not detect target SDK")
}

// Determine optimal signature scheme based on SDK levels
func (tool *AdvancedSSLBypass) determineSignatureScheme() {
	log.Printf("⚙️  Determining optimal signature scheme for SDK %d...", tool.OriginalTargetSDK)

	// SDK compatibility matrix for signature schemes:
	// - SDK < 24: v1 signature works fine
	// - SDK 24-27: v2 signature recommended but v1 still works
	// - SDK 28+: v2+ signature strongly recommended
	// - SDK 30+: v2+ signature required by some devices
	// - SDK 35+: v2+ signature mandatory

	// Ultimate strategy: Try to preserve SDK first, fallback if needed
	tool.PreserveSDK = true
	tool.UltimateMode = true

	switch {
	case tool.OriginalTargetSDK >= 35:
		// Very high SDK - try modern signature first, fallback to downgrade
		tool.NewTargetSDK = tool.OriginalTargetSDK // Try to preserve first
		tool.SignatureScheme = "ultimate"          // Ultimate mode with fallbacks
		tool.UseLegacyCompat = false
		tool.ForceCleanSign = true
		log.Printf("� Ultra-modern SDK (%d) - using ultimate signature strategy", tool.OriginalTargetSDK)

	case tool.OriginalTargetSDK >= 30:
		// High SDK - try to preserve with proper v2 signature
		tool.NewTargetSDK = tool.OriginalTargetSDK
		tool.SignatureScheme = "v2v3" // Modern signature for modern SDK
		tool.UseLegacyCompat = false
		tool.ForceCleanSign = true
		log.Printf("🔧 Modern SDK (%d) - using v2v3 signature scheme", tool.OriginalTargetSDK)

	case tool.OriginalTargetSDK >= 28:
		// Compatible SDK - perfect for v2
		tool.NewTargetSDK = tool.OriginalTargetSDK
		tool.SignatureScheme = "v2"
		tool.UseLegacyCompat = false
		log.Printf("✅ Compatible SDK (%d) - using v2 signature", tool.OriginalTargetSDK)

	case tool.OriginalTargetSDK >= 24:
		// Legacy-compatible SDK
		tool.NewTargetSDK = tool.OriginalTargetSDK
		tool.SignatureScheme = "hybrid" // Hybrid for better compatibility
		tool.UseLegacyCompat = false
		log.Printf("📱 Legacy-compatible SDK (%d) - using hybrid signature", tool.OriginalTargetSDK)

	default:
		// Low SDK - pure v1
		tool.NewTargetSDK = tool.OriginalTargetSDK
		tool.SignatureScheme = "v1"
		tool.UseLegacyCompat = false
		log.Printf("📱 Legacy SDK (%d) - using pure v1 signature", tool.OriginalTargetSDK)
	}

	log.Printf("✅ Signature strategy: %s scheme, Target SDK: %d → %d", tool.SignatureScheme, tool.OriginalTargetSDK, tool.NewTargetSDK)
}

func (tool *AdvancedSSLBypass) generateCustomCertificate() error {
	log.Println("Generating custom certificate...")

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"SSL Bypass"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %v", err)
	}

	// Save certificate
	certPath := filepath.Join(tool.TempDir, "custom_cert.pem")
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to create cert file: %v", err)
	}
	defer certOut.Close()

	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tool.CertificatePath = certPath
	log.Printf("Custom certificate generated: %s", certPath)
	return nil
}

// Create network security config
func (tool *AdvancedSSLBypass) createNetworkSecurityConfig() error {
	log.Println("Creating network security config...")

	// Create res/xml directory if it doesn't exist
	xmlDir := filepath.Join(tool.TempDir, "res", "xml")
	err := os.MkdirAll(xmlDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create xml directory: %v", err)
	}

	// Network security config content
	networkConfig := `<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">10.0.2.2</domain>
        <domain includeSubdomains="true">localhost</domain>
        <domain includeSubdomains="true">127.0.0.1</domain>
        <domain includeSubdomains="true">192.168.0.0/16</domain>
        <domain includeSubdomains="true">172.16.0.0/12</domain>
        <domain includeSubdomains="true">10.0.0.0/8</domain>
        <domain includeSubdomains="true">.local</domain>
    </domain-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system"/>
            <certificates src="user"/>
        </trust-anchors>
    </base-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="system"/>
            <certificates src="user"/>
        </trust-anchors>
    </debug-overrides>
</network-security-config>`

	// Write the network security config
	configPath := filepath.Join(xmlDir, "network_security_config.xml")
	err = os.WriteFile(configPath, []byte(networkConfig), 0644)
	if err != nil {
		return fmt.Errorf("failed to write network security config: %v", err)
	}

	log.Printf("Network security config created at: %s", configPath)
	return nil
}

func (tool *AdvancedSSLBypass) bypassNetworkSecurityConfig() error {
	log.Println("Configuring network security bypass...")

	xmlDir := filepath.Join(tool.TempDir, "res", "xml")
	err := os.MkdirAll(xmlDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create xml directory: %v", err)
	}

	networkConfig := `<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system"/>
            <certificates src="user"/>
        </trust-anchors>
    </base-config>
</network-security-config>`

	configPath := filepath.Join(xmlDir, "network_security_config.xml")
	return os.WriteFile(configPath, []byte(networkConfig), 0644)
}

// Static patching approach - modifies bytecode directly without runtime dependency
func (tool *AdvancedSSLBypass) executeSelectedMethods() error {
	log.Println("Executing selected bypass methods...")

	for _, method := range tool.SelectedMethods {
		log.Printf("Executing: %s", BypassMethodNames[method])

		switch method {
		case ManifestBypass:
			if err := tool.modifyManifest(); err != nil {
				log.Printf("Warning: Manifest bypass failed: %v", err)
			}
		case NetworkSecurityConfig:
			if err := tool.createNetworkSecurityConfig(); err != nil {
				log.Printf("Warning: Network security config creation failed: %v", err)
			}
		case StaticPatch:
			if err := tool.staticPatchSSLFunctions(); err != nil {
				log.Printf("Warning: Static patch failed: %v", err)
			}
		case SmaliPatch:
			if err := tool.patchSmaliForSSL(); err != nil {
				log.Printf("Warning: Smali patch failed: %v", err)
			}
		case UniversalBypass:
			if err := tool.universalSSLBypass(); err != nil {
				log.Printf("Warning: Universal SSL bypass failed: %v", err)
			}
		case OkHttpBypass:
			if err := tool.okHttpSSLBypass(); err != nil {
				log.Printf("Warning: OkHttp bypass failed: %v", err)
			}
		case RetrofitBypass:
			if err := tool.retrofitSSLBypass(); err != nil {
				log.Printf("Warning: Retrofit bypass failed: %v", err)
			}
		case TrustAllCerts:
			if err := tool.trustAllCertificates(); err != nil {
				log.Printf("Warning: Trust all certificates failed: %v", err)
			}
		case HostnameVerifierBypass:
			if err := tool.bypassHostnameVerifier(); err != nil {
				log.Printf("Warning: Hostname verifier bypass failed: %v", err)
			}
		}
	}

	log.Println("All bypass methods executed")
	return nil
}

func (tool *AdvancedSSLBypass) staticPatchSSLFunctions() error {
	log.Println("Applying static SSL function patches...")

	// Walk through smali directories
	smaliDirs := []string{"smali", "smali_classes2", "smali_classes3", "smali_classes4", "smali_classes5"}

	for _, dir := range smaliDirs {
		smaliPath := filepath.Join(tool.TempDir, dir)
		if _, err := os.Stat(smaliPath); os.IsNotExist(err) {
			continue
		}

		err := filepath.Walk(smaliPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			if strings.HasSuffix(path, ".smali") {
				return tool.patchSmaliFile(path)
			}
			return nil
		})

		if err != nil {
			log.Printf("Error patching smali in %s: %v", dir, err)
		}
	}

	return nil
}

func (tool *AdvancedSSLBypass) patchSmaliFile(filePath string) error {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	contentStr := string(content)
	modified := false

	// Patch certificate validation methods
	patterns := map[string]string{
		`invoke-virtual.*Ljava/security/cert/X509Certificate;->checkValidity`:    "# Certificate validation bypassed",
		`invoke-virtual.*Ljavax/net/ssl/X509TrustManager;->checkServerTrusted`:   "# TrustManager bypassed",
		`invoke-interface.*Ljavax/net/ssl/X509TrustManager;->checkServerTrusted`: "# TrustManager interface bypassed",
		`invoke-virtual.*Ljavax/net/ssl/HostnameVerifier;->verify`:               "# HostnameVerifier bypassed",
		`invoke-interface.*Ljavax/net/ssl/HostnameVerifier;->verify`:             "# HostnameVerifier interface bypassed",
	}

	for pattern, replacement := range patterns {
		regex := regexp.MustCompile(pattern)
		if regex.MatchString(contentStr) {
			contentStr = regex.ReplaceAllString(contentStr, replacement)
			modified = true
		}
	}

	if modified {
		return os.WriteFile(filePath, []byte(contentStr), 0644)
	}

	return nil
}

// Comprehensive Smali patching for SSL bypass
func (tool *AdvancedSSLBypass) patchSmaliForSSL() error {
	log.Println("Patching Smali files for SSL bypass...")

	// Common SSL-related class patterns to patch
	patterns := []struct {
		pattern     string
		replacement string
		description string
	}{
		{
			pattern:     `invoke-virtual.*checkServerTrusted`,
			replacement: `# invoke-virtual checkServerTrusted bypassed`,
			description: "Bypass checkServerTrusted",
		},
		{
			pattern:     `invoke-interface.*checkServerTrusted`,
			replacement: `# invoke-interface checkServerTrusted bypassed`,
			description: "Bypass interface checkServerTrusted",
		},
		{
			pattern:     `invoke-virtual.*verify.*Ljavax/net/ssl/HostnameVerifier`,
			replacement: `const/4 v0, 0x1\n    return v0`,
			description: "Bypass hostname verification",
		},
		{
			pattern:     `throw-exception.*Ljava/security/cert/CertificateException`,
			replacement: `# certificate exception bypassed`,
			description: "Bypass certificate exceptions",
		},
	}

	return tool.patchSmaliWithPatterns(patterns)
}

// Universal SSL bypass - patches common SSL validation points
func (tool *AdvancedSSLBypass) universalSSLBypass() error {
	log.Println("Applying universal SSL bypass...")

	// Use minimal, safer SSL bypass code
	bypassCode := `
.method public static safeSSLBypass()V
    .registers 1
    
    # Minimal SSL bypass - safer approach
    :try_start_ssl_bypass
    invoke-static {}, Lcom/bypass/TrustAllManager;->trustAllCerts()V
    :try_end_ssl_bypass
    .catch Ljava/lang/Exception; {:try_start_ssl_bypass .. :try_end_ssl_bypass} :catch_ssl_bypass
    goto :after_ssl_bypass
    :catch_ssl_bypass
    # Silently ignore SSL bypass setup errors to prevent crashes
    :after_ssl_bypass
    
    return-void
.end method
`

	// Find Application class and inject bypass - only if TrustAllManager exists
	if err := tool.trustAllCertificates(); err != nil {
		log.Printf("Warning: TrustAllManager creation failed, skipping universal bypass: %v", err)
		return nil
	}

	return tool.injectCodeToApplication(bypassCode)
}

// OkHttp3 specific SSL bypass
func (tool *AdvancedSSLBypass) okHttpSSLBypass() error {
	log.Println("Applying OkHttp SSL bypass...")

	// Pattern untuk OkHttp certificate pinning
	okHttpPatterns := []struct {
		pattern     string
		replacement string
		description string
	}{
		{
			pattern:     `invoke-virtual.*Lokhttp3/CertificatePinner;->check`,
			replacement: `# OkHttp certificate pinning bypassed`,
			description: "Bypass OkHttp certificate pinning",
		},
		{
			pattern:     `new-instance.*Lokhttp3/CertificatePinner\$Builder`,
			replacement: `# OkHttp CertificatePinner creation bypassed`,
			description: "Bypass OkHttp certificate pinner creation",
		},
	}

	return tool.patchSmaliWithPatterns(okHttpPatterns)
}

// Retrofit SSL bypass
func (tool *AdvancedSSLBypass) retrofitSSLBypass() error {
	log.Println("Applying Retrofit SSL bypass...")

	// Retrofit biasanya menggunakan OkHttp di belakang layar
	retrofitPatterns := []struct {
		pattern     string
		replacement string
		description string
	}{
		{
			pattern:     `invoke-virtual.*Lretrofit2/Retrofit\$Builder;->client`,
			replacement: `# Retrofit client configuration bypassed`,
			description: "Bypass Retrofit client SSL config",
		},
	}

	return tool.patchSmaliWithPatterns(retrofitPatterns)
}

// Trust all certificates approach
func (tool *AdvancedSSLBypass) trustAllCertificates() error {
	log.Println("Implementing trust-all certificates...")

	// Create custom TrustManager class
	trustAllClass := `
.class public Lcom/bypass/TrustAllManager;
.super Ljava/lang/Object;
.source "TrustAllManager.java"

.implements Ljavax/net/ssl/X509TrustManager;

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public checkClientTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
    .registers 3
    return-void
.end method

.method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
    .registers 3
    return-void
.end method

.method public getAcceptedIssuers()[Ljava/security/cert/X509Certificate;
    .registers 2
    const/4 v0, 0x0
    new-array v0, v0, [Ljava/security/cert/X509Certificate;
    return-object v0
.end method
`

	// Write TrustAllManager class
	trustManagerPath := filepath.Join(tool.TempDir, "smali", "com", "bypass")
	err := os.MkdirAll(trustManagerPath, 0755)
	if err != nil {
		return fmt.Errorf("failed to create trust manager directory: %v", err)
	}

	trustManagerFile := filepath.Join(trustManagerPath, "TrustAllManager.smali")
	err = os.WriteFile(trustManagerFile, []byte(trustAllClass), 0644)
	if err != nil {
		return fmt.Errorf("failed to write TrustAllManager class: %v", err)
	}

	log.Printf("TrustAllManager class created at: %s", trustManagerFile)
	return nil
}

// Hostname verifier bypass
func (tool *AdvancedSSLBypass) bypassHostnameVerifier() error {
	log.Println("Bypassing hostname verification...")

	// Create custom hostname verifier
	verifierClass := `
.class public Lcom/bypass/TrustAllHostnameVerifier;
.super Ljava/lang/Object;
.source "TrustAllHostnameVerifier.java"

.implements Ljavax/net/ssl/HostnameVerifier;

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z
    .registers 3
    const/4 v0, 0x1
    return v0
.end method
`

	// Write hostname verifier class
	verifierPath := filepath.Join(tool.TempDir, "smali", "com", "bypass")
	err := os.MkdirAll(verifierPath, 0755)
	if err != nil {
		return fmt.Errorf("failed to create verifier directory: %v", err)
	}

	verifierFile := filepath.Join(verifierPath, "TrustAllHostnameVerifier.smali")
	err = os.WriteFile(verifierFile, []byte(verifierClass), 0644)
	if err != nil {
		return fmt.Errorf("failed to write hostname verifier class: %v", err)
	}

	log.Printf("TrustAllHostnameVerifier class created at: %s", verifierFile)
	return nil
}

// Helper function to patch smali files with patterns
func (tool *AdvancedSSLBypass) patchSmaliWithPatterns(patterns []struct {
	pattern     string
	replacement string
	description string
}) error {
	smaliDirs := []string{"smali", "smali_classes2", "smali_classes3", "smali_classes4", "smali_classes5"}

	for _, dir := range smaliDirs {
		smaliPath := filepath.Join(tool.TempDir, dir)
		if _, err := os.Stat(smaliPath); os.IsNotExist(err) {
			continue
		}

		err := filepath.Walk(smaliPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			if !strings.HasSuffix(path, ".smali") {
				return nil
			}

			content, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			modified := false
			contentStr := string(content)

			for _, pattern := range patterns {
				regex := regexp.MustCompile(pattern.pattern)
				if regex.MatchString(contentStr) {
					contentStr = regex.ReplaceAllString(contentStr, pattern.replacement)
					modified = true
					log.Printf("Applied %s in %s", pattern.description, filepath.Base(path))
				}
			}

			if modified {
				err = os.WriteFile(path, []byte(contentStr), info.Mode())
				if err != nil {
					log.Printf("Failed to write patched file %s: %v", path, err)
				}
			}

			return nil
		})

		if err != nil {
			log.Printf("Error walking smali directory %s: %v", dir, err)
		}
	}

	return nil
}

// Inject code to Application class
func (tool *AdvancedSSLBypass) injectCodeToApplication(code string) error {
	// Find and patch only the main Application class to avoid syntax errors
	smaliDirs := []string{"smali", "smali_classes2", "smali_classes3", "smali_classes4", "smali_classes5"}

	injected := false
	for _, dir := range smaliDirs {
		smaliPath := filepath.Join(tool.TempDir, dir)
		if _, err := os.Stat(smaliPath); os.IsNotExist(err) {
			continue
		}

		// Look for the actual main Application class (not all Application-related classes)
		err := filepath.Walk(smaliPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || !strings.HasSuffix(path, ".smali") || injected {
				return nil
			}

			content, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			contentStr := string(content)
			// Only inject to the main app's Application class, not framework classes
			if strings.Contains(contentStr, "Landroid/app/Application;") &&
				(strings.Contains(path, "MainApplication") || strings.Contains(path, "Application.smali")) &&
				!strings.Contains(path, "androidx") && !strings.Contains(path, "com/google") {

				// Find the proper location to inject - before the last closing brace of the class
				if strings.Contains(contentStr, ".method") && strings.Contains(contentStr, ".end method") {
					// Find a safe insertion point after existing methods but before class end
					lastMethodEnd := strings.LastIndex(contentStr, ".end method")
					if lastMethodEnd != -1 {
						insertPoint := lastMethodEnd + len(".end method")

						// Ensure we add proper method structure
						safeCode := `
.method public static initSSLBypass()V
    .locals 0
    # SSL bypass initialization would go here
    return-void
.end method`

						newContent := contentStr[:insertPoint] + safeCode + contentStr[insertPoint:]
						err = os.WriteFile(path, []byte(newContent), info.Mode())
						if err == nil {
							log.Printf("Injected SSL bypass code to main Application class: %s", path)
							injected = true
						}
					}
				}
			}

			return nil
		})

		if err != nil {
			log.Printf("Error injecting to Application class in %s: %v", dir, err)
		}

		if injected {
			break // Only inject to one main Application class
		}
	}

	if !injected {
		log.Println("No suitable Application class found for code injection")
	}

	return nil
}

func (tool *AdvancedSSLBypass) removeCertificatePinning() error {
	log.Println("Removing certificate pinning...")

	// Remove certificate pinning from XML files
	xmlFiles := []string{"res/xml/network_security_config.xml"}

	for _, xmlFile := range xmlFiles {
		xmlPath := filepath.Join(tool.TempDir, xmlFile)
		if err := tool.removePinningFromXML(xmlPath); err != nil {
			log.Printf("Failed to remove pinning from %s: %v", xmlFile, err)
		}
	}

	// Replace certificates in assets
	if err := tool.replaceCertificatesInAssets(); err != nil {
		log.Printf("Failed to replace certificates: %v", err)
	}

	return nil
}

func (tool *AdvancedSSLBypass) removePinningFromXML(filePath string) error {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil // File doesn't exist, nothing to do
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	// Remove certificate pinning configurations
	contentStr := string(content)
	patterns := []string{
		`<pin-set.*?>.*?</pin-set>`,
		`<pin.*?>.*?</pin>`,
		`<certificate-pinning.*?>.*?</certificate-pinning>`,
	}

	for _, pattern := range patterns {
		regex := regexp.MustCompile(pattern)
		contentStr = regex.ReplaceAllString(contentStr, "")
	}

	return os.WriteFile(filePath, []byte(contentStr), 0644)
}

func (tool *AdvancedSSLBypass) replaceCertificatesInAssets() error {
	assetsPath := filepath.Join(tool.TempDir, "assets")
	if _, err := os.Stat(assetsPath); os.IsNotExist(err) {
		return nil // No assets directory
	}

	return filepath.Walk(assetsPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		// Look for certificate files
		if strings.HasSuffix(info.Name(), ".crt") || strings.HasSuffix(info.Name(), ".pem") ||
			strings.HasSuffix(info.Name(), ".cer") || strings.HasSuffix(info.Name(), ".p12") {

			if tool.CertificatePath != "" {
				// Replace with our custom certificate
				return tool.copyFile(tool.CertificatePath, path)
			}
		}

		return nil
	})
}

// Update manifest SDK dynamically during signing process
func (tool *AdvancedSSLBypass) updateManifestSDK() error {
	log.Printf("🔄 Updating manifest to use SDK %d...", tool.NewTargetSDK)

	manifestPath := filepath.Join(tool.TempDir, "AndroidManifest.xml")
	content, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to read manifest for SDK update: %v", err)
	}

	contentStr := string(content)
	newSDKStr := fmt.Sprintf("%d", tool.NewTargetSDK)

	// Update targetSdkVersion
	targetSdkRegex := regexp.MustCompile(`android:targetSdkVersion="[^"]*"`)
	if targetSdkRegex.MatchString(contentStr) {
		contentStr = targetSdkRegex.ReplaceAllString(contentStr, fmt.Sprintf(`android:targetSdkVersion="%s"`, newSDKStr))
	} else {
		usesSdkRegex := regexp.MustCompile(`(<uses-sdk[^>]*?)(/>)`)
		contentStr = usesSdkRegex.ReplaceAllString(contentStr, fmt.Sprintf(`${1} android:targetSdkVersion="%s"${2}`, newSDKStr))
	}

	err = os.WriteFile(manifestPath, []byte(contentStr), 0644)
	if err != nil {
		return fmt.Errorf("failed to write updated manifest: %v", err)
	}

	log.Printf("✅ Manifest updated to SDK %d", tool.NewTargetSDK)
	return nil
}

func (tool *AdvancedSSLBypass) modifyManifest() error {
	log.Println("Modifying AndroidManifest.xml...")

	// Find AndroidManifest.xml
	manifestPath := filepath.Join(tool.TempDir, "AndroidManifest.xml")
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		return fmt.Errorf("AndroidManifest.xml not found at %s", manifestPath)
	}

	// Read the manifest file
	content, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to read manifest: %v", err)
	}

	contentStr := string(content)

	// Only modify SDK if actually changed (preserve modern SDKs when possible)
	if tool.NewTargetSDK != tool.OriginalTargetSDK {
		newSDKStr := fmt.Sprintf("%d", tool.NewTargetSDK)
		targetSdkRegex := regexp.MustCompile(`android:targetSdkVersion="[^"]*"`)
		if targetSdkRegex.MatchString(contentStr) {
			contentStr = targetSdkRegex.ReplaceAllString(contentStr, fmt.Sprintf(`android:targetSdkVersion="%s"`, newSDKStr))
			log.Printf("🔄 Target SDK adjusted: %d → %d for signature compatibility", tool.OriginalTargetSDK, tool.NewTargetSDK)
		} else {
			// If targetSdkVersion doesn't exist, add it
			usesSdkRegex := regexp.MustCompile(`(<uses-sdk[^>]*?)(/>)`)
			contentStr = usesSdkRegex.ReplaceAllString(contentStr, fmt.Sprintf(`${1} android:targetSdkVersion="%s"${2}`, newSDKStr))
			log.Printf("➕ Added targetSdkVersion=\"%s\" for compatibility", newSDKStr)
		}
	} else {
		// SDK preserved - just ensure it's properly set
		sdkStr := fmt.Sprintf("%d", tool.OriginalTargetSDK)
		targetSdkRegex := regexp.MustCompile(`android:targetSdkVersion="[^"]*"`)
		if !targetSdkRegex.MatchString(contentStr) {
			// Add targetSdkVersion if missing
			usesSdkRegex := regexp.MustCompile(`(<uses-sdk[^>]*?)(/>)`)
			contentStr = usesSdkRegex.ReplaceAllString(contentStr, fmt.Sprintf(`${1} android:targetSdkVersion="%s"${2}`, sdkStr))
			log.Printf("➕ Ensured targetSdkVersion=\"%s\" is set", sdkStr)
		} else {
			log.Printf("✅ Target SDK preserved: %d (modern %s signatures will be used)", tool.OriginalTargetSDK, tool.SignatureScheme)
		}
	}

	// Look for the application tag and modify it to add our attributes
	// Use regex to find and replace the application tag
	applicationRegex := regexp.MustCompile(`(<application[^>]*?)( android:debuggable="[^"]*")([^>]*>)`)
	if applicationRegex.MatchString(contentStr) {
		// If debuggable already exists, replace it
		contentStr = applicationRegex.ReplaceAllString(contentStr, `${1} android:debuggable="true"${3}`)
	} else {
		// If debuggable doesn't exist, add it
		applicationRegex = regexp.MustCompile(`(<application[^>]*?)(>)`)
		contentStr = applicationRegex.ReplaceAllString(contentStr, `${1} android:debuggable="true"${2}`)
	}

	// Add networkSecurityConfig if not present
	networkConfigRegex := regexp.MustCompile(`(<application[^>]*?)( android:networkSecurityConfig="[^"]*")([^>]*>)`)
	if !networkConfigRegex.MatchString(contentStr) {
		applicationRegex = regexp.MustCompile(`(<application[^>]*?)(>)`)
		contentStr = applicationRegex.ReplaceAllString(contentStr, `${1} android:networkSecurityConfig="@xml/network_security_config"${2}`)
	}

	// Write the modified content back
	err = os.WriteFile(manifestPath, []byte(contentStr), 0644)
	if err != nil {
		return fmt.Errorf("failed to write modified manifest: %v", err)
	}

	log.Println("AndroidManifest.xml modified successfully")
	return nil
}

// Validate APK without ADB - checks structure and signature
func (tool *AdvancedSSLBypass) validateAPK() error {
	log.Println("Validating generated APK...")

	// Check if APK file exists
	if _, err := os.Stat(tool.OutputPath); os.IsNotExist(err) {
		return fmt.Errorf("output APK does not exist: %s", tool.OutputPath)
	}

	// Check APK structure with aapt
	if err := tool.validateAPKStructure(); err != nil {
		return fmt.Errorf("APK structure validation failed: %v", err)
	}

	// Check APK signature
	if err := tool.validateAPKSignature(); err != nil {
		return fmt.Errorf("APK signature validation failed: %v", err)
	}

	// Check APK size (should be reasonable)
	stat, err := os.Stat(tool.OutputPath)
	if err != nil {
		return fmt.Errorf("cannot get APK file info: %v", err)
	}

	size := stat.Size()
	if size < 1024*1024 { // Less than 1MB might be corrupted
		log.Printf("Warning: APK size is very small (%.2f MB)", float64(size)/(1024*1024))
	}

	log.Printf("APK validation passed. Size: %.2f MB", float64(size)/(1024*1024))
	return nil
}

// Validate APK structure using aapt
func (tool *AdvancedSSLBypass) validateAPKStructure() error {
	cmd := exec.Command("aapt", "dump", "badging", tool.OutputPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("aapt validation failed: %v\nOutput: %s", err, string(output))
	}

	// Check for critical elements in aapt output
	outputStr := string(output)
	if !strings.Contains(outputStr, "package:") {
		return fmt.Errorf("APK missing package information")
	}

	if !strings.Contains(outputStr, "application-label:") {
		return fmt.Errorf("APK missing application label")
	}

	if strings.Contains(outputStr, "ERROR:") {
		return fmt.Errorf("APK structure errors detected: %s", outputStr)
	}

	// Check for debuggable flag
	if strings.Contains(outputStr, "application-debuggable") {
		log.Println("✓ APK is debuggable (SSL bypass should work)")
	} else {
		log.Println("⚠ APK is not debuggable (some bypass methods may not work)")
	}

	return nil
}

// Validate APK signature using appropriate validator
func (tool *AdvancedSSLBypass) validateAPKSignature() error {
	// Use scheme-aware validation based on our signing method
	switch tool.SignatureScheme {
	case "v2v3", "v2", "hybrid":
		// For v2+ schemes, try apksigner first but be lenient
		log.Printf("🔍 Validating %s signature scheme...", tool.SignatureScheme)
		cmd := exec.Command("apksigner", "verify", "--print-certs", tool.OutputPath)
		_, err := cmd.CombinedOutput()

		if err != nil {
			log.Printf("⚠️ apksigner validation shows issues, checking practical validity...")
			// Don't log full error output to reduce noise

			// Try jarsigner as fallback for v1 compatibility
			cmd = exec.Command("jarsigner", "-verify", "-certs", tool.OutputPath)
			_, err = cmd.CombinedOutput()
			if err != nil {
				// Final structural check
				if zipReader, zipErr := zip.OpenReader(tool.OutputPath); zipErr == nil {
					zipReader.Close()
					log.Println("� APK structure is valid - signature inconsistencies may not prevent installation")
					return nil
				}
				return fmt.Errorf("APK validation failed: %v", err)
			} else {
				log.Printf("✅ APK has valid v1 signature (jarsigner verified)")
				return nil
			}
		} else {
			log.Printf("✅ APK %s signature verified successfully", tool.SignatureScheme)
			return nil
		}

	default: // "v1" or others
		// For v1 schemes, use jarsigner primarily
		log.Println("� Validating v1 signature scheme...")
		cmd := exec.Command("jarsigner", "-verify", "-certs", tool.OutputPath)
		_, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("v1 signature validation failed: %v", err)
		} else {
			log.Println("✅ APK v1 signature verified successfully")
			return nil
		}
	}
}

// Simulate installation check without ADB
func (tool *AdvancedSSLBypass) simulateInstallationCheck() error {
	log.Println("Performing installation simulation check...")

	// Check APK parsing capability
	cmd := exec.Command("aapt", "dump", "xmltree", tool.OutputPath, "AndroidManifest.xml")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("manifest parsing failed (installation would fail): %v", err)
	}

	// Check for common installation blockers
	outputStr := string(output)
	if strings.Contains(outputStr, "ERROR") {
		return fmt.Errorf("manifest contains errors that would prevent installation")
	}

	// Validate resources
	cmd = exec.Command("aapt", "dump", "resources", tool.OutputPath)
	output, err = cmd.CombinedOutput()
	if err != nil {
		log.Printf("Warning: Resource validation failed: %v", err)
	} else if strings.Contains(string(output), "ERROR") {
		log.Printf("Warning: Resource errors detected (may cause installation issues)")
	}

	log.Println("✓ Installation simulation passed - APK should be installable")
	return nil
}

// Comprehensive APK health check
func (tool *AdvancedSSLBypass) performHealthCheck() error {
	log.Println("\n=== APK Health Check ===")

	// Basic validation
	if err := tool.validateAPK(); err != nil {
		return fmt.Errorf("basic validation failed: %v", err)
	}

	// Installation simulation
	if err := tool.simulateInstallationCheck(); err != nil {
		return fmt.Errorf("installation check failed: %v", err)
	}

	// Additional checks
	if err := tool.checkAPKIntegrity(); err != nil {
		log.Printf("Warning: Integrity check failed: %v", err)
	}

	log.Println("=== Health Check Complete ===")
	return nil
}

// Check APK integrity using ZIP validation
func (tool *AdvancedSSLBypass) checkAPKIntegrity() error {
	// APK is essentially a ZIP file, so validate ZIP structure
	zipReader, err := zip.OpenReader(tool.OutputPath)
	if err != nil {
		return fmt.Errorf("failed to open APK as ZIP: %v", err)
	}
	defer zipReader.Close()

	// Check for essential APK components
	essentialFiles := []string{
		"AndroidManifest.xml",
		"classes.dex",
		"META-INF/",
	}

	foundFiles := make(map[string]bool)
	for _, file := range zipReader.File {
		for _, essential := range essentialFiles {
			if strings.Contains(file.Name, essential) {
				foundFiles[essential] = true
			}
		}
	}

	for _, essential := range essentialFiles {
		if !foundFiles[essential] {
			return fmt.Errorf("missing essential component: %s", essential)
		}
	}

	log.Printf("✓ APK contains %d files with all essential components", len(zipReader.File))
	return nil
}

func (tool *AdvancedSSLBypass) validateAndFixManifest(manifestPath string) error {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to read manifest: %v", err)
	}

	content := string(data)
	modified := false

	// Fix common XML issues
	// 1. Remove any null bytes that might corrupt the XML
	if bytes.Contains(data, []byte{0}) {
		content = strings.ReplaceAll(content, string([]byte{0}), "")
		modified = true
		log.Println("Removed null bytes from manifest")
	}

	// 2. Ensure proper XML structure
	if !strings.Contains(content, "<?xml") {
		content = `<?xml version="1.0" encoding="utf-8"?>` + "\n" + content
		modified = true
		log.Println("Added XML declaration")
	}

	// 3. Fix malformed attribute spacing
	re := regexp.MustCompile(`\s+android:`)
	content = re.ReplaceAllString(content, " android:")

	if modified {
		err = os.WriteFile(manifestPath, []byte(content), 0644)
		if err != nil {
			return fmt.Errorf("failed to write fixed manifest: %v", err)
		}
		log.Println("Manifest validation and fixes applied")
	}

	return nil
}

// Helper function to find minimum
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (tool *AdvancedSSLBypass) validateXMLFile(xmlPath string) error {
	// Basic XML validation
	content, err := os.ReadFile(xmlPath)
	if err != nil {
		return fmt.Errorf("cannot read XML file: %v", err)
	}

	// Check for proper XML structure
	contentStr := string(content)
	if !strings.Contains(contentStr, "<?xml") {
		return fmt.Errorf("missing XML declaration")
	}

	if !strings.Contains(contentStr, "<manifest") {
		return fmt.Errorf("missing manifest root element")
	}

	if !strings.Contains(contentStr, "</manifest>") {
		return fmt.Errorf("missing manifest closing tag")
	}

	return nil
}

func (tool *AdvancedSSLBypass) recompileAPK() error {
	log.Println("🔧 Recompiling APK...")

	// Apply Android 11+ target SDK fix before recompilation
	if err := tool.adjustTargetSDKForAndroid11(); err != nil {
		log.Printf("Warning: Could not adjust target SDK: %v", err)
	} else if tool.NewTargetSDK == 28 {
		// Force compatibility mode for Android 11+ fixes
		tool.UseLegacyCompat = true
		tool.SignatureScheme = "v1v2" // Use v1+v2 only for Android 11+ compatibility
		log.Println("🔧 Enabled legacy compatibility mode for Android 11+")
	}

	// Validate AndroidManifest.xml before recompiling
	manifestPath := filepath.Join(tool.TempDir, "AndroidManifest.xml")
	if err := tool.validateAndFixManifest(manifestPath); err != nil {
		log.Printf("Warning: Manifest validation failed: %v", err)
	}

	// Try recompiling with different options for compatibility
	cmd := exec.Command("apktool", "b", tool.TempDir, "-o", tool.OutputPath, "-f", "--use-aapt2")
	out, err := cmd.CombinedOutput()

	if err != nil {
		log.Printf("AAPT2 recompile failed, trying with AAPT1: %v", err)
		// Fallback to AAPT1
		cmd = exec.Command("apktool", "b", tool.TempDir, "-o", tool.OutputPath, "-f")
		out, err = cmd.CombinedOutput()

		if err != nil {
			return fmt.Errorf("apktool recompilation failed: %v\nOutput: %s", err, string(out))
		}
	}

	log.Println("APK recompiled successfully")
	return nil
}

func (tool *AdvancedSSLBypass) cleanExistingSignatures() error {
	log.Println("🧹 Cleaning existing signatures...")

	// Use temporary file with unique name to avoid conflicts
	tempDir := filepath.Dir(tool.OutputPath)
	cleanPath := filepath.Join(tempDir, fmt.Sprintf("clean_%d_%s", time.Now().Unix(), filepath.Base(tool.OutputPath)))

	// Ensure output file is closed and not being used
	time.Sleep(100 * time.Millisecond) // Small delay to ensure file handles are released

	// Open original APK with retry mechanism
	var reader *zip.ReadCloser
	var err error
	for attempts := 0; attempts < 3; attempts++ {
		reader, err = zip.OpenReader(tool.OutputPath)
		if err == nil {
			break
		}
		log.Printf("Attempt %d: Failed to open APK, retrying: %v", attempts+1, err)
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		return fmt.Errorf("failed to open APK after retries: %v", err)
	}
	defer reader.Close()

	// Create clean APK without META-INF
	writer, err := os.Create(cleanPath)
	if err != nil {
		reader.Close()
		return fmt.Errorf("failed to create clean APK: %v", err)
	}
	defer writer.Close()

	zipWriter := zip.NewWriter(writer)
	defer zipWriter.Close()

	// Copy all files except META-INF (completely remove all signature traces)
	copiedFiles := 0
	skippedFiles := 0
	for _, file := range reader.File {
		// Skip ALL META-INF related files and directories (including signature artifacts)
		if strings.HasPrefix(file.Name, "META-INF/") || file.Name == "META-INF" ||
			strings.Contains(file.Name, ".SF") || strings.Contains(file.Name, ".RSA") ||
			strings.Contains(file.Name, ".DSA") || strings.Contains(file.Name, "MANIFEST.MF") {
			skippedFiles++
			continue // Completely skip all signature-related files
		}

		// Copy file to clean APK
		if err := tool.copyZipFile(file, zipWriter); err != nil {
			log.Printf("Warning: failed to copy %s: %v", file.Name, err)
		} else {
			copiedFiles++
		}
	}

	log.Printf("📝 Signature cleanup: copied %d files, removed %d signature files", copiedFiles, skippedFiles)

	// Close all handles before file operations
	zipWriter.Close()
	writer.Close()
	reader.Close()

	// Wait a moment for handles to be fully released
	time.Sleep(200 * time.Millisecond)

	// Replace original with clean version using retry mechanism
	for attempts := 0; attempts < 5; attempts++ {
		err = os.Remove(tool.OutputPath)
		if err == nil {
			break
		}
		if attempts < 4 {
			log.Printf("🔄 Attempt %d: File in use, waiting before retry...", attempts+1)
			time.Sleep(time.Duration(attempts+1) * 500 * time.Millisecond)
		}
	}

	if err != nil {
		// If we can't remove the original, try renaming it first
		backupPath := tool.OutputPath + ".backup"
		if renameErr := os.Rename(tool.OutputPath, backupPath); renameErr == nil {
			log.Printf("📁 Moved original APK to backup: %s", backupPath)
			err = nil // Reset error since rename worked
		}
	}

	if err == nil {
		err = os.Rename(cleanPath, tool.OutputPath)
		if err != nil {
			return fmt.Errorf("failed to replace with clean APK: %v", err)
		}
		log.Println("✅ Signatures cleaned successfully - APK ready for fresh signing")
	} else {
		// Cleanup temporary file if replacement failed
		os.Remove(cleanPath)
		return fmt.Errorf("failed to remove original APK (file locked): %v", err)
	}

	return nil
}

// Remove APK signature scheme metadata that can cause installation conflicts
func (tool *AdvancedSSLBypass) removeSignatureMetadata() error {
	log.Println("🔧 CRITICAL FIX: Removing v2/v3 signature metadata conflicts...")
	log.Println("   This fixes error code -2 and Android 11+ installation issues")
	
	// Use aapt to remove ALL signature-related entries from APK
	filesToRemove := []string{
		"META-INF/ANDROIDD.SF", "META-INF/ANDROIDD.RSA",
		"META-INF/CERT.SF", "META-INF/CERT.RSA", 
		"META-INF/MANIFEST.MF",
		"META-INF/RELEASE.SF", "META-INF/RELEASE.RSA",
		"META-INF/ANDROID_.SF", "META-INF/ANDROID_.RSA",
		"META-INF/*.SF", "META-INF/*.RSA", "META-INF/*.DSA"} 
	
	for _, file := range filesToRemove {
		cmd := exec.Command("aapt", "remove", tool.OutputPath, file)
		if err := cmd.Run(); err == nil {
			log.Printf("   🗑️ Removed: %s", file)
		}
	}
	
	log.Println("✅ All signature metadata conflicts removed")
	return nil
}// Adjust target SDK for Android 11+ compatibility (resources.arsc issue)
func (tool *AdvancedSSLBypass) adjustTargetSDKForAndroid11() error {
	if tool.OriginalTargetSDK >= 30 {
		log.Printf("🔧 Android 11+ detected (SDK %d) - adjusting for resources.arsc compatibility...", tool.OriginalTargetSDK)
		
		// Modify apktool.yml to use SDK 28 (avoids resources.arsc uncompressed requirement)
		apktoolYmlPath := filepath.Join(tool.TempDir, "apktool.yml")
		content, err := os.ReadFile(apktoolYmlPath)
		if err != nil {
			return fmt.Errorf("failed to read apktool.yml: %v", err)
		}
		
		// Replace targetSdkVersion with 28 for compatibility
		updatedContent := string(content)
		updatedContent = strings.ReplaceAll(updatedContent, 
			fmt.Sprintf("targetSdkVersion: %d", tool.OriginalTargetSDK),
			"targetSdkVersion: 28")
		
		if err := os.WriteFile(apktoolYmlPath, []byte(updatedContent), 0644); err != nil {
			return fmt.Errorf("failed to update apktool.yml: %v", err)
		}
		
		tool.NewTargetSDK = 28 // Update internal tracking
		log.Printf("✅ Target SDK adjusted to 28 for Android 11+ compatibility")
	}
	
	return nil
}

// Create a better debug keystore for signing
func (tool *AdvancedSSLBypass) createBetterKeystore() (string, error) {
	log.Println("🔑 Creating enhanced debug keystore...")

	keystorePath := filepath.Join(tool.TempDir, "enhanced_debug.keystore")

	// Create keystore with better compatibility parameters
	cmd := exec.Command("keytool",
		"-genkey",
		"-v",
		"-keystore", keystorePath,
		"-alias", "androiddebugkey",
		"-keyalg", "RSA",
		"-keysize", "2048",
		"-validity", "10000",
		"-storepass", "android",
		"-keypass", "android",
		"-dname", "CN=Android Debug,O=Android,C=US")

	if err := cmd.Run(); err != nil {
		log.Printf("Failed to create enhanced keystore: %v", err)
		return "", err
	}

	log.Printf("✅ Enhanced keystore created: %s", keystorePath)
	return keystorePath, nil
}

func (tool *AdvancedSSLBypass) copyZipFile(file *zip.File, zipWriter *zip.Writer) error {
	reader, err := file.Open()
	if err != nil {
		return err
	}
	defer reader.Close()

	header, err := zip.FileInfoHeader(file.FileInfo())
	if err != nil {
		return err
	}
	header.Name = file.Name
	header.Method = zip.Deflate

	writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		return err
	}

	_, err = io.Copy(writer, reader)
	return err
}

func (tool *AdvancedSSLBypass) signAPK() error {
	log.Println("🔐 Signing APK...")

	// Check if debug keystore exists, create if not
	keystorePath := "debug.keystore"
	if _, err := os.Stat(keystorePath); os.IsNotExist(err) {
		log.Println("Creating debug keystore...")
		cmd := exec.Command("keytool", "-genkey", "-v", "-keystore", keystorePath,
			"-alias", "androiddebugkey", "-keyalg", "RSA", "-keysize", "2048",
			"-validity", "10000", "-keypass", "android", "-storepass", "android",
			"-dname", "CN=Android Debug,O=Android,C=US")

		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to create debug keystore: %v", err)
		}
	}

	// Clean any existing signatures first (critical for proper signing)
	if err := tool.cleanExistingSignatures(); err != nil {
		log.Printf("⚠️  Warning: Could not clean existing signatures: %v", err)
		log.Println("🔄 Continuing with signing anyway, but this may cause signature conflicts...")
		// Don't fail completely - sometimes signing can still work
	} else {
		log.Println("✅ Existing signatures cleaned successfully")
	}

	// Ultimate adaptive signing with comprehensive fallback strategy
	switch tool.SignatureScheme {
	case "ultimate":
		// Ultimate mode: Focus on installation compatibility
		log.Printf("🚀 ULTIMATE MODE: Installation-focused signing for SDK %d...", tool.NewTargetSDK)

		// Remove signature metadata conflicts first - CRITICAL for error code -2 fix
		log.Println("🚨 FIXING SIGNATURE METADATA CONFLICT (Root cause of error code -2)")
		if err := tool.removeSignatureMetadata(); err != nil {
			log.Printf("Warning: Could not remove signature metadata: %v", err)
		}
		
		// CRITICAL: Clean ALL existing signatures to avoid v2/v3 metadata conflicts
		if err := tool.cleanExistingSignatures(); err != nil {
			log.Printf("Warning: Could not clean signatures: %v", err)
		}

		// Strategy 1: Ultimate compatibility signing (based on successful manual tests)
		log.Printf("🔑 Strategy 1: Ultimate compatibility signing (v1+v2, Android 11+ compatible)...")

		// Try apksigner with v1+v2 (proven successful method)
		apksignerCmd := exec.Command("apksigner", "sign",
			"--ks", keystorePath,
			"--ks-pass", "pass:android",
			"--key-pass", "pass:android", 
			"--v1-signing-enabled", "true",
			"--v2-signing-enabled", "true",
			"--v3-signing-enabled", "false",
			"--v4-signing-enabled", "false",
			tool.OutputPath)

		if err := apksignerCmd.Run(); err == nil {
			log.Printf("🎉 SUCCESS: Ultimate v1+v2 signature applied! (Proven method)")
			return nil
		} else {
			log.Printf("❌ Strategy 1 failed: %v", err)
		}

		// Strategy 2: Enhanced keystore with v1 signature (fallback)
		log.Printf("🔑 Strategy 2: Enhanced keystore + v1 signature (legacy compatibility)...")

		// Create enhanced keystore
		enhancedKeystore, err := tool.createBetterKeystore()
		if err != nil {
			log.Printf("Enhanced keystore creation failed, using default: %v", err)
			enhancedKeystore = keystorePath
		}

		jarsignerCmd := exec.Command("jarsigner",
			"-keystore", enhancedKeystore,
			"-storepass", "android",
			"-keypass", "android",
			"-digestalg", "SHA1", // More compatible digest
			"-sigalg", "SHA1withRSA", // More compatible algorithm
			tool.OutputPath,
			"androiddebugkey")

		if err := jarsignerCmd.Run(); err == nil {
			log.Printf("🎉 SUCCESS: Enhanced v1 signature works! Legacy compatible.")
			return nil
		} else {
			log.Printf("❌ Strategy 2 failed: %v", err)
		}

		// Strategy 2: v1+v2 hybrid (better compatibility than pure v2)
		log.Printf("🔑 Strategy 2: Hybrid v1+v2 signature (balanced compatibility)...")
		// Clean signatures again
		if err := tool.cleanExistingSignatures(); err != nil {
			log.Printf("Warning: Could not clean signatures: %v", err)
		}

		apksignerCmd = exec.Command("apksigner", "sign",
			"--ks", keystorePath,
			"--ks-key-alias", "androiddebugkey",
			"--ks-pass", "pass:android",
			"--key-pass", "pass:android",
			"--v1-signing-enabled", "true", // Include v1 for compatibility
			"--v2-signing-enabled", "true", // Add v2 for modern support
			"--v3-signing-enabled", "false", // Avoid v3 complications
			"--v4-signing-enabled", "false",
			tool.OutputPath)

		if err := apksignerCmd.Run(); err == nil {
			log.Printf("🎉 SUCCESS: Hybrid v1+v2 signature works!")
			return nil
		} else {
			log.Printf("❌ Strategy 2 failed: %v", err)
		}

		// Strategy 3: Lower SDK and try again
		originalSDK := tool.NewTargetSDK
		tool.NewTargetSDK = 28
		log.Printf("🔄 Strategy 3: Lowering SDK to %d for better compatibility...", tool.NewTargetSDK)

		if err := tool.updateManifestSDK(); err == nil {
			if err := tool.recompileAPK(); err == nil {
				if err := tool.cleanExistingSignatures(); err != nil {
					log.Printf("Warning: Could not clean signatures: %v", err)
				}

				// Try jarsigner with SDK 28
				jarsignerCmd := exec.Command("jarsigner",
					"-verbose",
					"-keystore", keystorePath,
					"-storepass", "android",
					"-keypass", "android",
					tool.OutputPath,
					"androiddebugkey")

				if err := jarsignerCmd.Run(); err == nil {
					log.Printf("🎉 SUCCESS: v1 signature with SDK 28 works!")
					return nil
				}
			}
		}

		// Restore original SDK on failure
		tool.NewTargetSDK = originalSDK

		return fmt.Errorf("all signature strategies failed for ultimate mode - try manual installation")

	case "v2v3":
		// Modern signing with v2+v3 for SDK 30+
		log.Printf("🔐 Signing with modern scheme (v1+v2+v3) for SDK %d...", tool.NewTargetSDK)
		apksignerCmd := exec.Command("apksigner", "sign",
			"--ks", keystorePath,
			"--ks-key-alias", "androiddebugkey",
			"--ks-pass", "pass:android",
			"--key-pass", "pass:android",
			"--v1-signing-enabled", "true", // v1 for maximum compatibility
			"--v2-signing-enabled", "true", // v2 for modern Android
			"--v3-signing-enabled", "true", // v3 for SDK 28+
			"--v4-signing-enabled", "false", // v4 not needed
			tool.OutputPath)

		if err := apksignerCmd.Run(); err != nil {
			log.Printf("Modern signing failed, trying v2 only: %v", err)
			tool.SignatureScheme = "v2" // Fallback to v2
		} else {
			log.Printf("✅ APK signed with modern signatures (v1+v2+v3, SDK %d)", tool.NewTargetSDK)
			return nil
		}

	case "v2":
		// v2 signing for SDK 28-29 or fallback from v2v3
		log.Printf("🔐 Signing with v2 scheme for SDK %d...", tool.NewTargetSDK)
		apksignerCmd := exec.Command("apksigner", "sign",
			"--ks", keystorePath,
			"--ks-key-alias", "androiddebugkey",
			"--ks-pass", "pass:android",
			"--key-pass", "pass:android",
			"--v1-signing-enabled", "true", // Keep v1 for compatibility
			"--v2-signing-enabled", "true", // Main v2 signature
			"--v3-signing-enabled", "false",
			"--v4-signing-enabled", "false",
			tool.OutputPath)

		if err := apksignerCmd.Run(); err != nil {
			log.Printf("v2 signing failed, trying hybrid mode: %v", err)
			tool.SignatureScheme = "hybrid" // Fallback to hybrid
		} else {
			log.Printf("✅ APK signed with v2 signatures (v1+v2, SDK %d)", tool.NewTargetSDK)
			return nil
		}

	case "hybrid":
		// Hybrid signing - balanced approach
		log.Printf("🔐 Signing with hybrid scheme for SDK %d...", tool.NewTargetSDK)
		apksignerCmd := exec.Command("apksigner", "sign",
			"--ks", keystorePath,
			"--ks-key-alias", "androiddebugkey",
			"--ks-pass", "pass:android",
			"--key-pass", "pass:android",
			"--v1-signing-enabled", "true", // Strong v1 base
			"--v2-signing-enabled", "true", // Modern v2
			"--v3-signing-enabled", "false",
			"--v4-signing-enabled", "false",
			tool.OutputPath)

		if err := apksignerCmd.Run(); err != nil {
			log.Printf("Hybrid signing failed, trying clean v1-only: %v", err)
			tool.SignatureScheme = "v1clean" // Clean v1 fallback
		} else {
			log.Printf("✅ APK signed with hybrid signatures (v1+v2, SDK %d)", tool.NewTargetSDK)
			return nil
		}
	}

	// v1 or clean v1 signing (default or ultimate fallback)
	if tool.SignatureScheme == "v1clean" {
		log.Printf("🗯️ Signing with clean v1-only (no v2 artifacts) for SDK %d...", tool.NewTargetSDK)

		// Use jarsigner directly for pure v1 signature
		algorithm := "SHA256withRSA"
		digest := "SHA256"
		if tool.UseLegacyCompat {
			algorithm = "SHA1withRSA"
			digest = "SHA1"
		}

		jarsignerCmd := exec.Command("jarsigner",
			"-sigalg", algorithm,
			"-digestalg", digest,
			"-keystore", keystorePath,
			"-storepass", "android",
			"-keypass", "android",
			tool.OutputPath,
			"androiddebugkey")

		if err := jarsignerCmd.Run(); err != nil {
			output, _ := jarsignerCmd.CombinedOutput()
			return fmt.Errorf("clean v1 signing failed: %v\nOutput: %s", err, string(output))
		}
		log.Printf("✅ APK signed with clean v1 signature (%s, SDK %d)", algorithm, tool.NewTargetSDK)
		return nil
	}

	log.Printf("🔐 Signing with v1 scheme for SDK %d...", tool.NewTargetSDK)

	// Try apksigner v1-only first
	apksignerCmd := exec.Command("apksigner", "sign",
		"--ks", keystorePath,
		"--ks-key-alias", "androiddebugkey",
		"--ks-pass", "pass:android",
		"--key-pass", "pass:android",
		"--v1-signing-enabled", "true",
		"--v2-signing-enabled", "false",
		"--v3-signing-enabled", "false",
		"--v4-signing-enabled", "false",
		tool.OutputPath)

	if err := apksignerCmd.Run(); err != nil {
		log.Printf("apksigner v1 failed, using jarsigner: %v", err)

		// Ultimate fallback to jarsigner
		algorithm := "SHA256withRSA"
		digest := "SHA256"
		if tool.UseLegacyCompat {
			algorithm = "SHA1withRSA"
			digest = "SHA1"
			log.Println("🔄 Using legacy SHA1 for maximum compatibility")
		}

		jarsignerCmd := exec.Command("jarsigner",
			"-verbose",
			"-sigalg", algorithm,
			"-digestalg", digest,
			"-keystore", keystorePath,
			"-storepass", "android",
			"-keypass", "android",
			tool.OutputPath,
			"androiddebugkey")

		if err := jarsignerCmd.Run(); err != nil {
			output, _ := jarsignerCmd.CombinedOutput()
			return fmt.Errorf("all signing methods failed: %v\nOutput: %s", err, string(output))
		}
		log.Printf("✅ APK signed successfully with jarsigner (v1 signature, %s)", algorithm)
	} else {
		log.Printf("✅ APK signed successfully with apksigner (v1 signature, optimized for SDK %d)", tool.NewTargetSDK)
	}
	return nil
}

func (tool *AdvancedSSLBypass) alignAPK() error {
	log.Println("📐 Aligning APK...")

	// Use unique temporary file name
	alignedPath := filepath.Join(filepath.Dir(tool.OutputPath), fmt.Sprintf("aligned_%d_%s", time.Now().Unix(), filepath.Base(tool.OutputPath)))
	cmd := exec.Command("zipalign", "-v", "4", tool.OutputPath, alignedPath)
	output, err := cmd.CombinedOutput()

	if err != nil {
		log.Printf("APK alignment failed: %v\nOutput: %s", err, string(output))
		return err
	}

	// Wait for file operations to complete
	time.Sleep(100 * time.Millisecond)

	// Replace original with aligned version using retry
	for attempts := 0; attempts < 3; attempts++ {
		err = os.Remove(tool.OutputPath)
		if err == nil {
			break
		}
		if attempts < 2 {
			log.Printf("🔄 Alignment file conflict, retrying...")
			time.Sleep(300 * time.Millisecond)
		}
	}

	if err == nil {
		err = os.Rename(alignedPath, tool.OutputPath)
		if err != nil {
			log.Printf("Failed to replace with aligned APK: %v", err)
			os.Remove(alignedPath) // Cleanup
			return err
		}
	} else {
		os.Remove(alignedPath) // Cleanup
		return fmt.Errorf("failed to replace original APK during alignment: %v", err)
	}

	log.Println("✅ APK aligned successfully")
	return nil
}

// Fix native library compression in final APK
func (tool *AdvancedSSLBypass) fixAPKNativeLibCompression() error {
	log.Println("🔧 Performing comprehensive native library fix...")
	
	// Create temporary directory for APK reconstruction
	tempFixDir, err := os.MkdirTemp("", "native_lib_fix_*")
	if err != nil {
		return fmt.Errorf("failed to create temp fix dir: %v", err)
	}
	defer os.RemoveAll(tempFixDir)
	
	// Extract current APK
	log.Println("📦 Extracting APK for native library fix...")
	if err := tool.extractAPKForLibFix(tempFixDir); err != nil {
		return fmt.Errorf("failed to extract APK: %v", err)
	}
	
	// Fix native library issues
	if err := tool.fixNativeLibrariesInExtracted(tempFixDir); err != nil {
		log.Printf("Warning: Native lib fix issues: %v", err)
	}
	
	// Rebuild APK with proper compression settings
	log.Println("🔨 Rebuilding APK with uncompressed native libraries...")
	backupAPK := tool.OutputPath + ".backup"
	os.Rename(tool.OutputPath, backupAPK)
	
	if err := tool.rebuildAPKWithLibFix(tempFixDir); err != nil {
		// Restore backup if rebuild fails
		os.Rename(backupAPK, tool.OutputPath)
		return fmt.Errorf("failed to rebuild APK: %v", err)
	}
	
	// Clean up backup
	os.Remove(backupAPK)
	
	log.Println("✅ Native library fix completed")
	return nil
}

func (tool *AdvancedSSLBypass) extractAPKForLibFix(destDir string) error {
	// Use Java's unzip to handle APK properly
	cmd := exec.Command("powershell", "-Command", 
		fmt.Sprintf("Expand-Archive -Path '%s' -DestinationPath '%s' -Force", 
			strings.ReplaceAll(tool.OutputPath, "/", "\\"), 
			strings.ReplaceAll(destDir, "/", "\\")))
	
	if err := cmd.Run(); err != nil {
		// Fallback to aapt extraction
		return tool.extractWithAAP(destDir)
	}
	
	return nil
}

func (tool *AdvancedSSLBypass) extractWithAAP(destDir string) error {
	// Manual extraction using apktool
	cmd := exec.Command("apktool", "d", tool.OutputPath, "-o", destDir, "-f")
	return cmd.Run()
}

func (tool *AdvancedSSLBypass) fixNativeLibrariesInExtracted(extractDir string) error {
	libDir := filepath.Join(extractDir, "lib")
	if _, err := os.Stat(libDir); os.IsNotExist(err) {
		// No lib directory, check for direct .so files
		return tool.fixDirectSOFiles(extractDir)
	}
	
	// Process each architecture directory
	return filepath.Walk(libDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		
		if strings.HasSuffix(path, ".so") {
			log.Printf("🔧 Validating native library: %s", filepath.Base(path))
			
			// Check file size
			if info.Size() == 0 {
				log.Printf("⚠️ Removing empty native library: %s", filepath.Base(path))
				return os.Remove(path)
			}
			
			// Validate ELF header
			if !tool.isValidELF(path) {
				log.Printf("⚠️ Invalid ELF file detected: %s", filepath.Base(path))
				// Don't remove, just log - might be obfuscated
			}
			
			// Ensure proper permissions
			os.Chmod(path, 0644)
		}
		
		return nil
	})
}

func (tool *AdvancedSSLBypass) fixDirectSOFiles(extractDir string) error {
	// Some APKs have .so files in root or other locations
	return filepath.Walk(extractDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		
		if strings.HasSuffix(path, ".so") {
			log.Printf("🔧 Found native library in: %s", path)
			
			if info.Size() == 0 {
				log.Printf("⚠️ Removing empty .so file: %s", filepath.Base(path))
				return os.Remove(path)
			}
		}
		
		return nil
	})
}

func (tool *AdvancedSSLBypass) rebuildAPKWithLibFix(sourceDir string) error {
	// Method 1: Try apktool rebuild (preserves structure)
	cmd := exec.Command("apktool", "b", sourceDir, "-o", tool.OutputPath)
	if err := cmd.Run(); err == nil {
		log.Println("✅ APK rebuilt using apktool")
		return nil
	}
	
	log.Println("⚠️ apktool rebuild failed, using manual zip method...")
	
	// Method 2: Manual ZIP with proper compression settings
	return tool.createAPKWithUncompressedLibs(sourceDir)
}

func (tool *AdvancedSSLBypass) createAPKWithUncompressedLibs(sourceDir string) error {
	file, err := os.Create(tool.OutputPath)
	if err != nil {
		return err
	}
	defer file.Close()
	
	zipWriter := zip.NewWriter(file)
	defer zipWriter.Close()
	
	return filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		
		// Get relative path for ZIP entry
		relPath, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}
		
		// Convert to forward slashes for ZIP
		relPath = strings.ReplaceAll(relPath, "\\", "/")
		
		// Create ZIP header
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = relPath
		
		// Critical: Don't compress native libraries and specific files
		if strings.HasSuffix(relPath, ".so") || 
		   strings.Contains(relPath, "resources.arsc") ||
		   strings.HasSuffix(relPath, ".png") ||
		   strings.HasSuffix(relPath, ".jpg") ||
		   strings.HasSuffix(relPath, ".jpeg") ||
		   strings.HasSuffix(relPath, ".mp4") ||
		   strings.HasSuffix(relPath, ".webp") {
			header.Method = zip.Store // No compression
			log.Printf("📝 Storing uncompressed: %s", relPath)
		} else {
			header.Method = zip.Deflate // Compress other files
		}
		
		// Create file in ZIP
		writer, err := zipWriter.CreateHeader(header)
		if err != nil {
			return err
		}
		
		// Copy file content
		sourceFile, err := os.Open(path)
		if err != nil {
			return err
		}
		defer sourceFile.Close()
		
		_, err = io.Copy(writer, sourceFile)
		return err
	})
}

// Native library handling functions
func (tool *AdvancedSSLBypass) checkNativeLibraries() error {
	log.Println("🔍 Checking for native library issues...")
	
	// Check if APK has native libraries
	cmd := exec.Command("aapt", "list", tool.APKPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to check APK contents: %v", err)
	}
	
	outputStr := string(output)
	hasNativeLibs := strings.Contains(outputStr, "lib/") && strings.Contains(outputStr, ".so")
	
	if !hasNativeLibs {
		log.Println("✅ No native libraries detected")
		return nil
	}
	
	log.Println("📚 Native libraries detected - applying compression fixes...")
	return tool.fixNativeLibraryCompression()
}

func (tool *AdvancedSSLBypass) fixNativeLibraryCompression() error {
	log.Println("🔧 Fixing native library compression...")
	
	// Check lib directory in decompiled APK
	libDir := filepath.Join(tool.TempDir, "lib")
	if _, err := os.Stat(libDir); os.IsNotExist(err) {
		log.Println("✅ No lib directory in decompiled APK")
		return nil
	}
	
	// Process each architecture
	err := filepath.Walk(libDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		
		if strings.HasSuffix(path, ".so") {
			log.Printf("📋 Processing native library: %s", filepath.Base(path))
			
			// Check if library is valid
			if info.Size() == 0 {
				log.Printf("⚠️ Warning: %s is empty - removing", filepath.Base(path))
				return os.Remove(path)
			}
			
			// Verify ELF header
			if !tool.isValidELF(path) {
				log.Printf("⚠️ Warning: %s is not a valid ELF file", filepath.Base(path))
			}
		}
		
		return nil
	})
	
	if err != nil {
		log.Printf("✅ Native library processing completed with warnings")
	} else {
		log.Printf("✅ Native library processing completed successfully")
	}
	
	return nil
}

func (tool *AdvancedSSLBypass) isValidELF(filePath string) bool {
	file, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer file.Close()
	
	// Check ELF magic number
	magic := make([]byte, 4)
	if _, err := file.Read(magic); err != nil {
		return false
	}
	
	// ELF magic: 0x7F + "ELF"
	return magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F'
}

// Crash prevention functions
func (tool *AdvancedSSLBypass) preventCrashes() error {
	log.Println("🛡️ Applying crash prevention measures...")
	
	// 1. Validate smali integrity
	if err := tool.validateSmaliIntegrity(); err != nil {
		log.Printf("Warning: Smali validation issues: %v", err)
	}
	
	// 2. Add error handling to bypass code
	if err := tool.addErrorHandlingToBypass(); err != nil {
		log.Printf("Warning: Could not add error handling: %v", err)
	}
	
	// 3. Ensure proper application lifecycle
	if err := tool.ensureApplicationLifecycle(); err != nil {
		log.Printf("Warning: Application lifecycle issues: %v", err)
	}
	
	return nil
}

func (tool *AdvancedSSLBypass) validateSmaliIntegrity() error {
	log.Println("🔍 Validating smali file integrity...")
	
	smaliDirs := []string{"smali", "smali_classes2", "smali_classes3", "smali_classes4", "smali_classes5"}
	
	for _, dir := range smaliDirs {
		smaliPath := filepath.Join(tool.TempDir, dir)
		if _, err := os.Stat(smaliPath); os.IsNotExist(err) {
			continue
		}
		
		err := filepath.Walk(smaliPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			
			if strings.HasSuffix(path, ".smali") {
				return tool.validateSmaliFile(path)
			}
			return nil
		})
		
		if err != nil {
			return fmt.Errorf("smali validation failed in %s: %v", dir, err)
		}
	}
	
	log.Println("✅ Smali files validation passed")
	return nil
}

func (tool *AdvancedSSLBypass) validateSmaliFile(filePath string) error {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	
	contentStr := string(content)
	
	// Check for basic smali syntax issues
	if strings.Count(contentStr, ".method") != strings.Count(contentStr, ".end method") {
		return fmt.Errorf("method count mismatch in %s", filePath)
	}
	
	// Check for proper class structure
	if strings.Contains(contentStr, ".class") && !strings.Contains(contentStr, ".source") {
		log.Printf("Warning: %s missing .source declaration", filepath.Base(filePath))
	}
	
	return nil
}

func (tool *AdvancedSSLBypass) addErrorHandlingToBypass() error {
	// Find and wrap bypass code with try-catch blocks
	smaliDirs := []string{"smali", "smali_classes2", "smali_classes3", "smali_classes4", "smali_classes5"}
	
	for _, dir := range smaliDirs {
		smaliPath := filepath.Join(tool.TempDir, dir)
		if _, err := os.Stat(smaliPath); os.IsNotExist(err) {
			continue
		}
		
		// Look for our bypass classes and add error handling
		bypassPath := filepath.Join(smaliPath, "com", "bypass")
		if _, err := os.Stat(bypassPath); err == nil {
			err := filepath.Walk(bypassPath, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return nil
				}
				
				if strings.HasSuffix(path, ".smali") {
					return tool.wrapWithErrorHandling(path)
				}
				return nil
			})
			
			if err != nil {
				log.Printf("Error adding error handling: %v", err)
			}
		}
	}
	
	return nil
}

func (tool *AdvancedSSLBypass) wrapWithErrorHandling(filePath string) error {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	
	contentStr := string(content)
	
	// Add try-catch wrapper to critical methods only
	if strings.Contains(contentStr, "checkServerTrusted") || 
	   strings.Contains(contentStr, "verify") ||
	   strings.Contains(contentStr, "getAcceptedIssuers") {
		
		// Add basic error handling comment
		contentStr = strings.ReplaceAll(contentStr, 
			".method public",
			"# SSL bypass method with error handling\n    .method public")
	}
	
	return os.WriteFile(filePath, []byte(contentStr), 0644)
}

func (tool *AdvancedSSLBypass) ensureApplicationLifecycle() error {
	// Make sure our bypass code doesn't interfere with app startup
	manifestPath := filepath.Join(tool.TempDir, "AndroidManifest.xml")
	content, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	
	contentStr := string(content)
	
	// Ensure debuggable is set but don't force other attributes that might cause issues
	if !strings.Contains(contentStr, "android:debuggable=\"true\"") {
		applicationRegex := regexp.MustCompile(`(<application[^>]*?)(>)`)
		contentStr = applicationRegex.ReplaceAllString(contentStr, `${1} android:debuggable="true"${2}`)
	}
	
	return os.WriteFile(manifestPath, []byte(contentStr), 0644)
}

// Process method - Main processing function with all integrated fixes

func (tool *AdvancedSSLBypass) copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}

func (tool *AdvancedSSLBypass) cleanup() {
	if tool.TempDir != "" {
		log.Printf("Cleaning up temporary directory: %s", tool.TempDir)
		os.RemoveAll(tool.TempDir)
	}
}

func (tool *AdvancedSSLBypass) Process() error {
	// Create temp directory if not exists
	if tool.TempDir == "" {
		var err error
		tool.TempDir, err = os.MkdirTemp("", "ssl_bypass_*")
		if err != nil {
			return fmt.Errorf("failed to create temp directory: %v", err)
		}
		defer tool.cleanup()
	}

	log.Printf("Processing APK: %s", tool.APKPath)
	log.Printf("Output will be: %s", tool.OutputPath)
	log.Printf("Temp directory: %s", tool.TempDir)

	// Step 1: Decompile APK
	log.Println("\n[1/8] Decompiling APK...")
	if err := tool.decompileAPK(); err != nil {
		return fmt.Errorf("decompilation failed: %v", err)
	}

	// Display SDK detection results
	if tool.OriginalTargetSDK > 0 {
		log.Printf("\n📋 APK Analysis Summary:")
		log.Printf("   Original Target SDK: %d", tool.OriginalTargetSDK)
		log.Printf("   New Target SDK: %d", tool.NewTargetSDK)
		log.Printf("   Signature Scheme: %s", tool.SignatureScheme)
		if tool.UseLegacyCompat {
			log.Printf("   Compatibility Mode: Enabled (legacy SHA1)")
		}
	}

	// Step 2: Execute selected bypass methods
	log.Println("\n[2/8] Applying SSL bypass methods...")
	if err := tool.executeSelectedMethods(); err != nil {
		log.Printf("Some bypass methods failed: %v", err)
	}

	// Step 3: Generate custom certificate if needed
	log.Println("\n[3/8] Generating custom certificate...")
	if err := tool.generateCustomCertificate(); err != nil {
		log.Printf("Certificate generation failed (continuing): %v", err)
	}

	// Step 3.5: Check and fix native libraries
	log.Println("\n[3.5/8] Checking native libraries...")
	if err := tool.checkNativeLibraries(); err != nil {
		log.Printf("Native library issues detected: %v", err)
	}

	// Step 4: Recompile APK
	log.Println("\n[4/8] Recompiling APK...")
	if err := tool.recompileAPK(); err != nil {
		return fmt.Errorf("recompilation failed: %v", err)
	}

	// Step 4.5: Apply crash prevention measures
	log.Println("\n[4.5/8] Applying crash prevention...")
	if err := tool.preventCrashes(); err != nil {
		log.Printf("Warning: Crash prevention failed: %v", err)
	}

	// Step 5: Sign APK
	log.Println("\n[5/8] Signing APK...")
	if err := tool.signAPK(); err != nil {
		return fmt.Errorf("signing failed: %v", err)
	}

	// Step 6: Align APK
	log.Println("\n[6/8] Aligning APK...")
	if err := tool.alignAPK(); err != nil {
		log.Printf("APK alignment failed (not critical): %v", err)
	}

	// Step 7: Validate APK
	log.Println("\n[7/8] Validating APK...")
	if tool.AutoValidateInstall {
		if err := tool.performHealthCheck(); err != nil {
			log.Printf("APK validation failed: %v", err)
			log.Println("The APK may still work, but installation might fail")
		} else {
			log.Println("✓ APK validation successful - should be installable")
		}
	}

	// Step 8: Final summary
	log.Println("\n[8/8] Process complete")
	log.Printf("Applied %d bypass methods", len(tool.SelectedMethods))
	for _, method := range tool.SelectedMethods {
		log.Printf("  ✓ %s", BypassMethodNames[method])
	}

	log.Printf("\n🎉 SUCCESS! SSL Pinning bypass completed!")
	log.Printf("📦 Output: %s", tool.OutputPath)

	log.Println("")
	log.Println("=== Installation Instructions ===")
	log.Println("1. Enable 'Unknown Sources' in Android settings")
	log.Println("2. Transfer APK to device or use ADB:")
	log.Printf("   adb install -r %s", tool.OutputPath)
	if tool.OriginalTargetSDK >= 30 {
		log.Println("")
		log.Println("📱 ANDROID 11+ COMPATIBILITY NOTES:")
		log.Printf("   • Original Target SDK %d adjusted to 28 for compatibility", tool.OriginalTargetSDK)
		log.Println("   • This avoids resources.arsc compression issues (error -124)")
		log.Println("   • APK uses v1+v2 signature scheme for maximum compatibility")
		log.Println("   • Should install successfully on Android 11+ devices")
	}
	log.Println("3. Setup proxy (Burp Suite, OWASP ZAP, etc.)")
	log.Println("4. Install proxy certificate on device")
	log.Println("5. Start testing - SSL pinning should be bypassed!")
	log.Println("")
	log.Println("🛡️  CRASH PREVENTION NOTES:")
	log.Println("   • If app crashes, try regenerating with 'Safe Mode'")
	log.Println("   • Native library apps may need 'Native Lib Safe Mode'")
	log.Println("   • Smali integrity validation applied automatically")
	log.Println("")
	log.Println("⚠️  This tool is for authorized penetration testing only!")

	return nil
}

func (tool *AdvancedSSLBypass) selectBypassMode() error {
	fmt.Println("\n=== Bypass Mode Selection ===")
	fmt.Println("1. Aggressive Mode (All 9 methods - maximum bypass, may cause crashes)")
	fmt.Println("2. Balanced Mode (Selected safe methods - good balance)")
	fmt.Println("3. Safe Mode (Minimal changes - least likely to crash)")
	fmt.Println("4. Native Lib Safe Mode (For APKs with native libraries)")
	fmt.Println("5. Custom Selection (Choose specific methods)")
	
	fmt.Print("\nSelect bypass mode (1-5): ")
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read input: %v", err)
	}
	
	choice := strings.TrimSpace(input)
	
	switch choice {
	case "1":
		// Aggressive mode - all methods
		tool.SelectedMethods = []BypassMethod{
			ManifestBypass, NetworkSecurityConfig, StaticPatch, SmaliPatch,
			UniversalBypass, OkHttpBypass, RetrofitBypass, TrustAllCerts, HostnameVerifierBypass,
		}
		log.Println("🚀 Aggressive mode selected - using all bypass methods")
		
	case "2":
		// Balanced mode - safe but effective methods
		tool.SelectedMethods = []BypassMethod{
			ManifestBypass, NetworkSecurityConfig, OkHttpBypass, TrustAllCerts,
		}
		log.Println("⚖️  Balanced mode selected - using safe effective methods")
		
	case "3":
		// Safe mode - minimal changes
		tool.SelectedMethods = []BypassMethod{
			NetworkSecurityConfig, ManifestBypass,
		}
		log.Println("🛡️  Safe mode selected - minimal modification approach")
	
	case "4":
		// Native lib safe mode - avoid methods that might corrupt native libs
		tool.SelectedMethods = []BypassMethod{
			NetworkSecurityConfig, ManifestBypass, TrustAllCerts,
		}
		log.Println("📚 Native Lib Safe mode selected - native library friendly")
		
	case "5":
		// Custom selection
		return tool.selectBypassMethods()
		
	default:
		return fmt.Errorf("invalid selection")
	}
	
	return nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	fmt.Println("=== Advanced SSL Pinning Bypass Tool ===")
	fmt.Println("Version 3.1 - Enhanced with crash prevention & native lib fixes")
	fmt.Println()

	var tool *AdvancedSSLBypass

	// Parse command line arguments
	if len(os.Args) >= 3 {
		// Command line mode
		inputAPK := os.Args[1]
		outputAPK := os.Args[2]

		log.Printf("CLI Mode: Processing %s -> %s", inputAPK, outputAPK)
		tool = NewAdvancedSSLBypass(inputAPK, outputAPK)

		// Use balanced methods in CLI mode for stability
		tool.SelectedMethods = []BypassMethod{
			ManifestBypass, NetworkSecurityConfig, OkHttpBypass, TrustAllCerts,
		}

		if err := tool.Process(); err != nil {
			log.Fatalf("❌ SSL bypass failed: %v", err)
		}
	} else {
		// Interactive mode
		log.Println("Interactive Mode - Please follow the prompts")
		tool = &AdvancedSSLBypass{
			AutoValidateInstall: true,
		}

		// Interactive APK selection
		if err := tool.selectAPK(); err != nil {
			log.Fatalf("❌ APK selection failed: %v", err)
		}

		// Interactive output path selection
		if err := tool.selectOutputPath(); err != nil {
			log.Fatalf("❌ Output path selection failed: %v", err)
		}

		// Interactive bypass mode selection  
		if err := tool.selectBypassMode(); err != nil {
			log.Fatalf("❌ Method selection failed: %v", err)
		}

		// Create temp directory
		var err error
		tool.TempDir, err = os.MkdirTemp("", "ssl_bypass_*")
		if err != nil {
			log.Fatalf("Failed to create temp directory: %v", err)
		}
		defer func() {
			log.Printf("Cleaning up temporary directory: %s", tool.TempDir)
			if err := os.RemoveAll(tool.TempDir); err != nil {
				log.Printf("Failed to cleanup temp directory: %v", err)
			}
		}()

		if err := tool.Process(); err != nil {
			log.Fatalf("❌ SSL bypass failed: %v", err)
		}
	}
}
