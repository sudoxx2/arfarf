package main

import (
	"archive/zip"     // for handling zip file extraction
	"crypto/md5"       // for computing file hashes
	"encoding/hex"     // for converting hash bytes to hex strings
	"flag"             // for command-line argument parsing
	"fmt"              // for output printing
	"io"
	"io/ioutil"
	"os"
	"path/filepath"    // for path manipulation
	"strings"
	"bufio"            // for reading files line by line
)

// Global map to store known malware MD5 hashes
var malwareHashes = map[string]bool{}

// Load all .md5 hash files from a given directory
func loadHashesFromDir(dir string) error {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return err
	}

	for _, f := range files {
		if strings.HasSuffix(strings.ToLower(f.Name()), ".md5") {
			fullPath := filepath.Join(dir, f.Name())
			fmt.Println("🔍 Loading hashes from:", fullPath)
			err := loadHashesFromFile(fullPath)
			if err != nil {
				fmt.Printf("⚠️ Failed to load %s: %v\n", fullPath, err)
			}
		}
	}
	return nil
}

// Read a single .md5 file and add each valid hash to the global map
func loadHashesFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 32 { // MD5 hashes are 32 hex characters
			malwareHashes[line] = true
		}
	}

	return scanner.Err()
}

// Compute the MD5 hash of a file and return it as a hex string
func computeMD5(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// Scan a single file, compare its hash to known malware hashes
func scanFile(filePath string) {
	md5hash, err := computeMD5(filePath)
	if err != nil {
		fmt.Printf("[!] Could not hash %s: %v\n", filePath, err)
		return
	}
	if malwareHashes[md5hash] {
		fmt.Printf("[⚠️] Malware found: %s\n", filePath)
	} else {
		fmt.Printf("[OK] Clean: %s\n", filePath)
	}
}

// Extract all contents of a ZIP file to a temporary directory
func extractZip(zipPath string) (string, error) {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", err
	}
	defer r.Close()

	tempDir, err := ioutil.TempDir("", "unzipped")
	if err != nil {
		return "", err
	}

	for _, f := range r.File {
		fPath := filepath.Join(tempDir, f.Name)

		if f.FileInfo().IsDir() {
			os.MkdirAll(fPath, os.ModePerm)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fPath), os.ModePerm); err != nil {
			return "", err
		}

		dstFile, err := os.OpenFile(fPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return "", err
		}

		fileInArchive, err := f.Open()
		if err != nil {
			return "", err
		}

		_, err = io.Copy(dstFile, fileInArchive)
		dstFile.Close()
		fileInArchive.Close()
		if err != nil {
			return "", err
		}
	}

	return tempDir, nil
}

// Recursively walk a directory, scan files, and extract+scan ZIPs
func scanDirectory(path string) {
	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Printf("[!] Error accessing %s: %v\n", filePath, err)
			return nil
		}
		if info.IsDir() {
			return nil
		}

		if strings.HasSuffix(strings.ToLower(filePath), ".zip") {
			fmt.Printf("[📦] ZIP detected: %s → extracting...\n", filePath)
			unzippedDir, err := extractZip(filePath)
			if err != nil {
				fmt.Printf("[!] Error extracting %s: %v\n", filePath, err)
				return nil
			}
			scanDirectory(unzippedDir) // scan extracted files recursively
			return nil
		}

		scanFile(filePath)
		return nil
	})

	if err != nil {
		fmt.Printf("[!] Scan error: %v\n", err)
	}
}

// Entry point: parse CLI args, load hashes, then scan the directory
func main() {
	dirPtr := flag.String("scan", ".", "Directory to scan")
	flag.Parse()

	fmt.Println("🛡️  Malware Scanner (MD5 + ZIP support)")
	fmt.Printf("📂 Scanning: %s\n\n", *dirPtr)

	// Load .md5 files from hash directory
	err := loadHashesFromDir("virus_md5_hashes")
	if err != nil {
		fmt.Printf("❌ Failed to load hash directory: %v\n", err)
		return
	}

	fmt.Printf("✅ Total hashes loaded: %d\n", len(malwareHashes))

	// Begin scanning the selected directory
	scanDirectory(*dirPtr)

	// Wait for Enter before exiting (useful when run by double-click)
	fmt.Println("\nPress Enter to exit...")
	fmt.Scanln()
}
