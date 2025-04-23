package main

import (
	"archive/zip"
	"crypto/md5"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// === KNOWN MALWARE HASHES ===
var malwareHashes = map[string]string{
	"eicar_test_file": "44d88612fea8a8f36de82e1278abb02f",
}

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

func scanFile(filePath string) {
	md5hash, err := computeMD5(filePath)
	if err != nil {
		fmt.Printf("[!] Could not hash %s: %v\n", filePath, err)
		return
	}
	for name, knownHash := range malwareHashes {
		if md5hash == knownHash {
			fmt.Printf("[⚠️] Malware found: %s (%s)\n", filePath, name)
			return
		}
	}
	fmt.Printf("[OK] Clean: %s\n", filePath)
}

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
			scanDirectory(unzippedDir)
			return nil
		}

		scanFile(filePath)
		return nil
	})

	if err != nil {
		fmt.Printf("[!] Scan error: %v\n", err)
	}
}

func main() {
	dirPtr := flag.String("scan", ".", "Directory to scan")
	flag.Parse()

	fmt.Println("🛡️  Malware Scanner (MD5 + ZIP support)")
	fmt.Printf("📂 Scanning: %s\n\n", *dirPtr)

	scanDirectory(*dirPtr)
}
