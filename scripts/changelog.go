//go:build ignore

package main

import (
	"fmt"
	"os"
)

func main() {
	changelog, err := os.ReadFile("CHANGELOG.md")
	if err != nil {
		fmt.Printf("Error reading CHANGELOG.md: %v\n", err)
		os.Exit(1)
	}

	err = os.MkdirAll("docs/guides", 0755)
	if err != nil {
		fmt.Printf("Error creating docs/guides dir: %v\n", err)
		os.Exit(1)
	}

	out := "---\npage_title: \"Changelog\"\nsubcategory: \"\"\ndescription: |-\n  Changelog for the ClearPass Terraform provider.\n---\n\n" + string(changelog)

	err = os.WriteFile("docs/guides/changelog.md", []byte(out), 0644)
	if err != nil {
		fmt.Printf("Error writing docs/guides/changelog.md: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Successfully generated docs/guides/changelog.md from CHANGELOG.md")
}
