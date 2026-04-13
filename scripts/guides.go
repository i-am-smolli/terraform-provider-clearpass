//go:build ignore

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type guide struct {
	Slug        string
	Title       string
	Description string
	SourcePath  string
	OutputPath  string
	Code        string
}

func main() {
	guidesDir := "examples/guides"
	docsGuidesDir := "docs/guides"

	entries, err := os.ReadDir(guidesDir)
	if err != nil {
		fmt.Printf("Error reading %s: %v\n", guidesDir, err)
		os.Exit(1)
	}

	if err := os.MkdirAll(docsGuidesDir, 0755); err != nil {
		fmt.Printf("Error creating %s: %v\n", docsGuidesDir, err)
		os.Exit(1)
	}

	guides := make([]guide, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if filepath.Ext(name) != ".tf" {
			continue
		}

		sourcePath := filepath.Join(guidesDir, name)
		raw, err := os.ReadFile(sourcePath)
		if err != nil {
			fmt.Printf("Error reading %s: %v\n", sourcePath, err)
			os.Exit(1)
		}

		slug := strings.TrimSuffix(name, filepath.Ext(name))
		title := deriveTitle(slug)
		description := fmt.Sprintf("Terraform guide for the %s scenario.", strings.TrimPrefix(title, "ClearPass "))
		outputPath := filepath.Join(docsGuidesDir, slug+".md")

		guides = append(guides, guide{
			Slug:        slug,
			Title:       title,
			Description: description,
			SourcePath:  sourcePath,
			OutputPath:  outputPath,
			Code:        strings.TrimRight(string(raw), "\n") + "\n",
		})
	}

	if len(guides) == 0 {
		fmt.Printf("No guide files found in %s\n", guidesDir)
		os.Exit(1)
	}

	sort.Slice(guides, func(i, j int) bool {
		return guides[i].Slug < guides[j].Slug
	})

	for _, g := range guides {
		page := renderGuidePage(g)
		if err := os.WriteFile(g.OutputPath, []byte(page), 0644); err != nil {
			fmt.Printf("Error writing %s: %v\n", g.OutputPath, err)
			os.Exit(1)
		}
		fmt.Printf("Generated %s from %s\n", g.OutputPath, g.SourcePath)
	}

	indexPath := filepath.Join(docsGuidesDir, "index.md")
	index := renderIndexPage(guides)
	if err := os.WriteFile(indexPath, []byte(index), 0644); err != nil {
		fmt.Printf("Error writing %s: %v\n", indexPath, err)
		os.Exit(1)
	}

	fmt.Printf("Generated %s\n", indexPath)
}

func deriveTitle(slug string) string {
	tokens := strings.Split(slug, "_")
	parts := make([]string, 0, len(tokens))
	for _, t := range tokens {
		switch strings.ToLower(t) {
		case "tacacs":
			parts = append(parts, "TACACS+")
		case "junos":
			parts = append(parts, "Junos")
		case "example":
			parts = append(parts, "Example")
		default:
			if t == "" {
				continue
			}
			parts = append(parts, strings.ToUpper(t[:1])+strings.ToLower(t[1:]))
		}
	}

	if len(parts) == 0 {
		return "ClearPass Guide"
	}

	return "ClearPass " + strings.Join(parts, " ")
}

func renderGuidePage(g guide) string {
	var b strings.Builder
	b.WriteString("---\n")
	b.WriteString(fmt.Sprintf("page_title: \"%s\"\n", g.Title))
	b.WriteString("subcategory: \"Configuration Guides\"\n")
	b.WriteString("description: |-\n")
	b.WriteString("  ")
	b.WriteString(g.Description)
	b.WriteString("\n")
	b.WriteString("---\n\n")
	b.WriteString("# ")
	b.WriteString(g.Title)
	b.WriteString("\n\n")
	b.WriteString("This guide is generated from `")
	b.WriteString(g.SourcePath)
	b.WriteString("` and shows a full Terraform example.\n\n")
	b.WriteString("```terraform\n")
	b.WriteString(g.Code)
	b.WriteString("```\n")

	return b.String()
}

func renderIndexPage(guides []guide) string {
	var b strings.Builder
	b.WriteString("---\n")
	b.WriteString("page_title: \"Guides\"\n")
	b.WriteString("subcategory: \"Configuration Guides\"\n")
	b.WriteString("description: |-\n")
	b.WriteString("  Practical, generated guides for common ClearPass Terraform setups.\n")
	b.WriteString("---\n\n")
	b.WriteString("# Guides\n\n")
	b.WriteString("Use these generated guides as end-to-end examples for specific ClearPass scenarios.\n\n")
	b.WriteString("## Available Guides\n\n")

	for _, g := range guides {
		b.WriteString(fmt.Sprintf("- [%s](./%s.md) - %s\n", g.Title, g.Slug, g.Description))
	}
	b.WriteString("\n")

	return b.String()
}
