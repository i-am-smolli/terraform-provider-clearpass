---
description: A workflow to enforce code style
---

## Persona

- You specialize in human readable code that follows templates
- You understand the codebase and translate that into clear code
- Your output: Code that developers can understand

## Project knowledge

- **Tech Stack:** Golang 1.25.4, terraform-plugin-framework 1.16.1
- **File Structure:**
  - `internal/` – Source code for the terraform-provider-clearpass
  - `internal/provider/test/` - test files for the provider

## Tools you can use

- **Build:** `go build .` (from the root directory, outputs terraform-provider-clearpass)
- **Test:** `TF_ACC=1 go test ./internal/provider/... -v` (there are env values in .env . Must not fail before commits)
- **Lint:** `golangci-lint run` (must not return 0 issues)

## Standards

Follow these rules for all code you write:

**Naming conventions:**

- Functions: PascalCase (`GetUserData`, `CalculateTotal`)
- Classes: camalCase (`userService`, `dataController`)
- Constants: UPPER_SNAKE_CASE (`API_KEY`, `MAX_RETRIES`)

**Code style example:**

```typescript
// ✅ Good - descriptive names, proper error handling
func PrintReceipt(total float64) {
 fmt.Printf("Der Gesamtbetrag ist: %.2f %s\n", total, CURRENCY_SYMBOL)
}

// ❌ Bad - vague names, no error handling
func calculateStuff(val int) int {
 // BAD: Magic Numbers (500, 199) ohne Erklärung
 if val > 500 {
  // BAD: Panic für normale Logik-Steuerung benutzen
  panic("Wert zu hoch!")
 }
 return val * 199
}

Boundaries
- ✅ **Always:** Write to `interal/provider/` and `interal/provider/test/`, run tests before commits, follow naming conventions
- ⚠️ **Ask first:** Database schema changes, adding dependencies, modifying CI/CD config
- 🚫 **Never:** Commit secrets or API keys, edit `node_modules/` or `vendor/`
```
