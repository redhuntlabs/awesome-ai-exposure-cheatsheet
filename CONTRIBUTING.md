# Contributing to AI Exposure

This project is community-driven and only stays useful if people keep adding to it. Whether you found a new Shodan fingerprint, a misconfigured AI tool, a leaked key pattern, or a new no-code builder, your contribution matters.

---

## What to Contribute

**New tools or services** across any layer:
- A working Shodan / Censys query
- A fingerprint to confirm the service (HTTP response body, header, favicon hash)
- The layer it belongs to

**New API key patterns:**
- Provider name
- Regex pattern
- Whether it has a unique prefix or needs additional context to validate

**Improvements to existing entries:**
- More accurate fingerprints
- Additional Shodan queries
- Notes on authentication bypass, known CVEs, or default credentials

**New layers or categories** you think are missing entirely.

---

## How to Submit

1. Fork the repository
2. Edit `README.md` following the existing table format for the relevant layer
3. Open a pull request with a short description of what you added and how you found it

No rigid template required. If the information is accurate and useful, it belongs here.

---

## Fingerprint Format

For Shodan-based entries, try to include at least one of:
- `http.html:"..."` - body string match
- `http.title:"..."` - page title match
- `http.favicon.hash:...` - favicon hash (use shodan favicon hash calculator or fav-up)
- Response header match

For detection / validation, describe the HTTP check:
```
GET / -> body contains "..."
GET /api/health -> 200 OK
Header "X-Foo" present in response
```

---

## API Key Regex Format

Use Golang-compatible regex (`regexp` package syntax). Note any overlap with other providers (e.g. generic `sk-` prefix). If the key requires an API call to validate, mention it in the Notes column.

```go
// Example
`\b(sk-ant-(?:admin01|api03)-[\w\-]{93}AA)\b`
```

---

## Things to Keep in Mind

- Only submit findings for publicly exposed services, not internal or private infrastructure
- Do not include personally identifiable information or actual leaked keys
- If you found this through authorized testing, that context helps reviewers understand the finding

---

## Questions

Open an issue if you are unsure where something fits or want feedback before submitting a PR.
