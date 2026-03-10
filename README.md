# httpheaders

Inspect HTTP response headers with security analysis.

One file. Zero deps. Reads headers.

## Usage

```bash
# Show all headers
python3 httpheaders.py https://example.com

# Security header analysis with grade
python3 httpheaders.py https://github.com --security

# Filter specific headers
python3 httpheaders.py https://example.com --filter server,content-type

# JSON output
python3 httpheaders.py https://example.com --json
```

## Security Check

Checks 10 security headers (HSTS, CSP, X-Content-Type-Options, X-Frame-Options, etc.) and assigns a grade A-F.

## Requirements

Python 3.8+. No dependencies.

## License

MIT
