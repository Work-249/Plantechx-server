# Server README

Masking and logging

- MASK_PII: Controls masking of PII (emails) in server logs.
  - Default behavior: masking is enabled by default.
  - To disable masking for local debugging, set `MASK_PII=false` in your environment.
  - When masking is enabled, the logger will replace email local-parts with a masked form (e.g. `c***@gmail.com`).

Why this exists

- Sensitive data (email addresses, tokens, passwords) must not be written to logs in production.
- The central logger (`server/middleware/logger.js`) sanitizes metadata before writing to console or log files.

Notes and operational guidance

- There is one intentional direct stderr fallback inside the logger used when the logger fails to write to the log files. This prevents recursive calls to the logger when the logger itself cannot write to disk.
- Recommended environment variables for local development:
  - `MASK_PII=true` (default)
  - `LOG_LEVEL=INFO`

Example (Windows PowerShell):

```powershell
# Run tests with masking enabled
$env:MASK_PII = 'true'; npm test

# Run with masking disabled (show raw emails in logs for debugging)
$env:MASK_PII = 'false'; npm test
```

If you want this documented at top-level README instead, I can move or duplicate the content there.
