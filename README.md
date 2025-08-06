Script for Basic heuristic-based SQLi detection through error-based injection. Unaffected by WAF as it uses basic SQL syntax breaks to cause SQL errors.

Warning: Don’t supply URLs that already include SQL-injection payloads or you may get false negatives; this tool appends its own suffixes and expects “clean” parameters.

- Takes Input: URL with query parameters (e.g., `https://example.com/page?id=1&user=admin`) and for each:
    - Step 1: Send a baseline request (unchanged parameters). If the status code is `5xx`, skip this URL or param (already broken).
    - Step 2: For each parameter, mutate its value by appending `'`, `"`, `'--`, `"--`, `'#`, `"#`, etc. (mutates one param at a time, not all together)
    - Step 3: Send mutated request.
        - Detection Logic
            - 5xx Status Check
                - If the response is `5xx` and the baseline wasn't, it's flagged as potential SQLi.
            - Error Message Check
                - Check Response Body: Sometimes response code might be still 200, but the response body contains DB errors. It its the case, flagged as potential SQLi.
                - Compares against the baseline body to filter out SQL errors already present (avoiding false positives).

## Some points to keep in mind or might come handy while using VBust
- When the mutated URL uses a value `aprefix123asuffix` for a parameter, it means the original URL provided had the parameter name present but no assigned value.

### Compilation
```bash
nuitka --standalone --onefile hsqli.py --include-data-dir=errors=errors
```

# TODO:
- Option to ignore/remove specific SQL error messages.
- In likely database output don't just print one DBMS error found, rather print all DBMS errors found.
- Add option to specify use of one detection method: choose between HTTP 5xx status codes, SQL error message matching, rather than both.
