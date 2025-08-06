Script for Basic heuristic-based SQLi detection through error-based injection. Unaffected by WAF as it uses basic SQL syntax breaks to cause SQL errors.

- Takes Input: URL with query parameters (e.g., `https://example.com/page?id=1&user=admin`) and for each:
    - Step 1: Send a baseline request (unchanged parameters). If the status code is `5xx`, skip this URL or param (already broken).
    - Step 2: For each parameter, mutate its value by appending `'`, `"`, `'--`, `"--`, `'#`, `"#`. (mutates one param at a time, not all together)
    - Step 3: Send mutated request.
        - If the response is `5xx` and the baseline wasn't, it's flagged as SQLi-prone.
        - Check Response Body: Sometimes response code might be still 200, but the response body contains DB errors. It its the case, flagged as SQLi-prone.


### Compilation
```bash
nuitka --standalone --onefile hsqli.py --include-data-dir=errors=errors
```
