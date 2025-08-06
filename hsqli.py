#!/usr/bin/python3

import sys
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, unquote, quote
import argparse
import argcomplete
from collections import defaultdict
import requests
import urllib3  # For handling SSL warning suppression
import concurrent.futures

import ssl
import gzip
from http.client import HTTPConnection, HTTPSConnection

# Disable SSL certificate warnings 
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CYAN = "\033[96m"
RESET = "\033[0m"


#! debug_print does NOT print regex results
# passing f-strings to debug_print function - this function can handle f-strings directly (e.g., debug_print(f"one plus one = {1+1}")) and f-strings in variables passed as f-strings (e.g., 1plus1 = f"one plus one = {1+1}"; debug_print(f"{1plus1}")), but not f-string variables directly (e.g., 1plus1 = f"one plus one = {1+1}"; debug_print(1plus1)).
def debug_print(message, newline=False):
    """If debug_mode is enabled, prints debug messages from wherever it is called.

    Args:
        message (str): The message to be printed. This can be a regular string or an f-string.
        newline (bool, optional): If True, prints message with formatting and a separator. Defaults to False.
    """
    if debug_mode and newline:
        cyan_line = f"{CYAN}{'-' * 150}{RESET}"
        print(f"\n\n{cyan_line}\nDebug: {message}{RESET}\n{cyan_line}")
    elif debug_mode:
        print(f"Debug: {message}")


def detect_paramters(url):
    """Returns a list of all parameter names in a URL, including those without assigned values (e.g., "page" in "?page" or "?page=")

    Definitions:
        excluding empty keys: it means ignoring parameters that have no name before the equals sign, such as in =value. (e.g. http://example.com/home?=value&page=2)

    Args:
        url (str): URL whose path-embedded and query parameter names to be extracted.

    Returns:
        tuple: 
            - (str) url provided.
            - (list) All parameter names from the URL (path-embedded and query), excluding empty keys.
    """

    # For each url parameter query or path-embedded find unfiltered characters using unfiltered_characters function.
    # url = "https://example.com/products;category=electronics;brand=;items;id=1;color=black?sort=price&order=&page"  # example testing URL
    parsed = urlparse(url)

    # Extract path-embedded parameter names
    path_param_names = [pair.split("=")[0] for pair in parsed.params.split(";") if pair]

    # Extract query parameter names (even if no value is assigned)
    query_param_names = [pair.split("=")[0] for pair in parsed.query.split("&") if pair]

    all_parameters = path_param_names + query_param_names

    # Removes empty string elements from all_parameters if any present, caused by parameters with no name before the equal sign such as "=value" in http://example.com/home?=value&page=2
    # filtered_parameters_list = [item for item in all_parameters if item != ""]
    filtered_parameters_list = []
    for item in all_parameters:
        # If the parameter name is not an empty string, add it to the filtered list
        if item != "":
            filtered_parameters_list.append(item)
        # # If the parameter name is empty (e.g., "=value"), log a debug message
        # else:
        #     debug_print(f"{GRAY}[~] URL has parameter value but not name{RESET}", newline=True)

    return (url, filtered_parameters_list)


# #! If a URL contains the same query parameter multiple times (e.g., price=1&price=2), the modified URL will only retain one instance of that parameter with the new value. For example: https://example.com/page?foo=bar&price=100&price=200 becomes: https://example.com/page?foo=bar&price=aprefixpriceapsuffix
# def modified_url_param(url, target_param, replace_value):
#     """Replaces the VALUE of a specific query or path-embedded parameter (specified using target_param) in the given URL (specified using url) with a new string (specified using replace_value).

#     Args:
#         url (str): The URL to modify: URL whose targeted query paramter value needs to be replaced with replace_value.
#         target_param (str): The name of the parameter to modify: Target query paramter name which will tell the function which query parameter's value needs to be replaced with replace_value.
#         replace_value (str): Value that should be replaced with the current parameter value.

#     Returns:
#         modified_url (str or None): URL with the updated target query or path-embedded parameter value specified with replace_value while preserving all other paramters. Returns None if the target parameter is not found in URL paramters.
#     """

#     # if isinstance(url, bytes):  # fix for byte-type URLs  (didn't fix any error)
#     #     url = url.decode('utf-8', errors='replace')

#     parsed = urlparse(url)  # Splits the URL into components (scheme, netloc, path, params [parameters embedded in the path], query parameters, and fragment).

#     # --- Handle query string ---
#     query_params = parse_qs(parsed.query, keep_blank_values=True)  # Parses the query string into a dict of lists. Example: ?name=alex&age=22 → { 'name': ['alex'], 'age': ['22'] }
#     query_modified = False  # Flag to track whether any query parameter was modified.

#     if target_param in query_params.keys():  # Check if the target parameter exists in the query parameter names.
#         query_params[target_param] = [replace_value]  # Replaces/modifies only the target query parameter value with replace_value. Other parameters are untouched.
#         query_modified = True  # Mark that a query param was successfully modified.


#     # --- Handle path-embedded parameters ---
#     # Path-embedded are parameters embedded in the path, which are part of the URL path segment, not the query string. semicolon (;) is used to define parameters for path segments. Example: https://example.com/path;param1=value1?query=123

#     path_modified = False  # Flag to track whether any path-embedded parameter was modified.
#     path_embedded_params = parsed.params.split(';')  # returns list of path-embedded parameters. e.g. ['param1=value1', 'param2=value2']
#     path_embedded_params = {k: [v] for k, v in (s.split('=', 1) for s in path_embedded_params if '=' in s)}  # Converts the embedded_params list into a dictionary with parameter values being a single itme list. Example: {'param_name': ['param_value'], 'param_name2': ['param_value2']}

#     if target_param in path_embedded_params.keys():  # Check if the target parameter exists in the path-embedded parameter names.
#         path_embedded_params[target_param] = [replace_value]  # Replaces/modifies only the target path-embedded parameter value with replace_value. Other parameters are untouched.
#         path_modified = True  # Mark that a path-embedded parameter was successfully modified.


#     # If neither the path nor the query was modified, there’s no point in rebuilding the URL.
#     if not query_modified and not path_modified:
#         return None  # Return None to indicate the target parameter wasn't found.


#     # If the target parameter was a query parameter then returns the url encoded modified URL by reconstructing the URL with the updated target query parameter value while preserving all other query paramters. 
#     if query_modified:
#         new_query = urlencode(query_params, doseq=True)
#         modified_url = urlunparse(parsed._replace(query=new_query))
#     # If the target parameter was a path-embedded parameter then returns the url encoded modified URL by reconstructing the URL with the updated target path-embedded parameter value while preserving all other path-embedded paramters. 
#     elif path_modified:
#         new_path_embedded = urlencode(path_embedded_params, doseq=True)
#         modified_url = urlunparse(parsed._replace(params=new_path_embedded))

#     return modified_url


#! If a URL contains the same path embedded parameter multiple times (e.g., price=1&price=2), the modified URL will only retain one instance of that parameter with the new value. For example: https://example.com/path;price=100&price=200?query=chips becomes: https://example.com/path;price=aprefixpriceapsuffix?query=chips
def modified_url_param(url, target_param, replace_value):
    """Replaces the VALUE of a specific query or path-embedded parameter (specified using target_param) in the given URL (specified using url) with a new string (specified using replace_value).

    Args:
        url (str): The URL to modify: URL whose targeted query paramter value needs to be replaced with replace_value.
        target_param (str): The name of the parameter to modify: Target query paramter name which will tell the function which query parameter's value needs to be replaced with replace_value.
        replace_value (str): Value that should be replaced with the current parameter value.

    Returns:
        modified_url (str or None): URL with the updated target query or path-embedded parameter value specified with replace_value while preserving all other paramters. Returns None if the target parameter is not found in URL paramters.
    """

    parsed = urlparse(url)
    found = False

    # --- Query string ---
    if parsed.query:
        parts = parsed.query.split("&")
        for i, part in enumerate(parts):
            if "=" in part:
                key, val = part.split("=", 1)
                if key == target_param:
                    parts[i] = f"{key}={replace_value}"
                    found = True
        new_query = "&".join(parts)
    else:
        new_query = ""

    # --- Path-embedded parameters ---
    if parsed.params:
        parts = parsed.params.split(";")
        for i, part in enumerate(parts):
            if "=" in part:
                key, val = part.split("=", 1)
                if key == target_param:
                    parts[i] = f"{key}={replace_value}"
                    found = True
        new_params = ";".join(parts)
    else:
        new_params = ""

    if not found:
        return None

    # Rebuild URL without touching any other characters
    return urlunparse(parsed._replace(query=new_query, params=new_params))


def raw_get_request(full_url, proxy_url=None, headers=None, timeout=10, verify=False):
    """
    Sends a raw GET through an optional HTTPS proxy, preserving your exact path+query, then returns (status_code, decoded_body_str).

    Sends an exact, un-quoted HTTP GET request through an HTTPS proxy (if provided), preserving the raw path, params, and query string (including special characters) and returns the HTTP status code along with the fully decoded response body.

    This function uses Python’s low-level http.client to:
      1. (If proxy_url) Establish an SSL or plain‐text TCP connection to the proxy.
      2. (If proxy_url) Issue a CONNECT tunnel request for the target host and port.
      3. Send the raw GET request line exactly as provided (no automatic %-encoding).
      4. Read the complete response and, if gzip-encoded, decompress it.
      5. Decode the bytes into a Unicode string using UTF-8 (with error replacement).

    Args:
        full_url (str):
            The complete target URL.
        proxy_url (str, optional):
            The proxy address ("http://host:port" or "https://host:port").
            If None, no proxy is used. Defaults to None.
        headers (dict, optional):
            HTTP headers to include in the GET request. Defaults to None.
        timeout (int, optional):
            Socket timeout in seconds for the tunnel and request. Defaults to 10.
        verify (bool, optional):
            Whether to verify the proxy’s SSL certificate. Defaults to False.

    Returns:
        tuple[int, str]:
            - A pair of:
                - status_code (int): The HTTP response status code (e.g., 200, 404).
                - body (str): The full response body as a UTF-8 decoded string, with any gzip compression automatically handled.

    Raises:
        Any exceptions from http.client or socket operations will bubble up, allowing the caller to handle timeouts, proxy failures, etc.
    """

    parsed = urlparse(full_url)

    # Reconstruct raw request-path (path + ;params + ?query)
    raw_path = parsed.path
    if parsed.params:
        raw_path += ";" + parsed.params
    if parsed.query:
        raw_path += "?" + parsed.query

    is_https = parsed.scheme.lower() == "https"
    default_port = 443 if is_https else 80

    # Helper to create a connection
    def make_conn(host, port):
        if is_https:
            ctx = ssl._create_unverified_context() if not verify else ssl.create_default_context()
            return HTTPSConnection(host, port, timeout=timeout, context=ctx)
        else:
            return HTTPConnection(host, port, timeout=timeout)

    # Build connection (with or without proxy)
    if proxy_url:
        p = urlparse(proxy_url)
        conn = make_conn(p.hostname, p.port)
        conn.set_tunnel(parsed.hostname, parsed.port or default_port)
    else:
        conn = make_conn(parsed.hostname, parsed.port or default_port)

    # Send raw GET
    conn.request("GET", raw_path, headers=headers or {})
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()

    # Decompress gzip if needed
    if resp.getheader("Content-Encoding", "").lower() == "gzip":
        raw = gzip.decompress(raw)

    # Decode to text
    body = raw.decode("utf-8", errors="replace")
    return resp.status, body


# Required for test_sqli_error function
# Preloading DBMS-specific SQL error messages into memory by keeping it out of the test_sqli_error function. This avoids repeatedly opening and reading the same files during SQLi error testing.
error_files = {
    "mysql": "errors/mysql-errors.txt",
    "oracle_1": "errors/oracle-errors1.txt",
    "oracle_2": "errors/oracle-errors2.txt",
    "postgresql_1": "errors/postgresql-errors1.txt",
    "postgresql_2": "errors/postgresql-errors2.txt",
    "microsoft_sql_server": "errors/microsoft_sql_server-errors.txt",
    "microsoft_access": "errors/microsoft_access-errors.txt",
    "ibm_db2": "errors/ibm_db2-errors.txt",
    "sqlite": "errors/sqlite-errors.txt",
    "firebird_1": "errors/firebird-errors1.txt",
    "firebird_2": "errors/firebird-errors2.txt",
    "firebird_3": "errors/firebird-errors3.txt"
}

# 'errors' is a dict mapping each DBMS name to a list of its error messages.
errors = {
    "generic_errors": [
        "syntax error", "unterminated string", "unclosed quotation mark", "unexpected token", "query failed", "invalid query",
        "error in your SQL syntax", "missing operator", "column not found", "unknown column", "table not found", "ambiguous column",
        "data type mismatch", "division by zero", "operand should contain", "number of query values and columns do not match",
        "invalid identifier"
        ]
}

for db, path in error_files.items():
    with open(path, 'r') as file:
        errors[db] = [line.strip() for line in file]
def test_sqli_error(url, parameter_name, original_parameter_value, timeout, proxy_url=None, headers=None):
    """
    Detects SQL error messages in the response body by mutating a given URL parameter with common SQL injection payloads and checking for known DBMS-specific errors. It avoids false positives by comparing against the baseline (normal) response content, if the baseline also contains the same SQL error that's a false positive which is ignored.

    Args:
        url (str): The original URL containing the parameter to test.
        parameter_name (str): The name of the parameter to mutate.
        original_parameter_value (str): The original value of the parameter to be mutated by appending suffix.
        timeout (int): Timeout for requests in seconds.
        proxy_url (str, optional): Optional HTTP proxy to use for requests.
        headers (dict, optional): Custom HTTP headers to include in the request, such as User-Agent or Authorization.

    Returns:
        tuple: A tuple of (is_sqli_error: bool or None (None if request fails for baseline), database_name: str or None, matched_error_msg: str or None), mutated_url (str or None)
            - is_sqli_error: True if a known SQL error message is found in the mutated response but not in the baseline.
            - database_name: The name of the DBMS whose error message found in payload response, or None if no match found.
            - matched_error_msg: The actual SQL error message found in payload response, or None if no match found.
            - mutated_url: The URL with the payload that triggered the SQL error in response, or None if no error was triggered.
    """

    proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None

    baseline_response_text = None
    payload_response_text = None

    try:
        # Get baseline response
        baseline_response = requests.get(url, timeout=timeout, proxies=proxies, verify=False, allow_redirects=False, headers=headers)
        baseline_response_text = baseline_response.text.lower()
    # Handles all request failures
    except Exception as e:
        # returns None if couldn't get a response
        return (None, None, None, None)

    suffixes = ["'", '"', "'--", '"--', "'#", '"#']

    # parameter_value = parameter

    detected_database = None
    found_error_msg = None

    for suffix in suffixes:
        ## URL encoded
        payload = original_parameter_value + suffix
        mutated_url = modified_url_param(url=url, target_param=parameter_name, replace_value=payload)

        ## Non URL encoded
        payload_raw = original_parameter_value + suffix
        # doesn't URL encoded already URL encoded URL
        encoded_url = str(quote(url, safe="#!$%&'()*+,/:;=?@[]"))  # doesn't encoded hypen '-' even though it's not specified in safe
        # URL will be encoded except the suffix payload for the target parameter
        mutated_url_raw = modified_url_param(url=encoded_url, target_param=parameter_name, replace_value=payload_raw)

        try:
            # sending URL encoded payload and checking for potential sqli
            payload_response = requests.get(mutated_url, timeout=timeout, proxies=proxies, verify=False, allow_redirects=False, headers=headers)
            payload_response_text = payload_response.text.lower()  # response body in lowercase normalised

            if baseline_response_text is not None and payload_response_text is not None:
                for db in errors.keys():
                    sql_errors = errors.get(db)

                    for err in sql_errors:
                        if err.lower() in payload_response_text:
                            detected_database = db
                            found_error_msg = err.lower()

                            # Avoid false positives by checking if the error is already present in baseline
                            if found_error_msg in baseline_response_text:
                                continue

                            if found_error_msg not in baseline_response_text:
                                return (True, detected_database, found_error_msg, mutated_url)

            # sending non URL encoded payload and checking for potential sqli
            try:
                payload_response_raw = raw_get_request(full_url=mutated_url_raw, proxy_url=proxy_url, headers=headers, timeout=timeout)
            except Exception as e:
                payload_response_raw = None
            # if request didn't fail
            if payload_response_raw is not None:
                payload_response_raw_status_code, payload_response_raw_response_text = payload_response_raw
                payload_response_raw_response_text = payload_response_raw_response_text.lower()  # response body in lowercase normalised

                if baseline_response_text is not None and payload_response_raw_response_text is not None:
                    for db in errors.keys():
                        sql_errors = errors.get(db)

                        for err in sql_errors:
                            if err.lower() in payload_response_raw_response_text:
                                detected_database = db
                                found_error_msg = err.lower()

                                # Avoid false positives by checking if the error is already present in baseline
                                if found_error_msg in baseline_response_text:
                                    continue

                                if found_error_msg not in baseline_response_text:
                                    return (True, detected_database, found_error_msg, mutated_url_raw)

        # Handles all request failures
        except Exception as e:
            continue

    return (False, detected_database, found_error_msg, None)


#! if the URL contain the given parameter name multiple times, it returns the value of first parameter found.
#! Make sure the specified param_name exist in the provided url or else the function will return 'aprefix123asuffix' even though the parameter name doesn't exist in the url.
def get_parameter_value(url, param_name):
    """
    Retrieves the value of a specified parameter name from a URL.

    This function checks both path parameters (after a semicolon ';' in the last path segment) and query parameters (after the '?' in the URL), then returns the parameter value found for the given parameter name.
    If the parameter is present but has no value (e.g., `param1=`), the function returns the string "aprefix123asuffix".  
    If the parameter is not found at all, it returns `None`.

    Notes:
        - If the parameter occurs multiple times, only the first occurrence is returned.
        - Make sure the specified `param_name` exists in the URL. If not, the function will return `None`.

    Args:
        url (str): The URL to extract the parameter from.
        param_name (str): The name of the parameter whose value to retrieve.

    Returns:
        str or int or None:
            - The parameter value as a string if found and has a value (even if the parameter value is a number, it will be returned as a string),
            - "aprefix123asuffix" if the parameter exists without a value,
            - `None` if the parameter is not present in the URL.
    """

    # Parse the URL into components
    parsed = urlparse(url)

    # Extract path parameters (after ';' in the last path segment)
    path_params = parse_qs(parsed.params)
    # Extract query parameters (after '?') as a dictionary
    query_params = parse_qs(parsed.query)

    # # Parameter to search for
    # param_name = "param2"

    # Check if the parameter exists in path parameters
    if path_params.get(param_name):
        return path_params.get(param_name)[0]  # Found in path parameters
    # If parameter does not exist in path parameters, fallback to query parameters
    elif query_params.get(param_name):
        return query_params.get(param_name)[0]  # Found in query parameters
    # If the parameter exists in path parameters but doesn't have a value
    try:
        path_params[param_name]
    except KeyError:
        return "aprefix123asuffix"
    # If the parameter exists in query parameters but doesn't have a value
    try:
        query_params[param_name]
    except KeyError:
        return "aprefix123asuffix"
    # # If the parameter exists in path parameters but doesn't have a value
    # elif bool(path_params.get(param_name)):
    #     return "aprefix123asuffix"
    # # If the parameter exists in query parameters but doesn't have a value
    # elif bool(query_params.get(param_name)):
    #     return "aprefix123asuffix"
    # # If the parameter does not exist in the URL
    # else:
    #     return None


def test_sqli_500(url, parameter_name, original_parameter_value, timeout, proxy_url=None, headers=None):
    """
    Tests a specific URL parameter for potential SQL injection vulnerabilities by appending common payload suffixes to the original provided parameter value. If the parameter is vulnerable, these mutations may trigger server-side 5xx errors. Any 5xx status code other than baseline response is returned indicating potential SQLi behaviour.

    Args:
        url (str): Full URL containing the target parameter to be tested.
        parameter_name (str): The name of the parameter to test (mutate).
        original_parameter_value (str): The original, unmodified value of the parameter.
        timeout (int): Timeout for requests in seconds.
        proxy_url (str, optional): Optional HTTP proxy to route requests through.
        headers (dict, optional): Custom HTTP headers to include in the request, such as User-Agent or Authorization.

    Returns:
        tuple | None:
            - If a 5xx error is triggered by a payload, returns (mutated_url, response_status_code).
            - Returns None if:
                * The baseline response already returns 5xx (invalid test case),
                * No payload triggers a 5xx error,
                * A request exception occurs.
    """

    proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None

    try:
        # Get baseline response
        baseline_response = requests.get(url, timeout=timeout, proxies=proxies, verify=False, allow_redirects=False, headers=headers)
        if baseline_response.status_code >= 500 and baseline_response.status_code < 600:
            debug_print(f"[~] `test_sqli` Returning None because the baseline response returned a 5xx response code ({baseline_response.status_code}).")
            return None
    # Handles all request failures
    except Exception as e:
        # returns None if couldn't get a response
        return None

    suffixes = ["'", '"', "'--", '"--', "'#", '"#']

    # parameter_value = parameter

    for suffix in suffixes:
        ## URL encoded
        payload = original_parameter_value + suffix
        mutated_url = modified_url_param(url=url, target_param=parameter_name, replace_value=payload)

        ## Non URL encoded
        payload_raw = original_parameter_value + suffix
        # doesn't URL encoded already URL encoded URL
        encoded_url = str(quote(url, safe="#!$%&'()*+,/:;=?@[]"))  # doesn't encoded hypen '-' even though it's not specified in safe
        # URL will be encoded except the suffix payload for the target parameter
        mutated_url_raw = modified_url_param(url=encoded_url, target_param=parameter_name, replace_value=payload_raw)

        try:
            # sending URL encoded payload and checking for potential sqli
            mutated_response = requests.get(mutated_url, timeout=timeout, proxies=proxies, verify=False, allow_redirects=False, headers=headers)
            if mutated_response.status_code >= 500 and mutated_response.status_code < 600:
                return (mutated_url, mutated_response.status_code)
            
            # sending non URL encoded payload and checking for potential sqli
            try:
                mutated_response_raw = raw_get_request(full_url=mutated_url_raw, proxy_url=proxy_url, headers=headers, timeout=timeout)
            except Exception as e:
                mutated_response_raw = None
            # if request didn't fail
            if mutated_response_raw is not None:
                mutated_response_raw_status_code, mutated_response_raw_response_body = mutated_response_raw
                # mutated_response_raw_response_body = mutated_response_raw_response_body.lower()
                if mutated_response_raw_status_code >= 500 and mutated_response_raw_status_code < 600:
                    return (mutated_url_raw, mutated_response_raw_status_code)

        # Handles all request failures
        except Exception as e:
            continue
    
    # if reached end and yet didn't find any 5xx in response code (except basline respone) returns None
    return None

def replace_empty_url_param(url, target_param, default_value="123"):
    """
    In the given URL, if `target_param` appears with no value (e.g. `param=` or just `param`) in either the semicolon‐embedded path or the query string (even if the URL forgot the '?'), fills it with default_value. Leaves every other parameter untouched, and preserves encoding.

    Args:
        url (str): The URL to process.
        target_param (str): The name of the parameter to fill if empty (case-sensitive).
        default_value (str): What to assign if the parameter has no value.

    Returns:
        str: The updated URL.
    """
    parsed = urlparse(url)

    # Handle missing '?' but '&' in path
    if not parsed.query and "&" in parsed.path:
        base, fake_q = parsed.path.split("&", 1)
        parsed = parsed._replace(path=base, query=fake_q)

    # Process query string
    new_query_parts = []
    for part in parsed.query.split("&"):
        if not part:
            continue
        if "=" in part:
            key, val = part.split("=", 1)
            if key == target_param and val == "":
                new_query_parts.append(f"{key}={default_value}")
            else:
                new_query_parts.append(part)
        else:
            # “key” with no '='
            if part == target_param:
                new_query_parts.append(f"{part}={default_value}")
            else:
                new_query_parts.append(part)
    new_query = "&".join(new_query_parts)

    # Process semicolon‐embedded path params
    new_path_parts = []
    for part in parsed.params.split(";"):
        if not part:
            continue
        if "=" in part:
            key, val = part.split("=", 1)
            if key == target_param and val == "":
                new_path_parts.append(f"{key}={default_value}")
            else:
                new_path_parts.append(part)
        else:
            if part == target_param:
                new_path_parts.append(f"{part}={default_value}")
            else:
                new_path_parts.append(part)
    new_params = ";".join(new_path_parts)

    # Rebuild URL
    return urlunparse(parsed._replace(query=new_query, params=new_params))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SQLi vulnerability detector via 5xx errors and presence of SQL error messages.", formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "urls",
        nargs="*",
        help="One or more target URLs to test. Provide as CLI positional arguments or via piped stdin. Example: hsqli http://example.com?id=1 OR echo \"http://example.com?id=1\" | hsqli"
    )
    parser.add_argument(
        "-P",
        "--parameters",
        nargs='+',                  # Accept one or more values
        help="Only test these parameter names for potential SQLi (case-sensitive). If not provided all parameters are tested. Example: --parameters ID name token"
    )
    parser.add_argument(
        "-p",
        "--proxy",
        help="Optional proxy URL to route requests through. Example: --proxy http://127.0.0.1:9090"
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Enable debug mode."
    )
    parser.add_argument(
        "-T",
        "--threads",
        type=int,
        default=10,
        help="Number of concurrent worker threads to use (default: 10). Example: --threads 20"
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=10,
        help="Maximum seconds to wait for a response (default 10). Example: --timeout 10"
    )

    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    ## Collect URLs from CLI and from stdin if piped
    # Start with any URLs provided as positional arguments from CLI
    urls_value = list(args.urls)
    # If stdin is not a TTY, it means data was piped in
    if not sys.stdin.isatty():
        for line in sys.stdin:
            line = line.strip()
            if line:
                urls_value.append(line)

    if not urls_value:
        parser.error("No URLs provided (via args or piped input).")

    target_parameters_value = args.parameters
    proxy_url_value = args.proxy
    debug_mode = args.debug
    timeout_value = args.timeout
    threads_value = args.threads

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0",
        "Accept": "*/*",
        "Accept-Language": "en;q=0.5, *;q=0.1",
        "Accept-Encoding": "gzip, deflate, br"
    }

    def scan_url(url):
        # # for check for error presence throught status code, then check for error presence throught sql error present in mutated response
        # if target parameter(s) provided using --parameters, test for those specific parameters only
        if target_parameters_value:
            _, parameter_names = detect_paramters(url)

            for parameter_name in parameter_names:
                if parameter_name in target_parameters_value:
                    parameter_value = get_parameter_value(url=url, param_name=parameter_name)
                
                    # if the parameter didn't have a value, give that parameter the value 123
                    if parameter_value == "aprefix123asuffix":
                        # adds 123 value to specified parameter if its value is empty
                        url = replace_empty_url_param(url=url, target_param=parameter_name)

                    # -- Heuristic SQLi test THROUGH PRESENCE OF 5XX RESPONSE STATUS CODE
                    sqli_500_code = test_sqli_500(url=url, parameter_name=parameter_name, original_parameter_value=parameter_value, timeout=timeout_value, proxy_url=proxy_url_value, headers=headers)
                    # if test_sqli_500 doesn't return None
                    if sqli_500_code:
                        mutated_url, response_status_code = sqli_500_code
                        print(f"[+] Potential SQLi for URL: {url} in Parameter: {parameter_name}. Detection Reason: {response_status_code} response code. Mutated URL used for testing: {mutated_url}")

                    # -- Heuristic SQLi test THROUGH PRESENCE OF SQL ERRORS in response body
                    # Get baseline response
                    sqli_error_present, database, error_message, mutated_url =  test_sqli_error(url=url, parameter_name=parameter_name, original_parameter_value=parameter_value, timeout=timeout_value, proxy_url=proxy_url_value, headers=headers)
                    if sqli_error_present is True:
                        print(f"[+] Potential SQLi for URL: {url} in Parameter: {parameter_name}. Detection Reason: SQL error: '{error_message}' in response body (likely database: {database}). Mutated URL used for testing: {mutated_url}")

        # if target parameter(s) is not provided using --parameters, test for all parameters
        else:
            _, parameter_names = detect_paramters(url)

            for parameter_name in parameter_names:
                parameter_value = get_parameter_value(url=url, param_name=parameter_name)
                
                # if the parameter didn't have a value, give that parameter the value 123
                if parameter_value == "aprefix123asuffix":
                    # adds 123 value to specified parameter if its value is empty
                    url = replace_empty_url_param(url=url, target_param=parameter_name)

                # -- Heuristic SQLi test THROUGH PRESENCE OF 5XX RESPONSE STATUS CODE
                sqli_500_code = test_sqli_500(url=url, parameter_name=parameter_name, original_parameter_value=parameter_value, timeout=timeout_value, proxy_url=proxy_url_value, headers=headers)
                # if test_sqli_500 doesn't return None
                if sqli_500_code:
                    mutated_url, response_status_code = sqli_500_code
                    print(f"[+] Potential SQLi for URL: {url} in Parameter: {parameter_name}. Detection Reason: {response_status_code} response code. Mutated URL used for testing: {mutated_url}")

                # -- Heuristic SQLi test THROUGH PRESENCE OF SQL ERRORS in response body
                # Get baseline response
                sqli_error_present, database, error_message, mutated_url =  test_sqli_error(url=url, parameter_name=parameter_name, original_parameter_value=parameter_value, timeout=timeout_value, proxy_url=proxy_url_value, headers=headers)
                if sqli_error_present is True:
                    print(f"[+] Potential SQLi for URL: {url} in Parameter: {parameter_name}. Detection Reason: SQL error: '{error_message}' in response body (likely database: {database}). Mutated URL used for testing: {mutated_url}")


    MAX_PARALLEL = threads_value

    # Create a pool with up to 10 worker threads
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_PARALLEL) as executor:
        # executor.map will feed each url into scan_url, up to 10 at once
        for _ in executor.map(scan_url, urls_value):
            # scan_url prints its own findings, so we don't need to do anything here
            pass