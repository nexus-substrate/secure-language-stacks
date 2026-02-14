# SQL Security Scanning Tuning Guide

## Overview

This guide provides tuning recommendations for SQL security scanners to reduce false positives and improve detection accuracy.

## Semgrep Tuning

### False Positive Patterns

1. **Test/Migration Files**
```yaml
# In .semgrep.yml, add paths exclusion
paths:
  exclude:
    - "test/"
    - "tests/"
    - "migrations/"
    - "*_test.sql"
    - "seed_*.sql"
```

2. **Safe Dynamic SQL Patterns**
```yaml
# Allowlist for sp_executesql with parameters
rules:
  - id: sql-dynamic-sql-exec
    pattern-either:
      - pattern: sp_executesql @$SQL, @$PARAMS, ...
    pattern-not: sp_executesql @$SQL
    message: Dynamic SQL without parameters
```

3. **Known Safe Grants**
```yaml
# Allowlist for specific admin roles
rules:
  - id: sql-unsafe-grant-all
    pattern: GRANT ALL PRIVILEGES ON ... TO $USER
    metavariable-pattern:
      metavariable: $USER
      pattern-not-regex: '(admin|dba_role|root)'
```

### Custom Rules for SQL-Specific Risks

**Blind SQL Injection via Time-Based Delays**
```yaml
rules:
  - id: sql-time-based-injection
    pattern-either:
      - pattern: WAITFOR DELAY $TIME
      - pattern: SLEEP($TIME)
      - pattern: pg_sleep($TIME)
    message: Time-based delay function - potential blind SQL injection vector
    severity: WARNING
    metadata:
      cwe: CWE-89
```

**Mass Assignment via UPDATE**
```yaml
rules:
  - id: sql-mass-assignment
    pattern: |
      UPDATE $TABLE SET $COLUMNS WHERE id = $ID
    metavariable-pattern:
      metavariable: $COLUMNS
      pattern-regex: '.*,.*,.*'  # Multiple columns
    message: Mass assignment in UPDATE - ensure proper validation
    severity: WARNING
    metadata:
      cwe: CWE-915
```

**Information Disclosure via Error Messages**
```yaml
rules:
  - id: sql-verbose-error
    pattern-either:
      - pattern: RAISERROR($MSG, 16, 1) WITH LOG
      - pattern: RAISE EXCEPTION '%', $VAR
    message: Verbose error messages may leak schema information
    severity: WARNING
    metadata:
      cwe: CWE-209
```

## SQLFluff Tuning

### Dialect-Specific Configuration

**PostgreSQL**
```ini
[sqlfluff]
dialect = postgres
exclude_rules = L034  # Allow SELECT * in views
```

**MySQL**
```ini
[sqlfluff]
dialect = mysql
exclude_rules = L027  # Allow implicit table references
```

**SQL Server (T-SQL)**
```ini
[sqlfluff]
dialect = tsql
exclude_rules = L026  # Allow table aliases
```

### False Positive Suppression

**Stored Procedures**
```sql
-- noqa: disable=L001,L003
CREATE PROCEDURE complex_proc AS
BEGIN
    -- Complex logic exempt from line length/indentation rules
END;
-- noqa: enable=L001,L003
```

**Dynamic SQL (Explicitly Marked Safe)**
```sql
-- sqlfluff:disable=L045
DECLARE @sql NVARCHAR(MAX) = N'SELECT * FROM users WHERE id = @userId';
EXEC sp_executesql @sql, N'@userId INT', @userId = @SafeUserId;
-- sqlfluff:enable=L045
```

## Gitleaks Tuning

### SQL-Specific Allowlists

```toml
# In .gitleaks.toml
[[rules]]
id = "sql-connection-string"
description = "SQL Connection String"
regex = '''(?i)(server|data source|initial catalog|user id|password)\s*=\s*[^\s;]+'''

[rules.allowlist]
paths = [
    '''migrations/.*''',
    '''test/.*''',
    '''.*\.example\.sql'''
]
regexes = [
    '''(?i)password\s*=\s*(localhost|127\.0\.0\.1|testpassword)'''
]
```

### Credential Detection Tuning

**Safe Test Credentials**
```toml
[[rules.allowlist]]
regexes = [
    '''(?i)user\s*=\s*(testuser|demouser|sa)''',
    '''(?i)password\s*=\s*(test123|password|admin)'''
]
paths = [
    '''test/'''
]
```

## Parameterized Query Best Practices

### PostgreSQL: Prepared Statements

```sql
-- DO: Named prepared statement
PREPARE user_query (INT) AS
    SELECT id, username, email FROM users WHERE id = $1;

EXECUTE user_query(123);

-- DO: Function with parameters
CREATE FUNCTION get_user(user_id INT)
RETURNS TABLE(id INT, username TEXT, email TEXT)
AS $$
BEGIN
    RETURN QUERY
    SELECT u.id, u.username, u.email
    FROM users u
    WHERE u.id = user_id;  -- Parameter binding
END;
$$ LANGUAGE plpgsql;
```

### MySQL: Prepared Statements

```sql
-- DO: Prepared statement
PREPARE stmt FROM 'SELECT * FROM users WHERE id = ?';
SET @user_id = 123;
EXECUTE stmt USING @user_id;
DEALLOCATE PREPARE stmt;
```

### SQL Server: sp_executesql

```sql
-- DO: Parameterized with sp_executesql
DECLARE @sql NVARCHAR(MAX) = N'SELECT * FROM users WHERE id = @userId AND status = @status';
DECLARE @params NVARCHAR(MAX) = N'@userId INT, @status VARCHAR(20)';

EXEC sp_executesql @sql, @params, @userId = 123, @status = 'active';

-- DON'T: String concatenation
DECLARE @sql NVARCHAR(MAX) = 'SELECT * FROM users WHERE id = ' + CAST(@userId AS NVARCHAR);
EXEC(@sql);  -- VULNERABLE
```

## Stored Procedure Security Patterns

### Input Validation

```sql
-- SQL Server: Whitelist validation
CREATE PROCEDURE GetUsersByRole
    @RoleName VARCHAR(50)
AS
BEGIN
    -- Validate input against whitelist
    IF @RoleName NOT IN ('admin', 'user', 'guest')
    BEGIN
        RAISERROR('Invalid role name', 16, 1);
        RETURN;
    END;

    -- Safe to use after validation
    SELECT id, username FROM users WHERE role = @RoleName;
END;
```

### Safe Dynamic Column Selection

```sql
-- PostgreSQL: Safe dynamic ORDER BY
CREATE FUNCTION get_users_sorted(sort_column TEXT)
RETURNS TABLE(id INT, username TEXT, email TEXT)
AS $$
BEGIN
    -- Validate sort column against whitelist
    IF sort_column NOT IN ('id', 'username', 'email', 'created_at') THEN
        RAISE EXCEPTION 'Invalid sort column';
    END IF;

    RETURN QUERY EXECUTE format(
        'SELECT id, username, email FROM users ORDER BY %I',
        sort_column  -- %I quotes identifier safely
    );
END;
$$ LANGUAGE plpgsql;
```

## Privilege Management

### Principle of Least Privilege

```sql
-- PostgreSQL: Minimal privileges
CREATE USER app_readonly;
GRANT CONNECT ON DATABASE myapp TO app_readonly;
GRANT USAGE ON SCHEMA public TO app_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_readonly;

-- SQL Server: Application role with minimal rights
CREATE ROLE app_role;
GRANT SELECT, INSERT, UPDATE ON dbo.orders TO app_role;
GRANT SELECT ON dbo.products TO app_role;
GRANT EXECUTE ON dbo.usp_CreateOrder TO app_role;

-- Add user to role
ALTER ROLE app_role ADD MEMBER app_user;
```

### Audit Privilege Escalation

```sql
-- PostgreSQL: Find users with GRANT OPTION
SELECT grantee, privilege_type, is_grantable
FROM information_schema.table_privileges
WHERE is_grantable = 'YES'
AND grantee NOT IN ('postgres', 'root');

-- SQL Server: Find users with elevated privileges
SELECT sp.name AS principal_name,
       sp.type_desc,
       spm.permission_name,
       spm.state_desc
FROM sys.database_permissions spm
JOIN sys.database_principals sp ON spm.grantee_principal_id = sp.principal_id
WHERE spm.state_desc = 'GRANT_WITH_GRANT_OPTION'
ORDER BY sp.name;
```

## Row-Level Security (RLS) Patterns

### PostgreSQL: Multi-Tenant RLS

```sql
-- Create policy for tenant isolation
ALTER TABLE orders ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_policy ON orders
FOR ALL
TO app_user
USING (tenant_id = current_setting('app.current_tenant_id')::INT);

-- Application sets tenant context
SET app.current_tenant_id = 123;
```

### SQL Server: User-Based Filtering

```sql
-- Security function
CREATE FUNCTION dbo.fn_user_filter(@UserId INT)
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN SELECT 1 AS is_accessible
WHERE @UserId = CAST(SESSION_CONTEXT(N'UserId') AS INT);

-- Security policy
CREATE SECURITY POLICY UserFilter
ADD FILTER PREDICATE dbo.fn_user_filter(user_id) ON dbo.orders,
ADD BLOCK PREDICATE dbo.fn_user_filter(user_id) ON dbo.orders AFTER INSERT;

ALTER SECURITY POLICY UserFilter WITH (STATE = ON);
```

## Encryption Patterns

### Column-Level Encryption (PostgreSQL)

```sql
-- Using pgcrypto extension
CREATE EXTENSION pgcrypto;

-- Encrypt sensitive data
CREATE TABLE customers (
    id SERIAL PRIMARY KEY,
    name TEXT,
    ssn BYTEA,  -- Encrypted column
    credit_card BYTEA
);

-- Insert encrypted data
INSERT INTO customers (name, ssn, credit_card)
VALUES (
    'John Doe',
    pgp_sym_encrypt('123-45-6789', 'encryption_key'),
    pgp_sym_encrypt('4111-1111-1111-1111', 'encryption_key')
);

-- Query decrypted data
SELECT name, pgp_sym_decrypt(ssn, 'encryption_key') AS ssn
FROM customers
WHERE id = 1;
```

### Always Encrypted (SQL Server)

```sql
-- Create column master key
CREATE COLUMN MASTER KEY CMK_Auto1
WITH (
    KEY_STORE_PROVIDER_NAME = 'MSSQL_CERTIFICATE_STORE',
    KEY_PATH = 'CurrentUser/My/certificate_thumbprint'
);

-- Create column encryption key
CREATE COLUMN ENCRYPTION KEY CEK_Auto1
WITH VALUES (
    COLUMN_MASTER_KEY = CMK_Auto1,
    ALGORITHM = 'RSA_OAEP',
    ENCRYPTED_VALUE = 0x016E...
);

-- Create table with encrypted columns
CREATE TABLE Customers (
    CustomerId INT PRIMARY KEY,
    SSN CHAR(11) ENCRYPTED WITH (
        COLUMN_ENCRYPTION_KEY = CEK_Auto1,
        ENCRYPTION_TYPE = DETERMINISTIC,
        ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256'
    ),
    CreditCard VARCHAR(20) ENCRYPTED WITH (
        COLUMN_ENCRYPTION_KEY = CEK_Auto1,
        ENCRYPTION_TYPE = RANDOMIZED,
        ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256'
    )
);
```

## Performance Considerations

### Scanner Execution Time

| Scanner     | Typical Duration (1000 SQL files) | CPU Usage |
| ----------- | --------------------------------- | --------- |
| Semgrep     | 20-40s                            | Medium    |
| SQLFluff    | 60-120s                           | High      |
| Gitleaks    | 10-20s                            | Low       |

### CI/CD Optimization

- Run scanners in parallel
- Use incremental scanning for PRs
- Cache SQLFluff templates
- Run full scans on main branch only
- Use `--exclude` patterns aggressively

## References

- PostgreSQL Security Best Practices: https://www.postgresql.org/docs/current/security.html
- MySQL Security Guide: https://dev.mysql.com/doc/refman/8.0/en/security.html
- SQL Server Security: https://learn.microsoft.com/en-us/sql/relational-databases/security/
- OWASP SQL Injection Prevention: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- CWE-89: SQL Injection: https://cwe.mitre.org/data/definitions/89.html
