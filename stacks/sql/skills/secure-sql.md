# Secure SQL Development Skill

**Skill ID**: `secure-sql`
**Stack**: SQL
**Category**: Infrastructure/Database Security
**Compliance**: OWASP Top 10, CWE Top 25

## Overview

This skill provides secure development guidance for SQL databases including PostgreSQL, MySQL, SQL Server, and SQLite.

## Security Scanning Tools

| Tool      | Purpose           | Configuration                |
| --------- | ----------------- | ---------------------------- |
| Semgrep   | SAST              | `configs/.semgrep.yml`       |
| SQLFluff  | SQL Linting       | `configs/.sqlfluff`          |
| Gitleaks  | Secret Detection  | Shared config                |

## Key Security Principles

### 1. Parameterized Queries (Prevention of SQL Injection)

**DO:**
```sql
-- Using prepared statements (PostgreSQL/MySQL)
PREPARE user_query AS
SELECT * FROM users WHERE id = $1;

EXECUTE user_query(123);

-- Using sp_executesql (SQL Server)
DECLARE @sql NVARCHAR(MAX) = N'SELECT * FROM users WHERE id = @userId';
EXEC sp_executesql @sql, N'@userId INT', @userId = 123;
```

**DON'T:**
```sql
-- String concatenation - VULNERABLE
EXECUTE('SELECT * FROM users WHERE id = ' + @userId);

-- Dynamic SQL without parameters
DECLARE @sql NVARCHAR(MAX) = 'SELECT * FROM users WHERE name = ''' + @userName + '''';
EXEC(@sql);
```

### 2. Least Privilege Principle

**DO:**
```sql
-- Grant only necessary privileges
GRANT SELECT, INSERT ON orders TO order_app_user;

-- Revoke unnecessary privileges
REVOKE DELETE, DROP ON products FROM web_app_user;

-- Use roles for privilege management
CREATE ROLE readonly_role;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly_role;
GRANT readonly_role TO report_user;
```

**DON'T:**
```sql
-- NEVER grant all privileges
GRANT ALL PRIVILEGES ON *.* TO app_user;

-- NEVER use WITH GRANT OPTION for application users
GRANT SELECT ON users TO app_user WITH GRANT OPTION;

-- NEVER use wildcard grants
GRANT ALL ON *.* TO app_user@'%';
```

### 3. Stored Procedure Security

**DO:**
```sql
-- Parameterized stored procedure (SQL Server)
CREATE PROCEDURE GetUserById
    @UserId INT
AS
BEGIN
    SET NOCOUNT ON;

    SELECT id, username, email
    FROM users
    WHERE id = @UserId;
END;

-- SECURITY DEFINER with explicit schema (PostgreSQL)
CREATE FUNCTION get_user_by_id(user_id INT)
RETURNS TABLE(id INT, username TEXT, email TEXT)
SECURITY DEFINER
AS $$
BEGIN
    RETURN QUERY
    SELECT u.id, u.username, u.email
    FROM users u
    WHERE u.id = user_id;
END;
$$ LANGUAGE plpgsql;
```

**DON'T:**
```sql
-- Dynamic SQL in stored procedure - VULNERABLE
CREATE PROCEDURE SearchUsers
    @SearchTerm NVARCHAR(100)
AS
BEGIN
    DECLARE @sql NVARCHAR(MAX);
    SET @sql = 'SELECT * FROM users WHERE name LIKE ''%' + @SearchTerm + '%''';
    EXEC(@sql);
END;
```

### 4. Privilege Escalation Prevention

**DO:**
```sql
-- Review and audit privileges regularly
SELECT grantee, privilege_type, table_schema, table_name
FROM information_schema.table_privileges
WHERE grantee NOT IN ('root', 'postgres')
ORDER BY grantee, table_name;

-- Disable dangerous features
-- SQL Server
EXEC sp_configure 'xp_cmdshell', 0;
RECONFIGURE;

-- MySQL
SET GLOBAL local_infile = 0;
```

**DON'T:**
```sql
-- NEVER enable xp_cmdshell
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- NEVER use EXECUTE AS without validation
EXECUTE AS LOGIN = @UserSuppliedLogin;
```

### 5. Audit Logging

**DO:**
```sql
-- PostgreSQL: Enable audit logging
ALTER SYSTEM SET log_statement = 'mod';  -- Log all modifications
ALTER SYSTEM SET log_connections = 'on';
ALTER SYSTEM SET log_disconnections = 'on';

-- SQL Server: Enable audit
CREATE SERVER AUDIT SecurityAudit
TO FILE (FILEPATH = 'C:\AuditLogs\')
WITH (ON_FAILURE = CONTINUE);

CREATE DATABASE AUDIT SPECIFICATION UserDataAccess
FOR SERVER AUDIT SecurityAudit
ADD (SELECT, INSERT, UPDATE, DELETE ON dbo.users BY public);

ALTER DATABASE AUDIT SPECIFICATION UserDataAccess WITH (STATE = ON);
```

**DON'T:**
```sql
-- NEVER truncate audit logs
TRUNCATE TABLE audit_log;

-- NEVER disable auditing in production
ALTER DATABASE AUDIT SPECIFICATION UserDataAccess WITH (STATE = OFF);
```

### 6. Row-Level Security (RLS)

**DO:**
```sql
-- PostgreSQL: Row-level security
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;

CREATE POLICY user_documents_policy ON documents
FOR ALL
TO app_user
USING (owner_id = current_user_id());

-- SQL Server: Row-level security
CREATE FUNCTION dbo.fn_securitypredicate(@UserId INT)
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN SELECT 1 AS result
WHERE @UserId = USER_ID();

CREATE SECURITY POLICY UserDataFilter
ADD FILTER PREDICATE dbo.fn_securitypredicate(user_id) ON dbo.documents;
```

### 7. Encryption at Rest

**DO:**
```sql
-- PostgreSQL: Transparent Data Encryption (TDE) via pgcrypto
CREATE EXTENSION pgcrypto;

-- Encrypt sensitive columns
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username TEXT,
    ssn BYTEA DEFAULT NULL  -- Encrypted field
);

INSERT INTO users (username, ssn)
VALUES ('john', pgp_sym_encrypt('123-45-6789', 'encryption_key'));

-- SQL Server: Transparent Data Encryption
USE master;
CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'StrongPassword123!';
CREATE CERTIFICATE TDECert WITH SUBJECT = 'TDE Certificate';

USE AppDatabase;
CREATE DATABASE ENCRYPTION KEY
WITH ALGORITHM = AES_256
ENCRYPTION BY SERVER CERTIFICATE TDECert;

ALTER DATABASE AppDatabase SET ENCRYPTION ON;
```

## Common Vulnerabilities

| CWE       | Vulnerability                 | Semgrep Rule ID                |
| --------- | ----------------------------- | ------------------------------ |
| CWE-89    | SQL Injection                 | `sql-injection-concatenation`  |
| CWE-78    | OS Command Injection          | `sql-xp-cmdshell`              |
| CWE-250   | Excessive Privileges          | `sql-unsafe-grant-all`         |
| CWE-269   | Privilege Escalation          | `sql-grant-with-grant-option`  |
| CWE-732   | Incorrect Permissions         | `sql-wildcard-grant`           |
| CWE-521   | Weak Password                 | `sql-weak-password`            |
| CWE-311   | Missing Encryption            | `sql-no-encryption`            |
| CWE-117   | Log Tampering                 | `sql-truncate-audit-log`       |
| CWE-778   | Insufficient Logging          | `sql-disable-audit`            |
| CWE-22    | Path Traversal                | `sql-into-outfile`             |
| CWE-73    | External File Inclusion       | `sql-load-data-infile`         |

## Dynamic SQL Safety

### Safe Dynamic SQL Pattern

```sql
-- SQL Server: Safe dynamic SQL with sp_executesql
CREATE PROCEDURE SearchProducts
    @Category NVARCHAR(50),
    @MinPrice DECIMAL(10,2)
AS
BEGIN
    DECLARE @sql NVARCHAR(MAX);
    DECLARE @params NVARCHAR(MAX);

    SET @sql = N'SELECT id, name, price
                 FROM products
                 WHERE category = @cat
                 AND price >= @minPrice';

    SET @params = N'@cat NVARCHAR(50), @minPrice DECIMAL(10,2)';

    EXEC sp_executesql @sql, @params, @cat = @Category, @minPrice = @MinPrice;
END;
```

### PostgreSQL: Dynamic SQL with EXECUTE USING

```sql
CREATE FUNCTION search_products(cat TEXT, min_price NUMERIC)
RETURNS TABLE(id INT, name TEXT, price NUMERIC)
AS $$
BEGIN
    RETURN QUERY EXECUTE
        'SELECT id, name, price FROM products WHERE category = $1 AND price >= $2'
    USING cat, min_price;
END;
$$ LANGUAGE plpgsql;
```

## Database Hardening Checklist

- [ ] Disable `xp_cmdshell` (SQL Server)
- [ ] Disable `local_infile` (MySQL)
- [ ] Enable SSL/TLS connections
- [ ] Use strong password policies
- [ ] Implement network segmentation
- [ ] Enable audit logging
- [ ] Use row-level security where applicable
- [ ] Encrypt sensitive columns
- [ ] Enable Transparent Data Encryption (TDE)
- [ ] Regular security patches
- [ ] Principle of least privilege for all accounts
- [ ] Remove default/test accounts
- [ ] Disable unnecessary stored procedures (sp_OA*, sp_regread, etc.)

## CI/CD Integration

Use the provided pipelines:
- **Concourse**: `pipelines/concourse/pipeline.yml`
- **GitHub Actions**: `pipelines/github-actions/security.yml`

## References

- OWASP SQL Injection Prevention: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- CWE-89: SQL Injection: https://cwe.mitre.org/data/definitions/89.html
- PostgreSQL Security: https://www.postgresql.org/docs/current/security.html
- MySQL Security Guide: https://dev.mysql.com/doc/refman/8.0/en/security.html
- SQL Server Security: https://learn.microsoft.com/en-us/sql/relational-databases/security/

## Tuning Guide

See `tuning.md` for scanner-specific tuning and false positive management.
