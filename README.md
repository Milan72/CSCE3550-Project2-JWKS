# CSCE 3550 Project 2 - JWKS Server

## Description

This project extends the JWKS server from Project 1 by storing RSA private keys in a SQLite database.

The server creates the database automatically when it starts. Each key has a database-generated key ID (`kid`) and an expiration timestamp. Private RSA keys are serialized in PKCS#1 PEM format before being stored in the database.

## Database

The SQLite database file is:

`totally_not_my_privateKeys.db`

The required table is:

```sql
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
);
```

Database values are supplied using query parameters rather than being concatenated into SQL statements.

## Endpoints

### GET `/.well-known/jwks.json`

Returns all non-expired public RSA keys in JWKS format.

Expired keys are not included.

### POST `/auth`

Returns an RS256-signed JWT using a valid private key read from the SQLite database.

### POST `/auth?expired=true`

Returns a JWT signed with an expired private key from the database.

Authentication is mocked for this assignment, so the supplied Basic Auth or JSON username and password do not need to be validated.

## Running the Server

```bash
go run .
```

The server listens on port `8080`.

## Testing

Run the test suite:

```bash
go test
```

Run the tests with coverage:

```bash
go test -cover
```

Run Go static analysis:

```bash
go vet ./...
```

Run the linter:

```bash
golangci-lint run --no-config
```

The test suite covers database creation and persistence, RSA key serialization, JWT signing, valid and expired keys, JWKS responses, HTTP methods, authentication request formats, and error handling.

## Language

Go
