# CSCE 3550 Project 1 - JWKS Server

## Overview

This project implements a basic JWKS server in Go. The server generates RSA key pairs, assigns each key a unique key ID (`kid`) and expiration time, publishes valid public keys through a JWKS endpoint, and creates signed JWTs through an authentication endpoint.

The project uses Go's standard library for the HTTP server, RSA key generation, SHA-256 hashing, JSON encoding, and Base64URL encoding.

## Endpoints

### GET `/.well-known/jwks.json`

Returns the public RSA keys that have not expired in JWKS format.

Expired keys are not included.

### POST `/auth`

Returns a signed JWT using the current valid RSA private key.

### POST `/auth?expired=true`

Returns a JWT signed using the expired RSA key. The JWT also contains an expiration time in the past.

## Running the Server

```bash
go run .
```

The server runs on:

```text
http://localhost:8080
```

## Testing

Run the unit tests with:

```bash
go test
```

Run the tests with coverage information using:

```bash
go test -cover
```

Run static analysis using:

```bash
go vet ./...
```

The project can also be linted using:

```bash
golangci-lint run
```

## Language

Go
