package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

const (
	databaseFile    = "totally_not_my_privateKeys.db"
	databaseTimeout = 2 * time.Second
)

// storedKey represents an RSA private key loaded from the keys table.
// The database-generated kid is also used as the JWT and JWK key identifier.
type storedKey struct {
	Kid        int64
	PrivateKey *rsa.PrivateKey
	ExpiresAt  time.Time
}

// databaseContext creates a short-lived context for a single database
// operation. This prevents a stalled database call from blocking the server
// indefinitely.
func databaseContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(
		context.Background(),
		databaseTimeout,
	)
}

// openDatabase opens the SQLite database and creates the required keys table
// if it does not already exist.
func openDatabase(filename string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", filename)
	if err != nil {
		return nil, fmt.Errorf(
			"open database: %w",
			err,
		)
	}

	pingContext, cancelPing := databaseContext()
	err = db.PingContext(pingContext)
	cancelPing()

	if err != nil {
		closeErr := db.Close()

		if closeErr != nil {
			return nil, fmt.Errorf(
				"connect to database: %w; close database: %v",
				err,
				closeErr,
			)
		}

		return nil, fmt.Errorf(
			"connect to database: %w",
			err,
		)
	}

	const createTable = `
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)`

	createContext, cancelCreate := databaseContext()

	_, err = db.ExecContext(
		createContext,
		createTable,
	)

	cancelCreate()

	if err != nil {
		closeErr := db.Close()

		if closeErr != nil {
			return nil, fmt.Errorf(
				"create keys table: %w; close database: %v",
				err,
				closeErr,
			)
		}

		return nil, fmt.Errorf(
			"create keys table: %w",
			err,
		)
	}

	return db, nil
}

// serializePrivateKey converts an RSA private key to PKCS#1 PEM data so it
// can be stored as a SQLite BLOB.
func serializePrivateKey(
	privateKey *rsa.PrivateKey,
) []byte {
	keyBytes := x509.MarshalPKCS1PrivateKey(
		privateKey,
	)

	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: keyBytes,
		},
	)
}

// deserializePrivateKey converts stored PKCS#1 PEM data back into an RSA
// private key.
func deserializePrivateKey(
	data []byte,
) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)

	if block == nil {
		return nil, errors.New(
			"could not decode PEM private key",
		)
	}

	privateKey, err :=
		x509.ParsePKCS1PrivateKey(block.Bytes)

	if err != nil {
		return nil, fmt.Errorf(
			"parse RSA private key: %w",
			err,
		)
	}

	return privateKey, nil
}

// insertKey generates a 2048-bit RSA private key and persists it using a
// parameterized INSERT statement.
func insertKey(
	db *sql.DB,
	expiresAt time.Time,
) error {
	privateKey, err := rsa.GenerateKey(
		rand.Reader,
		2048,
	)

	if err != nil {
		return fmt.Errorf(
			"generate RSA key: %w",
			err,
		)
	}

	serializedKey := serializePrivateKey(
		privateKey,
	)

	ctx, cancel := databaseContext()

	_, err = db.ExecContext(
		ctx,
		"INSERT INTO keys (key, exp) VALUES (?, ?)",
		serializedKey,
		expiresAt.Unix(),
	)

	cancel()

	if err != nil {
		return fmt.Errorf(
			"insert key into database: %w",
			err,
		)
	}

	return nil
}

// getValidKey returns one private key whose expiration is still in the future.
func getValidKey(
	db *sql.DB,
) (storedKey, error) {
	ctx, cancel := databaseContext()
	defer cancel()

	row := db.QueryRowContext(
		ctx,
		`SELECT kid, key, exp
		 FROM keys
		 WHERE exp > ?
		 ORDER BY exp DESC
		 LIMIT 1`,
		time.Now().Unix(),
	)

	key, err := scanStoredKey(row)
	if err != nil {
		return storedKey{}, fmt.Errorf(
			"get valid key: %w",
			err,
		)
	}

	return key, nil
}

// getExpiredKey returns one private key whose expiration is now or earlier.
func getExpiredKey(
	db *sql.DB,
) (storedKey, error) {
	ctx, cancel := databaseContext()
	defer cancel()

	row := db.QueryRowContext(
		ctx,
		`SELECT kid, key, exp
		 FROM keys
		 WHERE exp <= ?
		 ORDER BY exp DESC
		 LIMIT 1`,
		time.Now().Unix(),
	)

	key, err := scanStoredKey(row)
	if err != nil {
		return storedKey{}, fmt.Errorf(
			"get expired key: %w",
			err,
		)
	}

	return key, nil
}

// getValidKeys returns every currently valid key for publication through
// the JWKS endpoint.
func getValidKeys(
	db *sql.DB,
) ([]storedKey, error) {
	ctx, cancel := databaseContext()
	defer cancel()

	rows, err := db.QueryContext(
		ctx,
		`SELECT kid, key, exp
		 FROM keys
		 WHERE exp > ?
		 ORDER BY kid`,
		time.Now().Unix(),
	)

	if err != nil {
		return nil, fmt.Errorf(
			"query valid keys: %w",
			err,
		)
	}

	var keys []storedKey

	for rows.Next() {
		var (
			kid     int64
			keyData []byte
			exp     int64
		)

		if err := rows.Scan(
			&kid,
			&keyData,
			&exp,
		); err != nil {
			if closeErr := rows.Close(); closeErr != nil {
				return nil, fmt.Errorf(
					"scan valid key: %w; close rows: %v",
					err,
					closeErr,
				)
			}

			return nil, fmt.Errorf(
				"scan valid key: %w",
				err,
			)
		}

		privateKey, err :=
			deserializePrivateKey(keyData)

		if err != nil {
			if closeErr := rows.Close(); closeErr != nil {
				return nil, fmt.Errorf(
					"decode key %d: %w; close rows: %v",
					kid,
					err,
					closeErr,
				)
			}

			return nil, fmt.Errorf(
				"decode key %d: %w",
				kid,
				err,
			)
		}

		keys = append(
			keys,
			storedKey{
				Kid:        kid,
				PrivateKey: privateKey,
				ExpiresAt:  time.Unix(exp, 0),
			},
		)
	}

	if err := rows.Err(); err != nil {
		if closeErr := rows.Close(); closeErr != nil {
			return nil, fmt.Errorf(
				"iterate valid keys: %w; close rows: %v",
				err,
				closeErr,
			)
		}

		return nil, fmt.Errorf(
			"iterate valid keys: %w",
			err,
		)
	}

	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf(
			"close valid key rows: %w",
			err,
		)
	}

	return keys, nil
}

// scanStoredKey converts a single database row into a usable RSA signing key.
func scanStoredKey(
	row *sql.Row,
) (storedKey, error) {
	var (
		kid     int64
		keyData []byte
		exp     int64
	)

	if err := row.Scan(
		&kid,
		&keyData,
		&exp,
	); err != nil {
		return storedKey{}, fmt.Errorf(
			"scan key: %w",
			err,
		)
	}

	privateKey, err :=
		deserializePrivateKey(keyData)

	if err != nil {
		return storedKey{}, fmt.Errorf(
			"deserialize key %d: %w",
			kid,
			err,
		)
	}

	return storedKey{
		Kid:        kid,
		PrivateKey: privateKey,
		ExpiresAt:  time.Unix(exp, 0),
	}, nil
}

// ensureRequiredKeys makes sure the database contains at least one expired
// signing key and one key that remains valid for at least another hour.
//
// Existing keys are reused whenever possible so key material persists across
// application restarts.
func ensureRequiredKeys(
	db *sql.DB,
) error {
	now := time.Now()

	var expiredCount int

	expiredContext, cancelExpired :=
		databaseContext()

	err := db.QueryRowContext(
		expiredContext,
		"SELECT COUNT(*) FROM keys WHERE exp <= ?",
		now.Unix(),
	).Scan(&expiredCount)

	cancelExpired()

	if err != nil {
		return fmt.Errorf(
			"count expired keys: %w",
			err,
		)
	}

	if expiredCount == 0 {
		if err := insertKey(
			db,
			now.Add(-time.Hour),
		); err != nil {
			return fmt.Errorf(
				"create expired key: %w",
				err,
			)
		}
	}

	var validCount int

	validContext, cancelValid :=
		databaseContext()

	err = db.QueryRowContext(
		validContext,
		"SELECT COUNT(*) FROM keys WHERE exp >= ?",
		now.Add(time.Hour).Unix(),
	).Scan(&validCount)

	cancelValid()

	if err != nil {
		return fmt.Errorf(
			"count valid keys: %w",
			err,
		)
	}

	if validCount == 0 {
		if err := insertKey(
			db,
			now.Add(2*time.Hour),
		); err != nil {
			return fmt.Errorf(
				"create valid key: %w",
				err,
			)
		}
	}

	return nil
}
