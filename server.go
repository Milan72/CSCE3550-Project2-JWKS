package main

import (
	"database/sql"
	"fmt"
)

// server owns the resources shared by the HTTP handlers.
// It is intentionally unexported because this package is the complete
// application rather than a reusable public library.
type server struct {
	db *sql.DB
}

// newServer opens the application's SQLite database and ensures the signing
// keys required by the assignment are available.
func newServer() (*server, error) {
	db, err := openDatabase(databaseFile)
	if err != nil {
		return nil, fmt.Errorf(
			"initialize database: %w",
			err,
		)
	}

	if err := ensureRequiredKeys(db); err != nil {
		closeErr := db.Close()

		if closeErr != nil {
			return nil, fmt.Errorf(
				"initialize signing keys: %w; close database: %v",
				err,
				closeErr,
			)
		}

		return nil, fmt.Errorf(
			"initialize signing keys: %w",
			err,
		)
	}

	return &server{
		db: db,
	}, nil
}

// close releases the database connection owned by the application.
func (s *server) close() error {
	if s.db == nil {
		return nil
	}

	if err := s.db.Close(); err != nil {
		return fmt.Errorf(
			"close database: %w",
			err,
		)
	}

	return nil
}
