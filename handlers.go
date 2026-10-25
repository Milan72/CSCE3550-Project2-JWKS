package main

import (
	"encoding/json"
	"log"
	"net/http"
)

// routes builds the HTTP routing table for the JWKS server.
func (s *server) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/jwks.json", s.jwksHandler)
	mux.HandleFunc("/auth", s.authHandler)

	return mux
}

// writeInternalError records the internal failure server-side while returning
// a generic response to the client.
func writeInternalError(
	w http.ResponseWriter,
	operation string,
	err error,
) {
	log.Printf("%s: %v", operation, err)

	http.Error(
		w,
		"internal server error",
		http.StatusInternalServerError,
	)
}

// jwksHandler returns every currently valid public RSA key in JWKS format.
func (s *server) jwksHandler(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)

		http.Error(
			w,
			"method not allowed",
			http.StatusMethodNotAllowed,
		)
		return
	}

	keys, err := getValidKeys(s.db)
	if err != nil {
		writeInternalError(
			w,
			"retrieve valid JWKS keys",
			err,
		)
		return
	}

	publicKeys := make([]jwk, 0, len(keys))

	for _, key := range keys {
		publicKeys = append(
			publicKeys,
			publicKeyToJWK(key),
		)
	}

	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	if err := json.NewEncoder(w).Encode(jwks{
		Keys: publicKeys,
	}); err != nil {
		log.Printf(
			"write JWKS response: %v",
			err,
		)
	}
}

// authHandler creates a JWT with either a valid or expired database key.
//
// Authentication itself is intentionally mocked for this assignment. Basic
// authentication headers and JSON credentials may be supplied, but the
// username and password are not validated.
func (s *server) authHandler(
	w http.ResponseWriter,
	r *http.Request,
) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)

		http.Error(
			w,
			"method not allowed",
			http.StatusMethodNotAllowed,
		)
		return
	}

	var (
		key storedKey
		err error
	)

	if _, expiredRequested :=
		r.URL.Query()["expired"]; expiredRequested {
		key, err = getExpiredKey(s.db)
	} else {
		key, err = getValidKey(s.db)
	}

	if err != nil {
		writeInternalError(
			w,
			"retrieve JWT signing key",
			err,
		)
		return
	}

	token, err := createJWT(key)
	if err != nil {
		writeInternalError(
			w,
			"create signed JWT",
			err,
		)
		return
	}

	w.Header().Set(
		"Content-Type",
		"application/jwt",
	)

	if _, err := w.Write([]byte(token)); err != nil {
		log.Printf(
			"write JWT response: %v",
			err,
		)
	}
}
