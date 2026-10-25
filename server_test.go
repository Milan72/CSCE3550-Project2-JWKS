package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// newTestDatabase creates an isolated SQLite database for a test.
func newTestDatabase(t *testing.T) *sql.DB {
	t.Helper()

	filename := filepath.Join(
		t.TempDir(),
		"test_keys.db",
	)

	db, err := openDatabase(filename)
	if err != nil {
		t.Fatalf(
			"could not open test database: %v",
			err,
		)
	}

	if err := ensureRequiredKeys(db); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			t.Errorf(
				"could not close database after setup failure: %v",
				closeErr,
			)
		}

		t.Fatalf(
			"could not initialize test keys: %v",
			err,
		)
	}

	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf(
				"could not close test database: %v",
				err,
			)
		}
	})

	return db
}

// decodeJWTPart decodes one Base64URL-encoded portion of a JWT.
func decodeJWTPart(
	t *testing.T,
	part string,
) map[string]any {
	t.Helper()

	data, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		t.Fatalf(
			"could not decode JWT section: %v",
			err,
		)
	}

	var value map[string]any

	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatalf(
			"could not decode JWT JSON: %v",
			err,
		)
	}

	return value
}

// verifyJWTSignature verifies an RS256 JWT using the supplied public key.
func verifyJWTSignature(
	t *testing.T,
	token string,
	publicKey *rsa.PublicKey,
) {
	t.Helper()

	parts := strings.Split(token, ".")

	if len(parts) != 3 {
		t.Fatalf(
			"expected three JWT sections, got %d",
			len(parts),
		)
	}

	signature, err :=
		base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf(
			"could not decode JWT signature: %v",
			err,
		)
	}

	signingInput := parts[0] + "." + parts[1]
	hash := sha256.Sum256([]byte(signingInput))

	if err := rsa.VerifyPKCS1v15(
		publicKey,
		crypto.SHA256,
		hash[:],
		signature,
	); err != nil {
		t.Fatalf(
			"JWT signature verification failed: %v",
			err,
		)
	}
}

func TestDatabaseSetup(t *testing.T) {
	db := newTestDatabase(t)

	var count int

	err := db.QueryRow(
		"SELECT COUNT(*) FROM keys",
	).Scan(&count)
	if err != nil {
		t.Fatalf(
			"could not count database keys: %v",
			err,
		)
	}

	if count < 2 {
		t.Fatalf(
			"expected at least two keys, got %d",
			count,
		)
	}

	validKey, err := getValidKey(db)
	if err != nil {
		t.Fatalf(
			"could not retrieve valid key: %v",
			err,
		)
	}

	if !validKey.ExpiresAt.After(time.Now()) {
		t.Error(
			"valid key should expire in the future",
		)
	}

	expiredKey, err := getExpiredKey(db)
	if err != nil {
		t.Fatalf(
			"could not retrieve expired key: %v",
			err,
		)
	}

	if expiredKey.ExpiresAt.After(time.Now()) {
		t.Error(
			"expired key should expire in the past",
		)
	}

	if validKey.Kid == expiredKey.Kid {
		t.Error(
			"valid and expired keys should have different kids",
		)
	}
}

func TestPrivateKeySerialization(t *testing.T) {
	privateKey, err := rsa.GenerateKey(
		rand.Reader,
		1024,
	)
	if err != nil {
		t.Fatalf(
			"could not generate RSA key: %v",
			err,
		)
	}

	encoded := serializePrivateKey(privateKey)

	if !strings.Contains(
		string(encoded),
		"BEGIN RSA PRIVATE KEY",
	) {
		t.Error(
			"serialized key is not PKCS#1 PEM",
		)
	}

	decoded, err := deserializePrivateKey(encoded)
	if err != nil {
		t.Fatalf(
			"could not deserialize RSA key: %v",
			err,
		)
	}

	if privateKey.N.Cmp(decoded.N) != 0 {
		t.Error(
			"RSA modulus changed after serialization",
		)
	}

	if privateKey.E != decoded.E {
		t.Error(
			"RSA exponent changed after serialization",
		)
	}
}

func TestInvalidPrivateKeyData(t *testing.T) {
	t.Run("invalid PEM", func(t *testing.T) {
		_, err := deserializePrivateKey(
			[]byte("not a PEM key"),
		)

		if err == nil {
			t.Error(
				"expected invalid PEM data to return an error",
			)
		}
	})

	t.Run("invalid PKCS1 data", func(t *testing.T) {
		data := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: []byte("invalid key data"),
			},
		)

		_, err := deserializePrivateKey(data)

		if err == nil {
			t.Error(
				"expected invalid PKCS#1 data to return an error",
			)
		}
	})
}

func TestDatabasePersistence(t *testing.T) {
	filename := filepath.Join(
		t.TempDir(),
		"persistent.db",
	)

	db, err := openDatabase(filename)
	if err != nil {
		t.Fatalf(
			"could not create database: %v",
			err,
		)
	}

	if err := ensureRequiredKeys(db); err != nil {
		t.Fatalf(
			"could not initialize keys: %v",
			err,
		)
	}

	validBefore, err := getValidKey(db)
	if err != nil {
		t.Fatalf(
			"could not read valid key: %v",
			err,
		)
	}

	expiredBefore, err := getExpiredKey(db)
	if err != nil {
		t.Fatalf(
			"could not read expired key: %v",
			err,
		)
	}

	if err := db.Close(); err != nil {
		t.Fatalf(
			"could not close database: %v",
			err,
		)
	}

	db, err = openDatabase(filename)
	if err != nil {
		t.Fatalf(
			"could not reopen database: %v",
			err,
		)
	}

	validAfter, err := getValidKey(db)
	if err != nil {
		t.Fatalf(
			"could not read valid key after restart: %v",
			err,
		)
	}

	expiredAfter, err := getExpiredKey(db)
	if err != nil {
		t.Fatalf(
			"could not read expired key after restart: %v",
			err,
		)
	}

	if validBefore.Kid != validAfter.Kid {
		t.Error(
			"valid key was not persisted across database restart",
		)
	}

	if expiredBefore.Kid != expiredAfter.Kid {
		t.Error(
			"expired key was not persisted across database restart",
		)
	}

	if err := db.Close(); err != nil {
		t.Fatalf(
			"could not close reopened database: %v",
			err,
		)
	}
}

func TestValidKeysQuery(t *testing.T) {
	db := newTestDatabase(t)

	keys, err := getValidKeys(db)
	if err != nil {
		t.Fatalf(
			"could not retrieve valid keys: %v",
			err,
		)
	}

	if len(keys) == 0 {
		t.Fatal(
			"expected at least one valid key",
		)
	}

	for _, key := range keys {
		if !key.ExpiresAt.After(time.Now()) {
			t.Errorf(
				"expired key %d returned by valid-key query",
				key.Kid,
			)
		}
	}
}

func TestCreateValidJWT(t *testing.T) {
	db := newTestDatabase(t)

	key, err := getValidKey(db)
	if err != nil {
		t.Fatalf(
			"could not get valid key: %v",
			err,
		)
	}

	token, err := createJWT(key)
	if err != nil {
		t.Fatalf(
			"could not create JWT: %v",
			err,
		)
	}

	parts := strings.Split(token, ".")

	if len(parts) != 3 {
		t.Fatalf(
			"expected three JWT sections, got %d",
			len(parts),
		)
	}

	header := decodeJWTPart(
		t,
		parts[0],
	)

	payload := decodeJWTPart(
		t,
		parts[1],
	)

	expectedKid := strconv.FormatInt(
		key.Kid,
		10,
	)

	if header["kid"] != expectedKid {
		t.Errorf(
			"expected kid %s, got %v",
			expectedKid,
			header["kid"],
		)
	}

	if header["alg"] != "RS256" {
		t.Errorf(
			"expected RS256, got %v",
			header["alg"],
		)
	}

	if header["typ"] != "JWT" {
		t.Errorf(
			"expected JWT type, got %v",
			header["typ"],
		)
	}

	if payload["sub"] != "fake-user" {
		t.Errorf(
			"expected fake-user subject, got %v",
			payload["sub"],
		)
	}

	exp, ok := payload["exp"].(float64)
	if !ok {
		t.Fatal(
			"JWT exp claim was not numeric",
		)
	}

	if int64(exp) <= time.Now().Unix() {
		t.Error(
			"valid JWT should expire in the future",
		)
	}

	verifyJWTSignature(
		t,
		token,
		&key.PrivateKey.PublicKey,
	)
}

func TestCreateExpiredJWT(t *testing.T) {
	db := newTestDatabase(t)

	key, err := getExpiredKey(db)
	if err != nil {
		t.Fatalf(
			"could not get expired key: %v",
			err,
		)
	}

	token, err := createJWT(key)
	if err != nil {
		t.Fatalf(
			"could not create expired JWT: %v",
			err,
		)
	}

	parts := strings.Split(token, ".")

	payload := decodeJWTPart(
		t,
		parts[1],
	)

	exp, ok := payload["exp"].(float64)
	if !ok {
		t.Fatal(
			"JWT exp claim was not numeric",
		)
	}

	if int64(exp) > time.Now().Unix() {
		t.Error(
			"expired JWT should have past expiration",
		)
	}

	verifyJWTSignature(
		t,
		token,
		&key.PrivateKey.PublicKey,
	)
}

func TestJWTSigningError(t *testing.T) {
	badKey := storedKey{
		Kid: 1,
		PrivateKey: &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{
				N: rsaPublicModulusForTest(),
				E: 65537,
			},
		},
		ExpiresAt: time.Now().Add(time.Hour),
	}

	_, err := createJWT(badKey)

	if err == nil {
		t.Error(
			"expected invalid RSA private key to fail signing",
		)
	}
}

func TestJWTNilPrivateKey(t *testing.T) {
	key := storedKey{
		Kid:        1,
		PrivateKey: nil,
		ExpiresAt:  time.Now().Add(time.Hour),
	}

	_, err := createJWT(key)

	if err == nil {
		t.Error(
			"expected nil private key to return an error",
		)
	}
}

// rsaPublicModulusForTest returns a deliberately unusable RSA modulus.
func rsaPublicModulusForTest() *big.Int {
	return big.NewInt(3)
}

func TestPublicKeyToJWK(t *testing.T) {
	db := newTestDatabase(t)

	key, err := getValidKey(db)
	if err != nil {
		t.Fatalf(
			"could not get valid key: %v",
			err,
		)
	}

	result := publicKeyToJWK(key)

	if result.Kty != "RSA" {
		t.Errorf(
			"expected RSA, got %s",
			result.Kty,
		)
	}

	if result.Alg != "RS256" {
		t.Errorf(
			"expected RS256, got %s",
			result.Alg,
		)
	}

	if result.Use != "sig" {
		t.Errorf(
			"expected sig, got %s",
			result.Use,
		)
	}

	expectedKid := strconv.FormatInt(
		key.Kid,
		10,
	)

	if result.Kid != expectedKid {
		t.Errorf(
			"expected kid %s, got %s",
			expectedKid,
			result.Kid,
		)
	}

	if result.N == "" {
		t.Error(
			"JWK modulus should not be empty",
		)
	}

	if result.E == "" {
		t.Error(
			"JWK exponent should not be empty",
		)
	}
}

func TestJWKSEndpoint(t *testing.T) {
	db := newTestDatabase(t)

	app := &server{
		db: db,
	}

	request := httptest.NewRequest(
		http.MethodGet,
		"/.well-known/jwks.json",
		nil,
	)

	response := httptest.NewRecorder()

	app.routes().ServeHTTP(
		response,
		request,
	)

	if response.Code != http.StatusOK {
		t.Fatalf(
			"expected 200, got %d",
			response.Code,
		)
	}

	if response.Header().Get(
		"Content-Type",
	) != "application/json" {
		t.Errorf(
			"unexpected Content-Type: %s",
			response.Header().Get("Content-Type"),
		)
	}

	var body jwks

	if err := json.NewDecoder(
		response.Body,
	).Decode(&body); err != nil {
		t.Fatalf(
			"could not decode JWKS response: %v",
			err,
		)
	}

	if len(body.Keys) == 0 {
		t.Fatal(
			"JWKS should contain a valid key",
		)
	}

	expiredKey, err := getExpiredKey(db)
	if err != nil {
		t.Fatalf(
			"could not retrieve expired key: %v",
			err,
		)
	}

	expiredKid := strconv.FormatInt(
		expiredKey.Kid,
		10,
	)

	for _, publicKey := range body.Keys {
		if publicKey.Kid == expiredKid {
			t.Error(
				"expired key must not appear in JWKS",
			)
		}
	}
}

func TestAuthEndpoint(t *testing.T) {
	db := newTestDatabase(t)

	app := &server{
		db: db,
	}

	request := httptest.NewRequest(
		http.MethodPost,
		"/auth",
		nil,
	)

	response := httptest.NewRecorder()

	app.routes().ServeHTTP(
		response,
		request,
	)

	if response.Code != http.StatusOK {
		t.Fatalf(
			"expected 200, got %d",
			response.Code,
		)
	}

	if response.Header().Get(
		"Content-Type",
	) != "application/jwt" {
		t.Errorf(
			"unexpected Content-Type: %s",
			response.Header().Get("Content-Type"),
		)
	}

	token := strings.TrimSpace(
		response.Body.String(),
	)

	key, err := getValidKey(db)
	if err != nil {
		t.Fatalf(
			"could not retrieve valid key: %v",
			err,
		)
	}

	verifyJWTSignature(
		t,
		token,
		&key.PrivateKey.PublicKey,
	)
}

func TestExpiredAuthEndpoint(t *testing.T) {
	db := newTestDatabase(t)

	app := &server{
		db: db,
	}

	request := httptest.NewRequest(
		http.MethodPost,
		"/auth?expired=true",
		nil,
	)

	response := httptest.NewRecorder()

	app.routes().ServeHTTP(
		response,
		request,
	)

	if response.Code != http.StatusOK {
		t.Fatalf(
			"expected 200, got %d",
			response.Code,
		)
	}

	key, err := getExpiredKey(db)
	if err != nil {
		t.Fatalf(
			"could not retrieve expired key: %v",
			err,
		)
	}

	token := strings.TrimSpace(
		response.Body.String(),
	)

	verifyJWTSignature(
		t,
		token,
		&key.PrivateKey.PublicKey,
	)

	parts := strings.Split(
		token,
		".",
	)

	payload := decodeJWTPart(
		t,
		parts[1],
	)

	exp, ok := payload["exp"].(float64)
	if !ok {
		t.Fatal(
			"JWT exp claim was not numeric",
		)
	}

	if int64(exp) > time.Now().Unix() {
		t.Error(
			"expected JWT to be expired",
		)
	}
}

func TestExpiredParameterPresence(t *testing.T) {
	db := newTestDatabase(t)

	app := &server{
		db: db,
	}

	request := httptest.NewRequest(
		http.MethodPost,
		"/auth?expired",
		nil,
	)

	response := httptest.NewRecorder()

	app.routes().ServeHTTP(
		response,
		request,
	)

	if response.Code != http.StatusOK {
		t.Fatalf(
			"expected 200, got %d",
			response.Code,
		)
	}

	parts := strings.Split(
		strings.TrimSpace(
			response.Body.String(),
		),
		".",
	)

	if len(parts) != 3 {
		t.Fatalf(
			"expected three JWT sections, got %d",
			len(parts),
		)
	}

	header := decodeJWTPart(
		t,
		parts[0],
	)

	expiredKey, err := getExpiredKey(db)
	if err != nil {
		t.Fatalf(
			"could not retrieve expired key: %v",
			err,
		)
	}

	expectedKid := strconv.FormatInt(
		expiredKey.Kid,
		10,
	)

	if header["kid"] != expectedKid {
		t.Error(
			"expired query parameter should select expired key",
		)
	}
}

func TestBasicAuthRequest(t *testing.T) {
	db := newTestDatabase(t)

	app := &server{
		db: db,
	}

	request := httptest.NewRequest(
		http.MethodPost,
		"/auth",
		nil,
	)

	request.SetBasicAuth(
		"userABC",
		"password123",
	)

	response := httptest.NewRecorder()

	app.routes().ServeHTTP(
		response,
		request,
	)

	if response.Code != http.StatusOK {
		t.Fatalf(
			"expected Basic Auth request to return 200, got %d",
			response.Code,
		)
	}
}

func TestJSONAuthRequest(t *testing.T) {
	db := newTestDatabase(t)

	app := &server{
		db: db,
	}

	body := strings.NewReader(
		`{"username":"userABC","password":"password123"}`,
	)

	request := httptest.NewRequest(
		http.MethodPost,
		"/auth",
		body,
	)

	request.Header.Set(
		"Content-Type",
		"application/json",
	)

	response := httptest.NewRecorder()

	app.routes().ServeHTTP(
		response,
		request,
	)

	if response.Code != http.StatusOK {
		t.Fatalf(
			"expected JSON auth request to return 200, got %d",
			response.Code,
		)
	}
}

func TestHTTPMethods(t *testing.T) {
	db := newTestDatabase(t)

	app := &server{
		db: db,
	}

	t.Run("auth rejects GET", func(t *testing.T) {
		request := httptest.NewRequest(
			http.MethodGet,
			"/auth",
			nil,
		)

		response := httptest.NewRecorder()

		app.routes().ServeHTTP(
			response,
			request,
		)

		if response.Code != http.StatusMethodNotAllowed {
			t.Fatalf(
				"expected 405, got %d",
				response.Code,
			)
		}

		if response.Header().Get("Allow") != http.MethodPost {
			t.Errorf(
				"expected Allow POST, got %s",
				response.Header().Get("Allow"),
			)
		}
	})

	t.Run("JWKS rejects POST", func(t *testing.T) {
		request := httptest.NewRequest(
			http.MethodPost,
			"/.well-known/jwks.json",
			nil,
		)

		response := httptest.NewRecorder()

		app.routes().ServeHTTP(
			response,
			request,
		)

		if response.Code != http.StatusMethodNotAllowed {
			t.Fatalf(
				"expected 405, got %d",
				response.Code,
			)
		}

		if response.Header().Get("Allow") != http.MethodGet {
			t.Errorf(
				"expected Allow GET, got %s",
				response.Header().Get("Allow"),
			)
		}
	})
}

func TestAuthWithoutSuitableKey(t *testing.T) {
	filename := filepath.Join(
		t.TempDir(),
		"empty.db",
	)

	db, err := openDatabase(filename)
	if err != nil {
		t.Fatalf(
			"could not open database: %v",
			err,
		)
	}

	app := &server{
		db: db,
	}

	request := httptest.NewRequest(
		http.MethodPost,
		"/auth",
		nil,
	)

	response := httptest.NewRecorder()

	app.routes().ServeHTTP(
		response,
		request,
	)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf(
			"expected 500, got %d",
			response.Code,
		)
	}

	if err := db.Close(); err != nil {
		t.Fatalf(
			"could not close empty database: %v",
			err,
		)
	}
}

func TestHandlerDatabaseErrors(t *testing.T) {
	filename := filepath.Join(
		t.TempDir(),
		"closed.db",
	)

	db, err := openDatabase(filename)
	if err != nil {
		t.Fatalf(
			"could not open database: %v",
			err,
		)
	}

	if err := db.Close(); err != nil {
		t.Fatalf(
			"could not close database: %v",
			err,
		)
	}

	app := &server{
		db: db,
	}

	t.Run("JWKS database failure", func(t *testing.T) {
		request := httptest.NewRequest(
			http.MethodGet,
			"/.well-known/jwks.json",
			nil,
		)

		response := httptest.NewRecorder()

		app.routes().ServeHTTP(
			response,
			request,
		)

		if response.Code != http.StatusInternalServerError {
			t.Fatalf(
				"expected 500, got %d",
				response.Code,
			)
		}

		if !strings.Contains(
			response.Body.String(),
			"internal server error",
		) {
			t.Error(
				"expected generic internal error response",
			)
		}
	})

	t.Run("auth database failure", func(t *testing.T) {
		request := httptest.NewRequest(
			http.MethodPost,
			"/auth",
			nil,
		)

		response := httptest.NewRecorder()

		app.routes().ServeHTTP(
			response,
			request,
		)

		if response.Code != http.StatusInternalServerError {
			t.Fatalf(
				"expected 500, got %d",
				response.Code,
			)
		}

		if !strings.Contains(
			response.Body.String(),
			"internal server error",
		) {
			t.Error(
				"expected generic internal error response",
			)
		}
	})
}

func TestDatabaseErrorPaths(t *testing.T) {
	t.Run("invalid database path", func(t *testing.T) {
		filename := filepath.Join(
			t.TempDir(),
			"missing-directory",
			"database.db",
		)

		db, err := openDatabase(filename)

		if err == nil {
			if db != nil {
				if closeErr := db.Close(); closeErr != nil {
					t.Errorf(
						"could not close unexpected database: %v",
						closeErr,
					)
				}
			}

			t.Fatal(
				"expected invalid database path to fail",
			)
		}
	})

	t.Run("valid key missing", func(t *testing.T) {
		filename := filepath.Join(
			t.TempDir(),
			"empty-valid.db",
		)

		db, err := openDatabase(filename)
		if err != nil {
			t.Fatalf(
				"could not open database: %v",
				err,
			)
		}

		_, err = getValidKey(db)
		if err == nil {
			t.Error(
				"expected missing valid key to return an error",
			)
		}

		if err := db.Close(); err != nil {
			t.Fatalf(
				"could not close database: %v",
				err,
			)
		}
	})

	t.Run("expired key missing", func(t *testing.T) {
		filename := filepath.Join(
			t.TempDir(),
			"empty-expired.db",
		)

		db, err := openDatabase(filename)
		if err != nil {
			t.Fatalf(
				"could not open database: %v",
				err,
			)
		}

		_, err = getExpiredKey(db)
		if err == nil {
			t.Error(
				"expected missing expired key to return an error",
			)
		}

		if err := db.Close(); err != nil {
			t.Fatalf(
				"could not close database: %v",
				err,
			)
		}
	})

	t.Run("ensure keys on closed database", func(t *testing.T) {
		filename := filepath.Join(
			t.TempDir(),
			"closed-ensure.db",
		)

		db, err := openDatabase(filename)
		if err != nil {
			t.Fatalf(
				"could not open database: %v",
				err,
			)
		}

		if err := db.Close(); err != nil {
			t.Fatalf(
				"could not close database: %v",
				err,
			)
		}

		if err := ensureRequiredKeys(db); err == nil {
			t.Error(
				"expected closed database to return an error",
			)
		}
	})

	t.Run("invalid stored private key", func(t *testing.T) {
		filename := filepath.Join(
			t.TempDir(),
			"invalid-key.db",
		)

		db, err := openDatabase(filename)
		if err != nil {
			t.Fatalf(
				"could not open database: %v",
				err,
			)
		}

		_, err = db.Exec(
			`INSERT INTO keys (key, exp)
			 VALUES (?, ?)`,
			[]byte("invalid key data"),
			time.Now().Add(time.Hour).Unix(),
		)
		if err != nil {
			t.Fatalf(
				"could not insert invalid test key: %v",
				err,
			)
		}

		_, err = getValidKeys(db)
		if err == nil {
			t.Error(
				"expected invalid stored key to return an error",
			)
		}

		if err := db.Close(); err != nil {
			t.Fatalf(
				"could not close database: %v",
				err,
			)
		}
	})
}

func TestNewServer(t *testing.T) {
	oldDirectory, err := os.Getwd()
	if err != nil {
		t.Fatalf(
			"could not determine working directory: %v",
			err,
		)
	}

	tempDirectory := t.TempDir()

	if err := os.Chdir(tempDirectory); err != nil {
		t.Fatalf(
			"could not enter temporary directory: %v",
			err,
		)
	}

	defer func() {
		if err := os.Chdir(oldDirectory); err != nil {
			t.Errorf(
				"could not restore working directory: %v",
				err,
			)
		}
	}()

	app, err := newServer()
	if err != nil {
		t.Fatalf(
			"newServer failed: %v",
			err,
		)
	}

	databasePath := filepath.Join(
		tempDirectory,
		databaseFile,
	)

	if _, err := os.Stat(databasePath); err != nil {
		t.Fatalf(
			"database file was not created: %v",
			err,
		)
	}

	if err := app.close(); err != nil {
		t.Fatalf(
			"could not close server: %v",
			err,
		)
	}
}

func TestServerCloseWithNilDatabase(t *testing.T) {
	app := &server{}

	if err := app.close(); err != nil {
		t.Fatalf(
			"closing server with nil database failed: %v",
			err,
		)
	}
}
