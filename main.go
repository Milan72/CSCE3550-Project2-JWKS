package main

import (
	"log"
	"net/http"
)

func main() {
	app, err := newServer()
	if err != nil {
		log.Fatalf(
			"could not create server: %v",
			err,
		)
	}

	defer func() {
		if err := app.close(); err != nil {
			log.Printf(
				"could not close server cleanly: %v",
				err,
			)
		}
	}()

	log.Println(
		"JWKS server running on http://localhost:8080",
	)

	if err := http.ListenAndServe(
		":8080",
		app.routes(),
	); err != nil {
		log.Fatal(err)
	}
}
