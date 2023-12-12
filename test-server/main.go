package main

import (
	"fmt"
	"net/http"
	"os"
)

var port = os.Getenv("PORT")

func main() {
	if port == "" {
		port = "8080"
	}

	addr := ":" + port

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("received request: %+v\n", r)
	})

	fmt.Printf("starting server: listening on %s\n", addr)
	http.ListenAndServe(addr, nil)
}
