package main

import (
	"net/http"

	"github.com/sameer-gits/godojo/auth"
	"github.com/sameer-gits/godojo/routes"
)

func main() {
	auth.Auth()

	server := routes.Server{}


	// Setup routes
	router := server.SetupRoutes()

	// Start server
	http.ListenAndServe(":3000", router)
}
