package main

import (
	"github.com/sameer-gits/godojo/auth"
	"github.com/sameer-gits/godojo/routes"
)

func main() {
	auth.Auth()
	routes.AuthCallbackHandler()

}
