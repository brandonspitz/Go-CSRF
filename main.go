package main

import (
	"log"

	"github.com/brandonspitz/Go-CSRF/db"
	"github.com/brandonspitz/Go-CSRF/server"
	"github.com/brandonspitz/Go-CSRF/server/middleware/myJWT" //imported packages from within project
)

var host = "localhost" //define host and port
var port = "9000"

func main() {
	db.InitDB() //initialize the databse

	jwtErr := myJWT.InitJWT() //initialize the JWT's
	if jwtErr != nil {
		log.Println("Error initializing the JWT's") //check for error
		log.Fatal(jwtErr)
	}

	serverErr := server.StartServer(host, port) //start the server with host and port
	if serverErr != nil {
		log.Println("Error starting the server") //check for error
		log.Fatal(serverErr)
	}
}
