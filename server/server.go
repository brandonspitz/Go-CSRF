package server

import (
	"log"
	"net/http"

	"github.com/brandonspitz/Go-CSRF/server/middleware" //imported package from within project
)

func StartServer(hostname string, port string) error { //server starting function requires host and port variables
	host := hostname + ":" + port

	log.Printf("Listening on: %s", host) //confirmation

	handler := middleware.NewHandler() //handler function

	http.Handle("/", handler)
	return http.ListenAndServe(host, nil) //return start
}
