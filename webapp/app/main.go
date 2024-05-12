package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func main() {
	log.Printf("sdfsdfsd")
	read()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Add("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Write([]byte("This is an example server.\n"))
	})
	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS10,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}
	srv := &http.Server{
		Addr:         ":8585",
		Handler:      mux,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}
	log.Fatal(srv.ListenAndServeTLS("/home/ca/certs/server.crt", "/home/ca/certs/server.key"))
}

func read() {
	files, err := ioutil.ReadDir("/home")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Files in directory:")
	for _, file := range files {
		fmt.Println(file.Name())
	}

}
