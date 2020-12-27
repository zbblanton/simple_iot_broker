package main

import (
	//"encoding/base64"
	//"encoding/json"
	//"fmt"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/cors"

	//"io/ioutil"
	"log"
	//"os"
)

const tokenCharset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}[]-_;<>?%$#@!*"

var ds DataStore

func RootHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hi there :)\n"))
}

type Device struct {
	Name    string
	Channel map[string]string
}

// https://gist.github.com/sambengtson/bc9f76331065f09e953f
func checkAccess(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok {
			http.Error(w, "Authorization failed", http.StatusUnauthorized)
			return
		}

		var token string
		tokenBytes, _ := ds.Get("broker/auth/token/" + user)
		json.Unmarshal(tokenBytes, &token)
		if token != pass {
			http.Error(w, "Authorization failed", http.StatusUnauthorized)
			return
		}

		granted := false                                //Assume access is not granted
		splitPath := strings.Split(r.URL.Path, "/")[1:] //Split AND remove the first item which is blank

		//Read existing ACL if it exist
		aclRules := make(map[string][]string)
		aclRulesBytes, err := ds.Get("broker/auth/acl/" + user)
		if aclRulesBytes == nil {
			http.Error(w, "Authorization failed", http.StatusUnauthorized)
			return
		}
		err = json.Unmarshal(aclRulesBytes, &aclRules)
		if err != nil {
			http.Error(w, "Could not unmarshal data", http.StatusInternalServerError)
			return
		}

		for aclPath, permissions := range aclRules {
			match := false
			splitACLPath := strings.Split(aclPath, "/")
			for pathIndex, pathElement := range splitACLPath {
				if pathElement == "**" {
					match = true
					break
				} else if pathElement == "*" {
					if len(splitPath)-1 == pathIndex && len(splitACLPath)-1 == pathIndex {
						match = true
						break
					}
					continue
				} else if pathElement == splitPath[pathIndex] {
					if len(splitPath)-1 == pathIndex && len(splitACLPath)-1 == pathIndex {
						match = true
						break
					} else if len(splitPath)-1 == pathIndex {
						break
					} else {
						continue
					}
				} else if pathElement != splitPath[pathIndex] {
					break
				}
			}

			if match {
				for _, method := range permissions {
					if r.Method == method {
						granted = true
						break
					}
				}
			}

			if granted {
				break
			}
		}

		if !granted {
			http.Error(w, "Authorization failed", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func RegisterDeviceHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	defer r.Body.Close()

	device := Device{}
	json.NewDecoder(r.Body).Decode(&device)

	deviceBytes, _ := json.Marshal(device)

	ds.Put("sensors/"+device.Name, deviceBytes)
}

func GetDeviceHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	defer r.Body.Close()

	vars := mux.Vars(r)
	sensor := vars["sensor"]

	var device Device
	deviceBytes, err := ds.Get("sensors/" + sensor)
	if deviceBytes == nil {
		http.Error(w, "Could not find device", http.StatusNotFound)
		return
	}

	err = json.Unmarshal(deviceBytes, &device)
	if err != nil {
		http.Error(w, "Could not unmarshal data", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(device)
	return
}

func GetDeviceChannelDataHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	defer r.Body.Close()

	vars := mux.Vars(r)
	sensor := vars["sensor"]
	channel := vars["channel"]

	var device Device
	deviceBytes, err := ds.Get("sensors/" + sensor)
	if deviceBytes == nil {
		http.Error(w, "Could not find device", http.StatusNotFound)
		return
	}

	err = json.Unmarshal(deviceBytes, &device)
	if err != nil {
		http.Error(w, "Could not unmarshal data", http.StatusInternalServerError)
		return
	}

	if _, ok := device.Channel[channel]; !ok {
		http.Error(w, "Could not find channel data for device", http.StatusNotFound)
		return
	}

	trimQuotes := strings.Trim(device.Channel[channel], "\"") //This could cause problems is the data actually should start and end with quotes
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(trimQuotes))
	return
}

func SetDeviceChannelDataHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	defer r.Body.Close()

	vars := mux.Vars(r)
	sensor := vars["sensor"]
	channel := vars["channel"]
	newValue := vars["newValue"]

	var device Device
	deviceBytes, err := ds.Get("sensors/" + sensor)
	if deviceBytes == nil {
		http.Error(w, "Could not find device", http.StatusNotFound)
		return
	}

	err = json.Unmarshal(deviceBytes, &device)
	if err != nil {
		http.Error(w, "Could not unmarshal data", http.StatusInternalServerError)
		return
	}

	if _, ok := device.Channel[channel]; !ok {
		http.Error(w, "Could not find channel data for device", http.StatusNotFound)
		return
	}

	device.Channel[channel] = newValue

	updatedDeviceBytes, _ := json.Marshal(device)

	ds.Put("sensors/"+device.Name, updatedDeviceBytes)

	w.WriteHeader(http.StatusOK)
}

func CreateTokenHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	defer r.Body.Close()

	vars := mux.Vars(r)
	user := vars["user"]

	token := generateTokenString()
	tokenBytes, _ := json.Marshal(token)
	ds.Put("broker/auth/token/"+user, tokenBytes)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(token)
	return
}

// https://www.calhoun.io/creating-random-strings-in-go/
func generateTokenString() string {
	b := make([]byte, 40)
	for i := range b {
		b[i] = tokenCharset[rand.Intn(len(tokenCharset))]
	}
	return string(b)
}

func CreateACLRulesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	defer r.Body.Close()

	vars := mux.Vars(r)
	user := vars["user"]

	aclRules := make(map[string][]string)
	json.NewDecoder(r.Body).Decode(&aclRules)

	aclRulesBytes, _ := json.Marshal(aclRules)
	ds.Put("broker/auth/acl/"+user, aclRulesBytes)
}

func main() {
	//Seed for token generation
	rand.Seed(time.Now().UnixNano())

	fmt.Println("Using file based datastore.")
	dbPath := os.Getenv("BROKER_DB_PATH")
	if dbPath == "" {
		dbPath = "data.db"
	}
	ds = &FileDataStore{Path: dbPath}
	ds.Init()
	defer ds.Close()

	//If admin token doesn't exist, create and print token out
	if ok, _ := ds.IfExist("broker/auth/token/admin"); !ok {
		t := generateTokenString()
		// fmt.Println("Please save this token, it will not be printed again.")
		// fmt.Println("Token for admin: " + t)
		tBytes, err := json.Marshal(t)
		if err != nil {
			fmt.Println(err)
		}

		trimQuotesToken := strings.Trim(t, "\"")
		err = ioutil.WriteFile("admin.token", []byte(trimQuotesToken), 0600)
		if err != nil {
			panic(err)
		}
		fmt.Println("Saved admin token as admin.token.")

		ds.Put("broker/auth/token/admin", tBytes)
	}
	//If admin ACL is not found then add it
	if ok, _ := ds.IfExist("broker/auth/acl/admin"); !ok {
		aclRules := make(map[string][]string)
		aclRules["**"] = []string{"GET", "POST"}
		aclRulesBytes, err := json.Marshal(aclRules)
		if err != nil {
			fmt.Println(err)
		}

		ds.Put("broker/auth/acl/admin", aclRulesBytes)
	}

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/", RootHandler)
	router.HandleFunc("/register", checkAccess(RegisterDeviceHandler))
	router.HandleFunc("/sensors/{sensor}", checkAccess(GetDeviceHandler))
	router.HandleFunc("/sensors/{sensor}/{channel}", checkAccess(GetDeviceChannelDataHandler))
	router.HandleFunc("/sensors/{sensor}/{channel}/set/{newValue}", checkAccess(SetDeviceChannelDataHandler))
	router.HandleFunc("/auth/token/{user}", checkAccess(CreateTokenHandler))
	router.HandleFunc("/auth/acl/{user}", checkAccess(CreateACLRulesHandler))

	handler := cors.Default().Handler(router)

	addr := os.Getenv("BROKER_HTTP_ADDR") //Blank means listen on all addresses
	port := os.Getenv("BROKER_HTTP_PORT")
	if port == "" {
		port = "8888"
	}
	fmt.Println("Listening on: " + addr + ":" + port)
	server := &http.Server{
		Addr:    addr + ":" + port,
		Handler: handler,
	}

	//Start server
	var err error
	serverCert := os.Getenv("BROKER_TLS_CERT_PATH")
	serverKey := os.Getenv("BROKER_TLS_KEY_PATH")
	if serverKey != "" && serverCert != "" {
		fmt.Println("TLS enabled.")
		err = server.ListenAndServeTLS(serverCert, serverKey)
	} else {
		err = server.ListenAndServe()
	}

	log.Fatal(err)
}
