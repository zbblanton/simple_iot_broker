package main

import (
	//"encoding/base64"
	//"encoding/json"
	//"fmt"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
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

// type User struct {
// 	AgentIP    string
// 	AgentPort  string
// 	ServerKey  string
// 	AgentKey   string
// 	Containers map[string]string
// 	Status     string
// }

type Device struct {
	Name    string
	Channel map[string]string
}

// func checkAccess(user, password string) {

// }

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

		// does we have access to "/sensors/frontdoor/battery"?
		// We need read to one or all: "/sensors/**", "/sensors/frontdoor/*","/sensors/frontdoor/**", "/sensors/frontdoor/battery"
		granted := false

		splitPath := strings.Split(r.URL.Path, "/")
		splitPath = splitPath[1:] //Remove the first item which is blank
		fmt.Println(splitPath)
		fmt.Println(len(splitPath))

		//Read existing ACL if it exist
		aclRules := make(map[string][]string)
		aclRulesBytes, err := ds.Get("auth/acl/" + user)
		// if deviceBytes == nil {
		// 	http.Error(w, "Could not find device", http.StatusNotFound)
		// 	return
		// }
		err = json.Unmarshal(aclRulesBytes, &aclRules)
		if err != nil {
			fmt.Println("its right here right")
			fmt.Println(err)
			http.Error(w, "Could not unmarshal data", http.StatusInternalServerError)
			return
		}

		//for aclPath, permissions := range aclRules {
		for aclPath, permissions := range aclRules {
			match := false
			fmt.Println(permissions)
			splitACLPath := strings.Split(aclPath, "/")
			fmt.Println(splitACLPath)
			for pathIndex, pathElement := range splitACLPath {
				if pathElement == "**" {
					match = true
					break
					//} else if pathElement == "*" && len(splitPath)-1 == pathIndex {
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
				fmt.Println("Match found")
				for _, method := range permissions {
					if r.Method == method {
						granted = true
						break
					}
				}
				//break
			}

			if granted {
				break
			}
		}

		if !granted {
			http.Error(w, "Authorization failed", http.StatusUnauthorized)
			return
		}
		//fmt.Println(match)

		// for each key { //x is access path we are testing, y is current acl we are testing
		// 	split x by /
		// 	for each element
		// 		if y[0] == "**"
		// 			granted = true
		// 			break
		// 		else if y[0] == "*" and last x
		// 			granted = true
		// 			break
		// 		else if y[0] == x[0] // or y[0] == "*"
		// 			continue
		// 		else if y[0] == x[0] && last x && last y
		// 			granted = true
		// 			break
		// 		else if y[0] == "*"
		// 			continue
		// 		else if len(x) - 1 == index
		// 			break

		// 	if granted
		// 		break
		// }

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

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(device.Channel[channel])
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
	ds.Put("auth/acl/"+user, aclRulesBytes)
}

func main() {
	//Seed for token generation
	rand.Seed(time.Now().UnixNano())

	fmt.Println(generateTokenString())
	fmt.Println(generateTokenString())
	fmt.Println(generateTokenString())
	fmt.Println(generateTokenString())
	fmt.Println(generateTokenString())
	fmt.Println(generateTokenString())

	fmt.Println("Using file based datastore.")
	ds = &FileDataStore{Path: "data.db"}
	ds.Init()
	defer ds.Close()

	//tmp init stuff
	if ok, _ := ds.IfExist("broker/auth/token/admin"); !ok {
		//resp := Resp{false, "Cannot find container"}
		resp := "Hello"
		c1, err := json.Marshal(resp)
		if err != nil {
			fmt.Println(err)
		}

		ds.Put("broker/auth/token/admin", c1)
		//ds.Put("broker/auth/acl/admin", accountBytes)
	}

	var testme string
	workerBytes, _ := ds.Get("broker/auth/token/admin")
	json.Unmarshal(workerBytes, &testme)
	fmt.Println(testme)

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/", RootHandler)

	router.HandleFunc("/register", checkAccess(RegisterDeviceHandler))
	router.HandleFunc("/sensors/{sensor}", checkAccess(GetDeviceHandler))
	router.HandleFunc("/sensors/{sensor}/{channel}", checkAccess(GetDeviceChannelDataHandler))
	router.HandleFunc("/sensors/{sensor}/{channel}/set/{newValue}", checkAccess(SetDeviceChannelDataHandler))
	//router.HandleFunc("/sensors/{sensor}/{somethingchannel}/set", checkAccess(GetDevicechannelSensor))
	//router.HandleFunc("/sensors/{sensor}/contact", RootHandler)
	//router.HandleFunc("/sensors/{sensor}/status", RootHandler) //Dont think we need /status. just do it at the sensorName level
	//router.HandleFunc("/switch/{sensor}/battery", RootHandler)
	//router.HandleFunc("/switch/{sensor}/contact", RootHandler)
	//router.HandleFunc("/switch/{sensor}/status", RootHandler)
	//router.HandleFunc("/auth/token/create", RootHandler)
	router.HandleFunc("/auth/token/{user}", checkAccess(CreateTokenHandler)) //Maybe instead of create about just do a post to here
	//router.HandleFunc("/auth/acl/{user}", checkAccess(CreateACLRulesHandler))
	router.HandleFunc("/auth/acl/{user}", CreateACLRulesHandler)

	// {
	// 	"/sensor/**": "RW",
	// 	"/sensor/frontdoor/*": "RW",
	// 	"/sensor/frontdoor/battery": "R",
	// }

	// thing/sensors/battery
	// thing/switches/
	// Only a sensor broker for reading sensor data (will also need to set sensor data)
	// maybe have types: percentage, boolean, string, number
	// maybe for now only output raw text
	// to register:
	// {
	// 	name: frontdoor
	// 	channel: [
	// 		battery,
	// 		contact
	// 	]
	// }
	// // status?:
	// {
	// 	name: frontdoor
	// 	channel: {
	// 		battery: 70,
	// 		contact: open
	// 	}
	// }
	// Maybe do an bearer token so taht we can have a username:token and tokens can be looked up by username

	handler := cors.Default().Handler(router)

	//Setup server config
	server := &http.Server{
		//Addr:      serverIP + ":" + serverPort,
		Addr:    ":8888",
		Handler: handler,
	}

	//Start API server
	//err = server.ListenAndServeTLS(serverCert, serverKey)
	err := server.ListenAndServe()
	log.Fatal(err)
}
