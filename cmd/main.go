package main

import (
	"log"
	"osd/pkg/authz"
	modul "osd/pkg/module"
	"osd/pkg/server"

	"github.com/casbin/casbin"
	"github.com/gorilla/mux"
)

type authorizer struct {
	users    modul.Users
	enforcer *casbin.Enforcer
}

func (a *authorizer) HasPermission(userID, action, asset string) bool {
	user, ok := a.users[userID]
	if !ok {
		// Unknown userID
		log.Print("Unknown user:", userID)
		return false
	}

	for _, role := range user.Roles {
		if a.enforcer.Enforce(role, asset, action) {
			return true
		}
	}

	return false
}

func main() {
	enforcer, err := casbin.NewEnforcerSafe("../casbin.conf", "../rbac_policy.csv")
	if err != nil {
		log.Fatal("Failed to create enforcer:", err)
	}

	users, err := modul.Load()
	if err != nil {
		log.Fatal("Failed to load users:", err)
	}

	router := mux.NewRouter()
	router.HandleFunc("/api/{asset}", server.Handler).Methods("GET", "POST", "DELETE")
	router.Use(
		authz.Middleware(&authorizer{users: users, enforcer: enforcer}),
	)

	server.Start(router)
}
