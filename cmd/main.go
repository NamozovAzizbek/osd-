package cmd

import (
	"log"

	
	"github.com/casbin/casbin"
)

type authorizer struct {
	users    module.Users
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
