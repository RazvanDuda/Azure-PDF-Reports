package output

import (
	"strings"
)

// ExtractRoleGUID extracts the GUID portion from a role definition ID path
func ExtractRoleGUID(roleDefID string) string {
	parts := strings.Split(roleDefID, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return roleDefID
}
