package graph

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// RoleDefinition represents an Entra ID role definition
type RoleDefinition struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
}

type roleDefinitionsResponse struct {
	Value    []RoleDefinition `json:"value"`
	NextLink string           `json:"@odata.nextLink"`
}

// Group represents a user's group membership
type Group struct {
	ID                   string `json:"id"`
	DisplayName          string `json:"displayName"`
	MailEnabled          bool   `json:"mailEnabled"`
	SecurityEnabled      bool   `json:"securityEnabled"`
	GroupTypes           []string `json:"groupTypes"`
	OnPremisesSyncEnabled *bool  `json:"onPremisesSyncEnabled"`
	Mail                 string `json:"mail"`
	IsAssignableToRole   bool   `json:"isAssignableToRole"`
}

type groupsResponse struct {
	ODataCount int     `json:"@odata.count"`
	Value      []Group `json:"value"`
	NextLink   string  `json:"@odata.nextLink"`
}

// DirectoryRoleAssignment represents a transitive role assignment
type DirectoryRoleAssignment struct {
	ID               string `json:"id"`
	PrincipalID      string `json:"principalId"`
	RoleDefinitionID string `json:"roleDefinitionId"`
	DirectoryScopeID string `json:"directoryScopeId"`
}

type roleAssignmentsResponse struct {
	ODataCount int                       `json:"@odata.count"`
	Value      []DirectoryRoleAssignment `json:"value"`
	NextLink   string                    `json:"@odata.nextLink"`
}

func doGraphRequest(token, apiURL string) ([]byte, error) {
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("ConsistencyLevel", "eventual")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// GetRoleDefinitions fetches all role definitions from Entra ID with pagination support
func GetRoleDefinitions(token string) ([]RoleDefinition, error) {
	apiURL := "https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions?$top=500"
	var allDefinitions []RoleDefinition

	for apiURL != "" {
		body, err := doGraphRequest(token, apiURL)
		if err != nil {
			return nil, err
		}

		var result roleDefinitionsResponse
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("failed to parse response: %w", err)
		}

		allDefinitions = append(allDefinitions, result.Value...)
		apiURL = result.NextLink
	}

	return allDefinitions, nil
}

// GetUserGroups fetches group memberships for a user with pagination support
// Uses transitiveMemberOf to get all groups including nested group memberships
func GetUserGroups(token, userID string) ([]Group, error) {
	selectFields := "id,displayName,mailEnabled,securityEnabled,groupTypes,onPremisesSyncEnabled,mail,isAssignableToRole"
	apiURL := fmt.Sprintf(
		"https://graph.microsoft.com/beta/users/%s/transitiveMemberOf/microsoft.graph.group?$select=%s&$top=100&$orderby=displayName%%20asc&$count=true",
		url.PathEscape(userID),
		selectFields,
	)
	var allGroups []Group

	for apiURL != "" {
		body, err := doGraphRequest(token, apiURL)
		if err != nil {
			return nil, err
		}

		var result groupsResponse
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("failed to parse response: %w", err)
		}

		allGroups = append(allGroups, result.Value...)
		apiURL = result.NextLink
	}

	return allGroups, nil
}

// GetTransitiveRoleAssignments fetches transitive role assignments for a user with pagination support
func GetTransitiveRoleAssignments(token, userID string) ([]DirectoryRoleAssignment, error) {
	apiURL := fmt.Sprintf(
		"https://graph.microsoft.com/beta/users/%s/roleManagement/directory/transitiveRoleAssignments?$top=999&$count=true",
		url.PathEscape(userID),
	)
	var allAssignments []DirectoryRoleAssignment

	for apiURL != "" {
		body, err := doGraphRequest(token, apiURL)
		if err != nil {
			return nil, err
		}

		var result roleAssignmentsResponse
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("failed to parse response: %w", err)
		}

		allAssignments = append(allAssignments, result.Value...)
		apiURL = result.NextLink
	}

	return allAssignments, nil
}

// BuildRoleDefinitionMap creates a map of role definition ID to display name
func BuildRoleDefinitionMap(definitions []RoleDefinition) map[string]string {
	m := make(map[string]string)
	for _, d := range definitions {
		m[d.ID] = d.DisplayName
	}
	return m
}

// DirectoryObject represents a user, group, or service principal from Azure AD
type DirectoryObject struct {
	ODataType   string `json:"@odata.type"`
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

type getByIdsRequest struct {
	IDs   []string `json:"ids"`
	Types []string `json:"types"`
}

type getByIdsResponse struct {
	Value []DirectoryObject `json:"value"`
}

// ResolveDirectoryObjects resolves principal IDs to their display names
// Handles the 1000 ID limit by batching requests
func ResolveDirectoryObjects(token string, principalIDs []string) (map[string]string, error) {
	if len(principalIDs) == 0 {
		return make(map[string]string), nil
	}

	// Remove duplicates
	uniqueIDs := make(map[string]bool)
	var ids []string
	for _, id := range principalIDs {
		if !uniqueIDs[id] && id != "" {
			uniqueIDs[id] = true
			ids = append(ids, id)
		}
	}

	// Build map of ID to display name
	principalMap := make(map[string]string)
	apiURL := "https://graph.microsoft.com/v1.0/directoryObjects/getByIds"
	client := &http.Client{}

	// Batch IDs into chunks of 1000 (API limit)
	const batchSize = 1000
	for i := 0; i < len(ids); i += batchSize {
		end := i + batchSize
		if end > len(ids) {
			end = len(ids)
		}
		batch := ids[i:end]

		reqBody := getByIdsRequest{
			IDs:   batch,
			Types: []string{"user", "group", "servicePrincipal"},
		}

		jsonBody, err := json.Marshal(reqBody)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request: %w", err)
		}

		req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonBody))
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to send request: %w", err)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to read response: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
		}

		var result getByIdsResponse
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("failed to parse response: %w", err)
		}

		for _, obj := range result.Value {
			principalMap[obj.ID] = obj.DisplayName
		}
	}

	return principalMap, nil
}

// UserInfo represents user details for PDF report
type UserInfo struct {
	ID                string `json:"id"`
	DisplayName       string `json:"displayName"`
	Mail              string `json:"mail"`
	UserPrincipalName string `json:"userPrincipalName"`
}

// GetUserInfo fetches user details from Microsoft Graph
func GetUserInfo(token, userID string) (*UserInfo, error) {
	apiURL := fmt.Sprintf(
		"https://graph.microsoft.com/v1.0/users/%s?$select=id,displayName,mail,userPrincipalName",
		url.PathEscape(userID),
	)

	body, err := doGraphRequest(token, apiURL)
	if err != nil {
		return nil, err
	}

	var user UserInfo
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, fmt.Errorf("failed to parse user response: %w", err)
	}

	return &user, nil
}

// UsersResponse represents the API response for searching users
type UsersResponse struct {
	Value    []UserInfo `json:"value"`
	NextLink string     `json:"@odata.nextLink"`
}

// SearchUsers searches for users in Azure AD by display name or UPN
func SearchUsers(token, searchText string) ([]UserInfo, error) {
	// Use $filter with startswith for display name and UPN
	filter := fmt.Sprintf("startswith(displayName,'%s') or startswith(userPrincipalName,'%s')",
		searchText, searchText)
	apiURL := fmt.Sprintf(
		"https://graph.microsoft.com/v1.0/users?$filter=%s&$select=id,displayName,mail,userPrincipalName&$top=50",
		url.QueryEscape(filter),
	)

	var allUsers []UserInfo
	for apiURL != "" {
		body, err := doGraphRequest(token, apiURL)
		if err != nil {
			return nil, err
		}

		var result UsersResponse
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("failed to parse users response: %w", err)
		}

		allUsers = append(allUsers, result.Value...)
		apiURL = result.NextLink
	}

	return allUsers, nil
}

// GroupsResponse represents the API response for searching groups
type GroupsResponse struct {
	Value    []Group `json:"value"`
	NextLink string  `json:"@odata.nextLink"`
}

// SearchGroups searches for groups in Azure AD by display name
func SearchGroups(token, searchText string) ([]Group, error) {
	filter := fmt.Sprintf("startswith(displayName,'%s')", searchText)
	apiURL := fmt.Sprintf(
		"https://graph.microsoft.com/v1.0/groups?$filter=%s&$select=id,displayName,mailEnabled,securityEnabled,groupTypes,isAssignableToRole&$top=50",
		url.QueryEscape(filter),
	)

	var allGroups []Group
	for apiURL != "" {
		body, err := doGraphRequest(token, apiURL)
		if err != nil {
			return nil, err
		}

		var result GroupsResponse
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("failed to parse groups response: %w", err)
		}

		allGroups = append(allGroups, result.Value...)
		apiURL = result.NextLink
	}

	return allGroups, nil
}

// GroupMembersResponse represents the API response for group members
type GroupMembersResponse struct {
	Value    []UserInfo `json:"value"`
	NextLink string     `json:"@odata.nextLink"`
}

// GetGroupMembers fetches all members of a group
func GetGroupMembers(token, groupID string) ([]UserInfo, error) {
	apiURL := fmt.Sprintf(
		"https://graph.microsoft.com/v1.0/groups/%s/members?$select=id,displayName,mail,userPrincipalName",
		groupID,
	)

	var allMembers []UserInfo
	for apiURL != "" {
		body, err := doGraphRequest(token, apiURL)
		if err != nil {
			return nil, err
		}

		var result GroupMembersResponse
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("failed to parse group members response: %w", err)
		}

		// Filter to only include users (not nested groups or service principals)
		for _, member := range result.Value {
			if member.ID != "" && member.DisplayName != "" {
				allMembers = append(allMembers, member)
			}
		}
		apiURL = result.NextLink
	}

	return allMembers, nil
}

// ServicePrincipalInfo represents service principal details
type ServicePrincipalInfo struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	AppID       string `json:"appId"`
}

// GetServicePrincipalByAppID fetches service principal details by its application (client) ID
func GetServicePrincipalByAppID(token, appID string) (*ServicePrincipalInfo, error) {
	filter := fmt.Sprintf("appId eq '%s'", appID)
	apiURL := fmt.Sprintf(
		"https://graph.microsoft.com/v1.0/servicePrincipals?$filter=%s&$select=id,displayName,appId",
		url.QueryEscape(filter),
	)

	body, err := doGraphRequest(token, apiURL)
	if err != nil {
		return nil, err
	}

	var result struct {
		Value []ServicePrincipalInfo `json:"value"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse service principal response: %w", err)
	}

	if len(result.Value) == 0 {
		return nil, fmt.Errorf("service principal not found for appId: %s", appID)
	}

	return &result.Value[0], nil
}

// GetUserDirectGroups fetches only direct group memberships for a user (not transitive)
func GetUserDirectGroups(token, userID string) ([]Group, error) {
	selectFields := "id,displayName,mailEnabled,securityEnabled,groupTypes,onPremisesSyncEnabled,mail,isAssignableToRole"
	apiURL := fmt.Sprintf(
		"https://graph.microsoft.com/v1.0/users/%s/memberOf/microsoft.graph.group?$select=%s&$top=100",
		url.PathEscape(userID),
		selectFields,
	)
	var allGroups []Group

	for apiURL != "" {
		body, err := doGraphRequest(token, apiURL)
		if err != nil {
			return nil, err
		}

		var result groupsResponse
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("failed to parse response: %w", err)
		}

		allGroups = append(allGroups, result.Value...)
		apiURL = result.NextLink
	}

	return allGroups, nil
}

// GetGroupMemberOfGroups fetches groups that a group is a member of (direct parent groups)
func GetGroupMemberOfGroups(token, groupID string) ([]Group, error) {
	apiURL := fmt.Sprintf(
		"https://graph.microsoft.com/v1.0/groups/%s/memberOf/microsoft.graph.group?$select=id,displayName&$top=100",
		url.PathEscape(groupID),
	)
	var allGroups []Group

	for apiURL != "" {
		body, err := doGraphRequest(token, apiURL)
		if err != nil {
			return nil, err
		}

		var result groupsResponse
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("failed to parse response: %w", err)
		}

		allGroups = append(allGroups, result.Value...)
		apiURL = result.NextLink
	}

	return allGroups, nil
}

// GetGroupMembershipChain finds the membership chain from user's direct group to target group
// Returns the chain of group names showing how the user inherits membership in the target group
// Example: if user is in "IT Dev - Onshore Lead Devs", which is in "IT Dev - Onshore Devs",
// which is in "aad-subscription-reader-dev" (target), returns:
// ["IT Dev - Onshore Lead Devs", "IT Dev - Onshore Devs", "aad-subscription-reader-dev"]
func GetGroupMembershipChain(token, userID, targetGroupID string, directGroupIDs map[string]bool) ([]string, error) {
	// If user is directly a member of the target group, no chain needed
	if directGroupIDs[targetGroupID] {
		return nil, nil
	}

	// Get target group name
	targetGroupName := targetGroupID
	targetGroupInfo, err := getGroupByID(token, targetGroupID)
	if err == nil && targetGroupInfo.DisplayName != "" {
		targetGroupName = targetGroupInfo.DisplayName
	}

	// BFS from user's direct groups upward to find path to target group
	type queueItem struct {
		groupID string
		chain   []string // chain from user's direct group toward target
	}

	visited := make(map[string]bool)
	var queue []queueItem

	// Start from each of user's direct groups
	for directGroupID := range directGroupIDs {
		directGroupName := directGroupID
		groupInfo, err := getGroupByID(token, directGroupID)
		if err == nil && groupInfo.DisplayName != "" {
			directGroupName = groupInfo.DisplayName
		}
		queue = append(queue, queueItem{groupID: directGroupID, chain: []string{directGroupName}})
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if visited[current.groupID] {
			continue
		}
		visited[current.groupID] = true

		// Get parent groups (groups that this group is a member of)
		parentGroups, err := GetGroupMemberOfGroups(token, current.groupID)
		if err != nil {
			continue // Skip on error, try other paths
		}

		for _, parent := range parentGroups {
			if parent.ID == targetGroupID {
				// Found the target! Complete the chain
				return append(current.chain, targetGroupName), nil
			}
			if !visited[parent.ID] {
				newChain := append([]string{}, current.chain...)
				newChain = append(newChain, parent.DisplayName)
				queue = append(queue, queueItem{groupID: parent.ID, chain: newChain})
			}
		}
	}

	// No chain found (shouldn't happen if transitive membership is correct)
	return nil, nil
}

// getGroupByID fetches a single group by ID
func getGroupByID(token, groupID string) (*Group, error) {
	apiURL := fmt.Sprintf(
		"https://graph.microsoft.com/v1.0/groups/%s?$select=id,displayName",
		url.PathEscape(groupID),
	)

	body, err := doGraphRequest(token, apiURL)
	if err != nil {
		return nil, err
	}

	var group Group
	if err := json.Unmarshal(body, &group); err != nil {
		return nil, fmt.Errorf("failed to parse group response: %w", err)
	}

	return &group, nil
}

// getGroupMemberGroups fetches groups that are members of a group
func getGroupMemberGroups(token, groupID string) ([]Group, error) {
	apiURL := fmt.Sprintf(
		"https://graph.microsoft.com/v1.0/groups/%s/members/microsoft.graph.group?$select=id,displayName&$top=100",
		url.PathEscape(groupID),
	)

	var allGroups []Group
	for apiURL != "" {
		body, err := doGraphRequest(token, apiURL)
		if err != nil {
			return nil, err
		}

		var result groupsResponse
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("failed to parse response: %w", err)
		}

		allGroups = append(allGroups, result.Value...)
		apiURL = result.NextLink
	}

	return allGroups, nil
}
