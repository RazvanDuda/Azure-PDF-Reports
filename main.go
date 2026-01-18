package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"azure-role-report/auth"
	"azure-role-report/azure"
	"azure-role-report/config"
	"azure-role-report/graph"
	"azure-role-report/logger"
	"azure-role-report/output"
	"azure-role-report/storage"

	"github.com/AlecAivazis/survey/v2"
	"github.com/spf13/cobra"
)

var debugFlag bool

func main() {
	rootCmd := &cobra.Command{
		Use:   "azure-role-report",
		Short: "Azure Role Assignments Report Tool",
		Long:  "A CLI tool to fetch and display Azure role assignments, group memberships, and directory roles for a specified user.",
		RunE:  run,
	}

	rootCmd.Flags().BoolVar(&debugFlag, "debug", false, "Enable debug logging to file")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	// Initialize logger
	if err := logger.Init(debugFlag); err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	defer logger.Close()

	cfg, err := config.LoadConfig("config.toml")
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	tenantID := cfg.Authentication.ServicePrincipal.TenantID
	clientID := cfg.Authentication.ServicePrincipal.ClientID
	clientSecret := cfg.Authentication.ServicePrincipal.ClientSecret

	// Get Azure Management token
	fmt.Println("Authenticating with Azure Management API...")
	managementToken, err := auth.GetManagementToken(tenantID, clientID, clientSecret)
	if err != nil {
		return fmt.Errorf("failed to get management token: %w", err)
	}

	// Get Microsoft Graph token
	fmt.Println("Authenticating with Microsoft Graph API...")
	graphToken, err := auth.GetGraphToken(tenantID, clientID, clientSecret)
	if err != nil {
		return fmt.Errorf("failed to get graph token: %w", err)
	}

	return runInteractive(cfg, managementToken, graphToken, clientID)
}

func runInteractive(cfg *config.Config, managementToken, graphToken, clientID string) error {
	fmt.Println("\n=== Interactive Mode ===")

	// Step 1: Fetch all subscriptions
	fmt.Println("Fetching available subscriptions...")
	subscriptions, err := azure.GetSubscriptions(managementToken)
	if err != nil {
		return fmt.Errorf("failed to get subscriptions: %w", err)
	}

	if len(subscriptions) == 0 {
		return fmt.Errorf("no subscriptions found")
	}

	// Build subscription options for multi-select
	subOptions := make([]string, len(subscriptions))
	subMap := make(map[string]azure.Subscription)
	for i, sub := range subscriptions {
		subOptions[i] = fmt.Sprintf("%s (%s)", sub.DisplayName, sub.SubscriptionID)
		subMap[subOptions[i]] = sub
	}

	// Step 2: Select subscriptions
	var selectedSubOptions []string
	subPrompt := &survey.MultiSelect{
		Message: "Select subscriptions to analyze:",
		Options: subOptions,
	}
	if err := survey.AskOne(subPrompt, &selectedSubOptions, survey.WithValidator(survey.Required)); err != nil {
		return fmt.Errorf("subscription selection cancelled: %w", err)
	}

	selectedSubs := make([]azure.Subscription, len(selectedSubOptions))
	for i, opt := range selectedSubOptions {
		selectedSubs[i] = subMap[opt]
	}
	fmt.Printf("Selected %d subscription(s)\n\n", len(selectedSubs))

	// Step 3: Ask for search type
	var searchType string
	typePrompt := &survey.Select{
		Message: "Search for:",
		Options: []string{"User", "Group"},
	}
	if err := survey.AskOne(typePrompt, &searchType); err != nil {
		return fmt.Errorf("search type selection cancelled: %w", err)
	}

	// Step 4: Search for users or groups
	var searchText string
	searchPrompt := &survey.Input{
		Message: fmt.Sprintf("Enter %s name to search:", strings.ToLower(searchType)),
	}
	if err := survey.AskOne(searchPrompt, &searchText, survey.WithValidator(survey.Required)); err != nil {
		return fmt.Errorf("search cancelled: %w", err)
	}

	var usersToProcess []graph.UserInfo

	if searchType == "User" {
		// Search for users
		fmt.Printf("Searching for users matching '%s'...\n", searchText)
		users, err := graph.SearchUsers(graphToken, searchText)
		if err != nil {
			return fmt.Errorf("failed to search users: %w", err)
		}

		if len(users) == 0 {
			return fmt.Errorf("no users found matching '%s'", searchText)
		}

		// Build user options for selection
		userOptions := make([]string, len(users))
		userMap := make(map[string]graph.UserInfo)
		for i, user := range users {
			display := user.DisplayName
			if user.UserPrincipalName != "" {
				display = fmt.Sprintf("%s (%s)", user.DisplayName, user.UserPrincipalName)
			}
			userOptions[i] = display
			userMap[display] = user
		}

		var selectedUserOption string
		userPrompt := &survey.Select{
			Message: "Select user:",
			Options: userOptions,
		}
		if err := survey.AskOne(userPrompt, &selectedUserOption); err != nil {
			return fmt.Errorf("user selection cancelled: %w", err)
		}

		usersToProcess = []graph.UserInfo{userMap[selectedUserOption]}
	} else {
		// Search for groups
		fmt.Printf("Searching for groups matching '%s'...\n", searchText)
		groups, err := graph.SearchGroups(graphToken, searchText)
		if err != nil {
			return fmt.Errorf("failed to search groups: %w", err)
		}

		if len(groups) == 0 {
			return fmt.Errorf("no groups found matching '%s'", searchText)
		}

		// Build group options for selection
		groupOptions := make([]string, len(groups))
		groupMap := make(map[string]graph.Group)
		for i, g := range groups {
			groupOptions[i] = g.DisplayName
			groupMap[g.DisplayName] = g
		}

		var selectedGroupOption string
		groupPrompt := &survey.Select{
			Message: "Select group:",
			Options: groupOptions,
		}
		if err := survey.AskOne(groupPrompt, &selectedGroupOption); err != nil {
			return fmt.Errorf("group selection cancelled: %w", err)
		}

		selectedGroup := groupMap[selectedGroupOption]

		// Fetch group members
		fmt.Printf("Fetching members of '%s'...\n", selectedGroup.DisplayName)
		members, err := graph.GetGroupMembers(graphToken, selectedGroup.ID)
		if err != nil {
			return fmt.Errorf("failed to get group members: %w", err)
		}

		if len(members) == 0 {
			return fmt.Errorf("no members found in group '%s'", selectedGroup.DisplayName)
		}

		fmt.Printf("Found %d members in group\n", len(members))
		usersToProcess = members
	}

	// Step 5: Generate reports
	fmt.Printf("\nGenerating PDF reports for %d user(s) across %d subscription(s)...\n\n",
		len(usersToProcess), len(selectedSubs))

	// Get service principal name for report footer
	spName := ""
	spInfo, err := graph.GetServicePrincipalByAppID(graphToken, clientID)
	if err != nil {
		fmt.Printf("Warning: failed to get service principal name: %v\n", err)
	} else if spInfo != nil {
		spName = spInfo.DisplayName
	}

	reportsGenerated := 0
	for _, user := range usersToProcess {
		fmt.Printf("Processing: %s...\n", user.DisplayName)

		if err := generateUserReport(cfg, managementToken, graphToken, user, selectedSubs, spName); err != nil {
			fmt.Printf("  Warning: failed to generate report for %s: %v\n", user.DisplayName, err)
			continue
		}
		reportsGenerated++
	}

	fmt.Printf("\n=== Summary ===\n")
	fmt.Printf("Generated %d PDF report(s)\n", reportsGenerated)

	return nil
}

func generateUserReport(cfg *config.Config, managementToken, graphToken string, user graph.UserInfo, subscriptions []azure.Subscription, spName string) error {
	// Build per-subscription data
	var subscriptionDataList []output.SubscriptionData
	var allAssignments []azure.RoleAssignment
	var allRoleDefinitions []azure.RoleDefinition
	allAzureRoleMap := make(map[string]string)
	allPrincipalIDs := make(map[string]bool)
	seenRoleDefs := make(map[string]bool)

	// Fetch user groups first (needed for group role assignments)
	groups, _ := graph.GetUserGroups(graphToken, user.ID)
	if groups == nil {
		groups = []graph.Group{}
	}

	// Fetch user's direct groups (for nested group chain detection)
	directGroups, _ := graph.GetUserDirectGroups(graphToken, user.ID)
	directGroupIDs := make(map[string]bool)
	for _, g := range directGroups {
		directGroupIDs[g.ID] = true
	}

	for _, sub := range subscriptions {
		subData := output.SubscriptionData{
			SubscriptionID:       sub.SubscriptionID,
			SubscriptionName:     sub.DisplayName,
			GroupRoleAssignments: make(map[string][]azure.RoleAssignment),
			GroupChains:          make(map[string][]string),
		}

		// Fetch role assignments for this subscription
		assignments, err := azure.GetRoleAssignments(managementToken, sub.SubscriptionID, user.ID)
		if err != nil {
			fmt.Printf("  Warning: failed to get role assignments for subscription %s: %v\n", sub.DisplayName, err)
		} else {
			subData.Assignments = assignments
			allAssignments = append(allAssignments, assignments...)
		}

		// Fetch role definitions
		roleDefs, err := azure.GetRoleDefinitions(managementToken, sub.SubscriptionID)
		if err == nil {
			for _, rd := range roleDefs {
				allAzureRoleMap[rd.ID] = rd.Properties.RoleName
				allAzureRoleMap[rd.Name] = rd.Properties.RoleName
				// Collect unique role definitions for high-risk permissions calculation
				if !seenRoleDefs[rd.Name] {
					seenRoleDefs[rd.Name] = true
					allRoleDefinitions = append(allRoleDefinitions, rd)
				}
			}
		}

		// Collect principal IDs
		for _, a := range assignments {
			allPrincipalIDs[a.Properties.PrincipalID] = true
		}

		// Fetch group role assignments for this subscription
		for _, g := range groups {
			groupAssignments, err := azure.GetRoleAssignmentsForPrincipal(managementToken, sub.SubscriptionID, g.ID)
			if err == nil && len(groupAssignments) > 0 {
				subData.GroupRoleAssignments[g.ID] = groupAssignments
				// Compute nested group chain if user is not a direct member
				if !directGroupIDs[g.ID] {
					chain, err := graph.GetGroupMembershipChain(graphToken, user.ID, g.ID, directGroupIDs)
					if err == nil && len(chain) > 0 {
						subData.GroupChains[g.ID] = chain
					}
				}
			}
		}

		subscriptionDataList = append(subscriptionDataList, subData)
	}

	// Resolve principal names
	var principalIDsList []string
	for id := range allPrincipalIDs {
		principalIDsList = append(principalIDsList, id)
	}
	principalMap, _ := graph.ResolveDirectoryObjects(graphToken, principalIDsList)
	if principalMap == nil {
		principalMap = make(map[string]string)
	}

	// Fetch Entra ID role definitions
	roleDefinitions, _ := graph.GetRoleDefinitions(graphToken)
	if roleDefinitions == nil {
		roleDefinitions = []graph.RoleDefinition{}
	}
	roleMap := graph.BuildRoleDefinitionMap(roleDefinitions)

	// Fetch directory roles
	directoryRoles, _ := graph.GetTransitiveRoleAssignments(graphToken, user.ID)
	if directoryRoles == nil {
		directoryRoles = []graph.DirectoryRoleAssignment{}
	}

	// Use first subscription as primary for backward compatibility
	primarySub := subscriptions[0]

	// Prepare PDF data
	pdfData := output.PDFReportData{
		UserInfo:              &user,
		SubscriptionID:        primarySub.SubscriptionID,
		SubscriptionName:      primarySub.DisplayName,
		Assignments:           allAssignments,
		GroupRoleAssignments:  make(map[string][]azure.RoleAssignment), // Not used in multi-sub mode
		AzureRoleMap:          allAzureRoleMap,
		PrincipalMap:          principalMap,
		Groups:                groups,
		DirectoryRoles:        directoryRoles,
		EntraRoleMap:          roleMap,
		RoleDefinitions:       allRoleDefinitions,
		Subscriptions:         subscriptionDataList, // Multi-subscription data
		DirectGroupIDs:        directGroupIDs,
		ServicePrincipalName:  spName,
	}

	// Generate filename
	userIdentifier := "unknown"
	if user.UserPrincipalName != "" {
		upn := user.UserPrincipalName
		if idx := strings.Index(upn, "@"); idx > 0 {
			userIdentifier = upn[:idx]
		} else {
			userIdentifier = upn
		}
	} else if user.DisplayName != "" {
		userIdentifier = strings.ReplaceAll(user.DisplayName, " ", "_")
	}
	userIdentifier = strings.ReplaceAll(userIdentifier, "/", "_")
	userIdentifier = strings.ReplaceAll(userIdentifier, "\\", "_")

	ukLocation, err := time.LoadLocation("Europe/London")
	if err != nil {
		ukLocation = time.UTC
	}
	ukTime := time.Now().In(ukLocation)
	timestamp := ukTime.Format("2006-01-02_15-04-05")

	pdfOutputFile := fmt.Sprintf("%s_%s.pdf", userIdentifier, timestamp)

	if err := output.GeneratePDFReport(pdfData, pdfOutputFile); err != nil {
		return fmt.Errorf("failed to generate PDF: %w", err)
	}

	fmt.Printf("  Generated: %s\n", pdfOutputFile)

	// Upload to Azure Storage if enabled
	if cfg.Storage.Enabled {
		if err := storage.UploadPDFReport(cfg.Storage, pdfOutputFile); err != nil {
			fmt.Printf("  Warning: failed to upload to Azure Storage: %v\n", err)
			logger.Debug("Azure Storage upload failed for %s: %v", pdfOutputFile, err)
		} else {
			fmt.Printf("  Uploaded to Azure Storage (cloud-only)\n")
			logger.Info("Successfully uploaded %s to Azure Storage", pdfOutputFile)

			// Delete local file after successful upload
			if err := os.Remove(pdfOutputFile); err != nil {
				fmt.Printf("  Warning: failed to delete local file: %v\n", err)
				logger.Debug("Failed to delete local file %s: %v", pdfOutputFile, err)
			} else {
				logger.Debug("Deleted local file %s after successful upload", pdfOutputFile)
			}
		}
	}

	return nil
}
