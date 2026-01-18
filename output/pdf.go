package output

import (
	"fmt"
	"math/rand"
	"strings"
	"time"

	"azure-role-report/azure"
	"azure-role-report/graph"

	"github.com/jung-kurt/gofpdf"
)

// SubscriptionData holds role assignment data for a single subscription
type SubscriptionData struct {
	SubscriptionID       string
	SubscriptionName     string
	Assignments          []azure.RoleAssignment
	GroupRoleAssignments map[string][]azure.RoleAssignment
	GroupChains          map[string][]string // Map of group ID to membership chain (for nested groups)
}

// PDFReportData contains all data needed to generate the PDF report
type PDFReportData struct {
	UserInfo              *graph.UserInfo
	SubscriptionID        string                             // Primary subscription (for single-sub reports)
	SubscriptionName      string                             // Primary subscription name
	Assignments           []azure.RoleAssignment             // All assignments (aggregated)
	GroupRoleAssignments  map[string][]azure.RoleAssignment  // Map of group ID to its role assignments
	AzureRoleMap          map[string]string
	PrincipalMap          map[string]string
	Groups                []graph.Group
	DirectoryRoles        []graph.DirectoryRoleAssignment
	EntraRoleMap          map[string]string
	RoleDefinitions       []azure.RoleDefinition
	Subscriptions         []SubscriptionData                 // For multi-subscription reports
	GroupChains           map[string][]string                // Map of group ID to membership chain (for single-sub mode)
	DirectGroupIDs        map[string]bool                    // Set of user's direct group IDs
	ServicePrincipalName  string                             // Name of the SP used to generate the report
}

// GeneratePDFReport generates a PDF report matching the example.pdf layout
func GeneratePDFReport(data PDFReportData, outputPath string) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetAutoPageBreak(true, 15)

	// Generate report ID using seeded random source for Go < 1.20 compatibility
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	reportID := fmt.Sprintf("%d", rng.Int63n(9999999999))

	// Calculate summary statistics
	summary := calculateSummary(data)

	// Page 1: Cover Page
	addCoverPage(pdf, data, summary, reportID)

	// Page 2: Executive Summary
	addExecutiveSummary(pdf, data, summary)

	// Page 3: Non-Subscription Rights
	addNonSubscriptionRights(pdf, data)

	// Page 4+: Subscription Details (one section per subscription)
	if len(data.Subscriptions) > 0 {
		// Multi-subscription mode
		for _, subData := range data.Subscriptions {
			addSubscriptionDetailsForSub(pdf, data, subData)
		}
	} else {
		// Single subscription mode (backward compatibility)
		addSubscriptionDetails(pdf, data)
	}

	return pdf.OutputFileAndClose(outputPath)
}

type reportSummary struct {
	ReportDate           string
	SubscriptionsCount   int
	TotalAssignments     int
	PrivilegedRoles      int
	HighRiskPermissions  int
	SubscriptionLevel    int
	ResourceGroupLevel   int
	ResourceLevel        int
	DirectAssignments    int
	GroupBased           int
}

func calculateSummary(data PDFReportData) reportSummary {
	summary := reportSummary{
		ReportDate: time.Now().UTC().Format("02/01/2006 15:04:05 UTC"),
	}

	// Set subscription count based on multi-subscription mode
	if len(data.Subscriptions) > 0 {
		summary.SubscriptionsCount = len(data.Subscriptions)
	} else {
		summary.SubscriptionsCount = 1
	}

	privilegedRoles := map[string]bool{
		"Owner":                     true,
		"Contributor":               true,
		"User Access Administrator": true,
	}

	seenRoles := make(map[string]bool)

	// Process assignments - use per-subscription data if available
	// Deduplicate assignments by ID to avoid counting the same assignment multiple times
	var allAssignments []azure.RoleAssignment
	seenAssignments := make(map[string]bool)
	if len(data.Subscriptions) > 0 {
		for _, subData := range data.Subscriptions {
			for _, a := range subData.Assignments {
				if !seenAssignments[a.ID] {
					seenAssignments[a.ID] = true
					allAssignments = append(allAssignments, a)
				}
			}
			// Include group-based assignments in totals
			for _, groupAssignments := range subData.GroupRoleAssignments {
				for _, a := range groupAssignments {
					if !seenAssignments[a.ID] {
						seenAssignments[a.ID] = true
						allAssignments = append(allAssignments, a)
					}
				}
			}
		}
	} else {
		for _, a := range data.Assignments {
			if !seenAssignments[a.ID] {
				seenAssignments[a.ID] = true
				allAssignments = append(allAssignments, a)
			}
		}
	}

	summary.TotalAssignments = len(allAssignments)

	for _, a := range allAssignments {
		roleID := ExtractRoleGUID(a.Properties.RoleDefinitionID)
		roleName := data.AzureRoleMap[roleID]
		if roleName == "" {
			roleName = data.AzureRoleMap[a.Properties.RoleDefinitionID]
		}

		if privilegedRoles[roleName] && !seenRoles[roleName] {
			summary.PrivilegedRoles++
			seenRoles[roleName] = true
		}

		// Count by scope level - properly detect resource vs resource group
		scope := a.Properties.Scope
		scopeLower := strings.ToLower(scope)
		if strings.Contains(scopeLower, "/managementgroups/") {
			// Management group level - don't count in subscription stats
			continue
		} else if strings.Contains(scopeLower, "/resourcegroups/") {
			// Split by /resourcegroups/ (case-insensitive) and check what comes after the resource group name
			idx := strings.Index(scopeLower, "/resourcegroups/")
			afterRG := scope[idx+len("/resourcegroups/"):]
			// afterRG is like "rg-name" or "rg-name/providers/..."
			rgParts := strings.SplitN(afterRG, "/", 2)
			if len(rgParts) > 1 && rgParts[1] != "" {
				// There's content after the resource group name (e.g., /providers/...)
				summary.ResourceLevel++
			} else {
				// Just the resource group, nothing after
				summary.ResourceGroupLevel++
			}
		} else {
			summary.SubscriptionLevel++
		}

		// Determine if direct or group-based
		if data.UserInfo != nil && a.Properties.PrincipalID == data.UserInfo.ID {
			summary.DirectAssignments++
		} else {
			summary.GroupBased++
		}
	}

	// Build a set of role GUIDs that are actually assigned to the user
	assignedRoleGUIDs := make(map[string]bool)
	for _, a := range allAssignments {
		roleGUID := ExtractRoleGUID(a.Properties.RoleDefinitionID)
		assignedRoleGUIDs[roleGUID] = true
	}

	// High-risk = roles with wildcard actions (only count if actually assigned)
	for _, rd := range data.RoleDefinitions {
		// Only count roles that are assigned to the user
		if !assignedRoleGUIDs[rd.Name] {
			continue
		}
		if len(rd.Properties.Permissions) > 0 {
			for _, action := range rd.Properties.Permissions[0].Actions {
				if action == "*" {
					summary.HighRiskPermissions++
					break
				}
			}
		}
	}

	return summary
}


func addCoverPage(pdf *gofpdf.Fpdf, data PDFReportData, summary reportSummary, reportID string) {
	pdf.SetAutoPageBreak(false, 0) // Disable auto page break for cover page
	pdf.AddPage()

	// Title
	pdf.SetFont("Arial", "B", 24)
	pdf.SetXY(10, 20)
	pdf.CellFormat(190, 12, "Microsoft Entra User Permissions Review", "", 1, "C", false, 0, "")

	// Subtitle
	pdf.SetFont("Arial", "", 14)
	pdf.SetXY(10, 35)
	pdf.CellFormat(190, 8, "Azure RBAC Role Assignments Analysis", "", 1, "C", false, 0, "")

	// User Information Box
	pdf.SetY(55)
	pdf.SetFont("Arial", "B", 12)
	pdf.SetDrawColor(0, 0, 0)
	pdf.SetLineWidth(0.5)
	pdf.Rect(15, 55, 180, 40, "D")
	pdf.SetXY(20, 58)
	pdf.Cell(0, 8, "USER INFORMATION")

	pdf.SetFont("Arial", "", 11)
	var userName, userEmail, userID string
	if data.UserInfo != nil {
		userName = data.UserInfo.DisplayName
		userEmail = data.UserInfo.Mail
		if userEmail == "" {
			userEmail = data.UserInfo.UserPrincipalName
		}
		userID = data.UserInfo.ID
	} else {
		userName = "Unknown User"
		userEmail = "N/A"
		userID = "N/A"
	}

	pdf.SetXY(20, 68)
	pdf.Cell(0, 6, fmt.Sprintf("Name: %s", userName))
	pdf.SetXY(20, 75)
	pdf.Cell(0, 6, fmt.Sprintf("Email: %s", userEmail))
	pdf.SetXY(20, 82)
	pdf.Cell(0, 6, fmt.Sprintf("Object ID (Entra): %s", userID))

	// Report Summary Box
	pdf.Rect(15, 105, 180, 55, "D")
	pdf.SetFont("Arial", "B", 12)
	pdf.SetXY(20, 108)
	pdf.Cell(0, 8, "REPORT SUMMARY")

	pdf.SetFont("Arial", "", 11)
	pdf.SetXY(20, 118)
	pdf.Cell(0, 6, fmt.Sprintf("Report Date: %s", summary.ReportDate))
	pdf.SetXY(20, 125)
	pdf.Cell(0, 6, fmt.Sprintf("Subscriptions Analyzed: %d", summary.SubscriptionsCount))
	pdf.SetXY(20, 132)
	pdf.Cell(0, 6, fmt.Sprintf("Total Role Assignments: %d", summary.TotalAssignments))
	pdf.SetXY(20, 139)
	pdf.Cell(0, 6, fmt.Sprintf("Privileged Roles: %d", summary.PrivilegedRoles))

	// Confidentiality Notice
	pdf.SetY(170)
	pdf.SetFont("Arial", "B", 14)
	pdf.SetXY(15, 170)
	pdf.Cell(0, 8, "CONFIDENTIAL - SECURITY SENSITIVE")

	pdf.SetFont("Arial", "", 12)
	pdf.SetXY(15, 182)
	pdf.MultiCell(180, 6, "This report contains sensitive security information about Azure role assignments and access permissions.\nIt should be handled according to your organization's data classification policies.\nReview all high-risk permissions and ensure they align with the principle of least privilege and zero trust security principles.", "", "L", false)

	// Footer
	pdf.SetY(270)
	pdf.SetFont("Arial", "", 9)
	pdf.Cell(0, 5, fmt.Sprintf("Authentication provided by Service Principal: %s", data.ServicePrincipalName))
	pdf.SetY(275)
	pdf.Cell(0, 5, fmt.Sprintf("Report ID: %s", reportID))

	pdf.SetAutoPageBreak(true, 15) // Re-enable auto page break for subsequent pages
}

func addExecutiveSummary(pdf *gofpdf.Fpdf, data PDFReportData, summary reportSummary) {
	pdf.AddPage()
	pdf.SetAutoPageBreak(false, 0)

	// Title
	pdf.SetFont("Arial", "B", 18)
	pdf.SetXY(10, 15)
	pdf.Cell(0, 10, "EXECUTIVE SUMMARY")

	// Bullet points
	pdf.SetFont("Arial", "", 11)
	y := 32.0
	bullets := []string{
		fmt.Sprintf("Total Subscriptions Analyzed: %d", summary.SubscriptionsCount),
		fmt.Sprintf("Total Role Assignments: %d", summary.TotalAssignments),
		fmt.Sprintf("Privileged Roles Count: %d", summary.PrivilegedRoles),
		fmt.Sprintf("Special Access Capabilities: %d", summary.PrivilegedRoles),
		fmt.Sprintf("Resource Groups with Access: %d", summary.ResourceGroupLevel),
	}

	for _, bullet := range bullets {
		pdf.SetXY(15, y)
		pdf.CellFormat(5, 6, "-", "", 0, "L", false, 0, "")
		pdf.SetX(22)
		pdf.Cell(0, 6, bullet)
		y += 7
	}

	// Access Summary Matrix
	pdf.SetY(y + 10)
	pdf.SetFont("Arial", "B", 14)
	pdf.Cell(0, 10, "ACCESS SUMMARY MATRIX")

	matrixY := y + 22

	// Multi-subscription mode: show per-subscription breakdown
	if len(data.Subscriptions) > 0 {
		for _, subData := range data.Subscriptions {
			// Calculate per-subscription stats
			subStats := calculateSubscriptionStats(subData, data.UserInfo)

			// Check if we need a new page (need ~55mm for a subscription block)
			if matrixY > 240 {
				pdf.AddPage()
				matrixY = 20
			}

			pdf.SetFont("Arial", "B", 11)
			pdf.SetXY(15, matrixY)
			pdf.Cell(0, 6, fmt.Sprintf("Subscription: %s", subData.SubscriptionName))
			matrixY += 8

			pdf.SetFont("Arial", "", 11)
			pdf.SetXY(20, matrixY)
			pdf.Cell(0, 6, fmt.Sprintf("Total Assignments: %d", subStats.total))
			matrixY += 7

			matrixItems := []string{
				fmt.Sprintf("Subscription-level: %d", subStats.subscriptionLevel),
				fmt.Sprintf("Resource Group-level: %d", subStats.resourceGroupLevel),
				fmt.Sprintf("Resource-level: %d", subStats.resourceLevel),
				fmt.Sprintf("Direct Assignments: %d", subStats.direct),
				fmt.Sprintf("Group-based: %d", subStats.groupBased),
			}

			for _, item := range matrixItems {
				// Check for page break before each item
				if matrixY > 270 {
					pdf.AddPage()
					matrixY = 20
				}
				pdf.SetXY(25, matrixY)
				pdf.CellFormat(5, 6, "-", "", 0, "L", false, 0, "")
				pdf.SetX(32)
				pdf.Cell(0, 6, item)
				matrixY += 7
			}
			matrixY += 5 // Space between subscriptions
		}
	} else {
		// Single subscription mode (backward compatibility)
		pdf.SetFont("Arial", "B", 11)
		pdf.SetXY(15, matrixY)
		pdf.Cell(0, 6, fmt.Sprintf("Subscription: %s", getSubscriptionDisplayName(data)))
		matrixY += 8

		pdf.SetFont("Arial", "", 11)
		pdf.SetXY(20, matrixY)
		pdf.Cell(0, 6, fmt.Sprintf("Total Assignments: %d", summary.TotalAssignments))
		matrixY += 7

		matrixItems := []string{
			fmt.Sprintf("Subscription-level: %d", summary.SubscriptionLevel),
			fmt.Sprintf("Resource Group-level: %d", summary.ResourceGroupLevel),
			fmt.Sprintf("Resource-level: %d", summary.ResourceLevel),
			fmt.Sprintf("Direct Assignments: %d", summary.DirectAssignments),
			fmt.Sprintf("Group-based: %d", summary.GroupBased),
		}

		for _, item := range matrixItems {
			// Check for page break before each item
			if matrixY > 270 {
				pdf.AddPage()
				matrixY = 20
			}
			pdf.SetXY(25, matrixY)
			pdf.CellFormat(5, 6, "-", "", 0, "L", false, 0, "")
			pdf.SetX(32)
			pdf.Cell(0, 6, item)
			matrixY += 7
		}
	}

	pdf.SetAutoPageBreak(true, 15) // Re-enable auto page break for subsequent pages
}

// subscriptionStats holds per-subscription statistics
type subscriptionStats struct {
	total              int
	subscriptionLevel  int
	resourceGroupLevel int
	resourceLevel      int
	direct             int
	groupBased         int
}

// calculateSubscriptionStats calculates statistics for a single subscription
func calculateSubscriptionStats(subData SubscriptionData, userInfo *graph.UserInfo) subscriptionStats {
	stats := subscriptionStats{}

	// Combine direct and group-based assignments, deduplicating by ID
	var allAssignments []azure.RoleAssignment
	seenAssignments := make(map[string]bool)
	for _, a := range subData.Assignments {
		if !seenAssignments[a.ID] {
			seenAssignments[a.ID] = true
			allAssignments = append(allAssignments, a)
		}
	}
	for _, groupAssignments := range subData.GroupRoleAssignments {
		for _, a := range groupAssignments {
			if !seenAssignments[a.ID] {
				seenAssignments[a.ID] = true
				allAssignments = append(allAssignments, a)
			}
		}
	}

	stats.total = len(allAssignments)

	for _, a := range allAssignments {
		scope := a.Properties.Scope
		scopeLower := strings.ToLower(scope)
		if strings.Contains(scopeLower, "/resourcegroups/") {
			idx := strings.Index(scopeLower, "/resourcegroups/")
			afterRG := scope[idx+len("/resourcegroups/"):]
			rgParts := strings.SplitN(afterRG, "/", 2)
			if len(rgParts) > 1 && rgParts[1] != "" {
				stats.resourceLevel++
			} else {
				stats.resourceGroupLevel++
			}
		} else {
			stats.subscriptionLevel++
		}

		// Determine if direct or group-based
		if userInfo != nil && a.Properties.PrincipalID == userInfo.ID {
			stats.direct++
		} else {
			stats.groupBased++
		}
	}

	return stats
}

func addSubscriptionDetails(pdf *gofpdf.Fpdf, data PDFReportData) {
	pdf.AddPage()

	// Horizontal line
	pdf.SetDrawColor(0, 0, 0)
	pdf.SetLineWidth(0.5)
	pdf.Line(10, 15, 200, 15)

	// Title
	pdf.SetFont("Arial", "B", 16)
	pdf.SetXY(10, 20)
	pdf.Cell(0, 10, fmt.Sprintf("SUBSCRIPTION: %s", strings.ToUpper(getSubscriptionDisplayName(data))))

	pdf.SetFont("Arial", "", 10)
	pdf.SetXY(10, 32)
	pdf.Cell(0, 6, fmt.Sprintf("Subscription ID: %s", data.SubscriptionID))

	y := 45.0

	// Build group name map for quick lookup
	groupNameMap := make(map[string]string)
	for _, g := range data.Groups {
		groupNameMap[g.ID] = g.DisplayName
	}

	// Categorize assignments into 3 groups
	type assignmentInfo struct {
		Assignment    azure.RoleAssignment
		GroupID       string   // Empty for direct user assignments
		GroupName     string   // Group display name if group-based
		NestedChain   []string // Nested group chain if inherited
	}

	var resourceLevelAssignments []assignmentInfo   // Direct user assignments at resource/RG level
	var subscriptionLevelAssignments []assignmentInfo // Direct user assignments at subscription level
	var groupBasedAssignments []assignmentInfo       // All group-based assignments

	// Process direct user assignments
	for _, a := range data.Assignments {
		// Skip management groups (shown in NON SUBSCRIPTION RIGHTS section)
		if strings.Contains(strings.ToLower(a.Properties.Scope), "/managementgroups/") {
			continue
		}

		// Only include direct user assignments
		if data.UserInfo != nil && a.Properties.PrincipalID == data.UserInfo.ID {
			if strings.Contains(strings.ToLower(a.Properties.Scope), "/resourcegroups/") {
				resourceLevelAssignments = append(resourceLevelAssignments, assignmentInfo{Assignment: a})
			} else {
				subscriptionLevelAssignments = append(subscriptionLevelAssignments, assignmentInfo{Assignment: a})
			}
		}
	}

	// Process group-based assignments
	seenGroupAssignments := make(map[string]bool)
	for groupID, assignments := range data.GroupRoleAssignments {
		groupName := groupNameMap[groupID]
		if groupName == "" {
			groupName = groupID
		}

		// Get nested chain if available
		nestedChain := data.GroupChains[groupID]

		for _, a := range assignments {
			// Skip management groups
			if strings.Contains(strings.ToLower(a.Properties.Scope), "/managementgroups/") {
				continue
			}

			// Deduplicate
			key := a.ID + "|" + groupID
			if seenGroupAssignments[key] {
				continue
			}
			seenGroupAssignments[key] = true

			groupBasedAssignments = append(groupBasedAssignments, assignmentInfo{
				Assignment:  a,
				GroupID:     groupID,
				GroupName:   groupName,
				NestedChain: nestedChain,
			})
		}
	}

	// Build overlap map: role+scope -> list of group names (for detecting overlapping permissions)
	overlapMap := make(map[string][]string)
	for _, info := range groupBasedAssignments {
		overlapKey := ExtractRoleGUID(info.Assignment.Properties.RoleDefinitionID) + "|" + info.Assignment.Properties.Scope
		overlapMap[overlapKey] = append(overlapMap[overlapKey], info.GroupName)
	}

	// Section 1: Resource-Level Rights
	pdf.SetY(y)
	pdf.SetFont("Arial", "B", 14)
	pdf.Cell(0, 8, "Direct Assignment: RESOURCE-LEVEL RIGHTS")
	y += 12

	if len(resourceLevelAssignments) > 0 {
		for _, info := range resourceLevelAssignments {
			a := info.Assignment
			if y > 250 {
				pdf.AddPage()
				y = 20
			}

			roleID := ExtractRoleGUID(a.Properties.RoleDefinitionID)
			roleName := data.AzureRoleMap[roleID]
			if roleName == "" {
				roleName = data.AzureRoleMap[a.Properties.RoleDefinitionID]
			}
			if roleName == "" {
				roleName = roleID
			}

			rgName, resourceName := parseResourceScope(a.Properties.Scope)

			pdf.SetFont("Arial", "B", 11)
			pdf.SetXY(15, y)
			pdf.Cell(0, 6, fmt.Sprintf("Role: %s", roleName))

			pdf.SetFont("Arial", "", 10)
			if resourceName != "" {
				pdf.SetXY(20, y+8)
				pdf.Cell(0, 5, fmt.Sprintf("Resource: %s", resourceName))
				pdf.SetXY(20, y+14)
				pdf.Cell(0, 5, fmt.Sprintf("Resource Group: %s", rgName))
				y += 26
			} else {
				pdf.SetXY(20, y+8)
				pdf.Cell(0, 5, fmt.Sprintf("Resource Group: %s", rgName))
				y += 20
			}
		}
	} else {
		pdf.SetFont("Arial", "", 11)
		pdf.SetXY(15, y)
		pdf.Cell(0, 6, "No direct resource-level rights found.")
		y += 12
	}

	// Section 2: Subscription-Level Rights
	y += 8
	if y > 250 {
		pdf.AddPage()
		y = 20
	}
	pdf.SetY(y)
	pdf.SetFont("Arial", "B", 14)
	pdf.Cell(0, 8, "Direct Assignment: SUBSCRIPTION-LEVEL RIGHTS")
	y += 12

	if len(subscriptionLevelAssignments) > 0 {
		for _, info := range subscriptionLevelAssignments {
			a := info.Assignment
			if y > 250 {
				pdf.AddPage()
				y = 20
			}

			roleID := ExtractRoleGUID(a.Properties.RoleDefinitionID)
			roleName := data.AzureRoleMap[roleID]
			if roleName == "" {
				roleName = data.AzureRoleMap[a.Properties.RoleDefinitionID]
			}
			if roleName == "" {
				roleName = roleID
			}

			pdf.SetFont("Arial", "B", 11)
			pdf.SetXY(15, y)
			pdf.Cell(0, 6, fmt.Sprintf("Role: %s", roleName))

			pdf.SetFont("Arial", "", 10)
			pdf.SetXY(20, y+8)
			pdf.Cell(0, 5, "Scope: Subscription")
			y += 20
		}
	} else {
		pdf.SetFont("Arial", "", 11)
		pdf.SetXY(15, y)
		pdf.Cell(0, 6, "No direct subscription-level rights found.")
		y += 12
	}

	// Section 3: Group-Based Rights
	y += 8
	if y > 250 {
		pdf.AddPage()
		y = 20
	}
	pdf.SetY(y)
	pdf.SetFont("Arial", "B", 14)
	pdf.Cell(0, 8, "GROUP-BASED RIGHTS")
	y += 12

	if len(groupBasedAssignments) > 0 {
		for _, info := range groupBasedAssignments {
			a := info.Assignment
			if y > 250 {
				pdf.AddPage()
				y = 20
			}

			roleID := ExtractRoleGUID(a.Properties.RoleDefinitionID)
			roleName := data.AzureRoleMap[roleID]
			if roleName == "" {
				roleName = data.AzureRoleMap[a.Properties.RoleDefinitionID]
			}
			if roleName == "" {
				roleName = roleID
			}

			// Check if this assignment overlaps with others (same role+scope from different groups)
			overlapKey := roleID + "|" + a.Properties.Scope
			isOverlapping := len(overlapMap[overlapKey]) > 1

			// Set red color for overlapping assignments
			if isOverlapping {
				pdf.SetTextColor(255, 0, 0) // Red
			}

			pdf.SetFont("Arial", "B", 11)
			pdf.SetXY(15, y)
			pdf.Cell(0, 6, fmt.Sprintf("Role: %s", roleName))

			// Reset to black
			pdf.SetTextColor(0, 0, 0)

			pdf.SetFont("Arial", "", 10)
			pdf.SetXY(20, y+8)
			pdf.Cell(0, 5, fmt.Sprintf("Assigned To: %s", info.GroupName))

			yOffset := 14.0

			// Show "Also granted via" in red for overlapping assignments
			if isOverlapping {
				var others []string
				for _, g := range overlapMap[overlapKey] {
					if g != info.GroupName {
						others = append(others, g)
					}
				}
				if len(others) > 0 {
					pdf.SetTextColor(255, 0, 0) // Red
					pdf.SetXY(20, y+yOffset)
					pdf.Cell(0, 5, fmt.Sprintf("Also granted via: %s", strings.Join(others, ", ")))
					pdf.SetTextColor(0, 0, 0) // Reset to black
					yOffset += 6
				}
			}

			// Show nested group chain if inherited
			if len(info.NestedChain) > 0 {
				chainStr := "User => " + strings.Join(info.NestedChain, " => ")
				pdf.SetXY(20, y+yOffset)
				pdf.Cell(40, 5, "Membership Path: ")
				pdf.SetX(60)
				// Use MultiCell for wrapping long paths (width 135mm to fit page)
				pdf.MultiCell(135, 5, chainStr, "", "L", false)
				// Calculate how many lines were used
				lines := pdf.GetY() - (y + yOffset)
				if lines < 5 {
					lines = 5
				}
				yOffset += lines + 1
			}

			// Show scope - display exact resource name
			rgName, resourceName := parseResourceScope(a.Properties.Scope)
			if resourceName != "" && rgName != "" {
				pdf.SetXY(20, y+yOffset)
				pdf.Cell(0, 5, fmt.Sprintf("Resource: %s", resourceName))
				yOffset += 6
				pdf.SetXY(20, y+yOffset)
				pdf.Cell(0, 5, fmt.Sprintf("Resource Group: %s", rgName))
				yOffset += 6
			} else if resourceName != "" {
				// Resource without resource group (subscription-level resource)
				pdf.SetXY(20, y+yOffset)
				pdf.Cell(0, 5, fmt.Sprintf("Resource: %s", resourceName))
				yOffset += 6
			} else if rgName != "" {
				pdf.SetXY(20, y+yOffset)
				pdf.Cell(0, 5, fmt.Sprintf("Resource Group: %s", rgName))
				yOffset += 6
			} else {
				pdf.SetXY(20, y+yOffset)
				pdf.Cell(0, 5, "Scope: Subscription")
				yOffset += 6
			}

			y += yOffset + 6
		}
	} else {
		pdf.SetFont("Arial", "", 11)
		pdf.SetXY(15, y)
		pdf.Cell(0, 6, "No group-based rights found.")
	}
}

// addSubscriptionDetailsForSub renders subscription details for a specific subscription in multi-sub mode
// Split into 3 sections: Resource-Level Rights, Subscription-Level Rights, Group-Based Rights
func addSubscriptionDetailsForSub(pdf *gofpdf.Fpdf, data PDFReportData, subData SubscriptionData) {
	pdf.AddPage()

	// Horizontal line
	pdf.SetDrawColor(0, 0, 0)
	pdf.SetLineWidth(0.5)
	pdf.Line(10, 15, 200, 15)

	// Title
	pdf.SetFont("Arial", "B", 16)
	pdf.SetXY(10, 20)
	pdf.Cell(0, 10, fmt.Sprintf("SUBSCRIPTION: %s", strings.ToUpper(subData.SubscriptionName)))

	pdf.SetFont("Arial", "", 10)
	pdf.SetXY(10, 32)
	pdf.Cell(0, 6, fmt.Sprintf("Subscription ID: %s", subData.SubscriptionID))

	y := 45.0

	// Build group name map for quick lookup
	groupNameMap := make(map[string]string)
	for _, g := range data.Groups {
		groupNameMap[g.ID] = g.DisplayName
	}

	// Categorize assignments into 3 groups
	type assignmentInfo struct {
		Assignment    azure.RoleAssignment
		GroupID       string   // Empty for direct user assignments
		GroupName     string   // Group display name if group-based
		NestedChain   []string // Nested group chain if inherited
	}

	var resourceLevelAssignments []assignmentInfo   // Direct user assignments at resource/RG level
	var subscriptionLevelAssignments []assignmentInfo // Direct user assignments at subscription level
	var groupBasedAssignments []assignmentInfo       // All group-based assignments

	// Process direct user assignments
	for _, a := range subData.Assignments {
		// Skip management groups (shown in NON SUBSCRIPTION RIGHTS section)
		if strings.Contains(strings.ToLower(a.Properties.Scope), "/managementgroups/") {
			continue
		}

		// Only include direct user assignments
		if data.UserInfo != nil && a.Properties.PrincipalID == data.UserInfo.ID {
			if strings.Contains(strings.ToLower(a.Properties.Scope), "/resourcegroups/") {
				resourceLevelAssignments = append(resourceLevelAssignments, assignmentInfo{Assignment: a})
			} else {
				subscriptionLevelAssignments = append(subscriptionLevelAssignments, assignmentInfo{Assignment: a})
			}
		}
	}

	// Process group-based assignments
	seenGroupAssignments := make(map[string]bool)
	for groupID, assignments := range subData.GroupRoleAssignments {
		groupName := groupNameMap[groupID]
		if groupName == "" {
			groupName = groupID
		}

		// Get nested chain if available
		nestedChain := subData.GroupChains[groupID]

		for _, a := range assignments {
			// Skip management groups
			if strings.Contains(strings.ToLower(a.Properties.Scope), "/managementgroups/") {
				continue
			}

			// Deduplicate
			key := a.ID + "|" + groupID
			if seenGroupAssignments[key] {
				continue
			}
			seenGroupAssignments[key] = true

			groupBasedAssignments = append(groupBasedAssignments, assignmentInfo{
				Assignment:  a,
				GroupID:     groupID,
				GroupName:   groupName,
				NestedChain: nestedChain,
			})
		}
	}

	// Build overlap map: role+scope -> list of group names (for detecting overlapping permissions)
	overlapMap := make(map[string][]string)
	for _, info := range groupBasedAssignments {
		overlapKey := ExtractRoleGUID(info.Assignment.Properties.RoleDefinitionID) + "|" + info.Assignment.Properties.Scope
		overlapMap[overlapKey] = append(overlapMap[overlapKey], info.GroupName)
	}

	// Section 1: Resource-Level Rights
	pdf.SetY(y)
	pdf.SetFont("Arial", "B", 14)
	pdf.Cell(0, 8, "Direct Assignment: RESOURCE-LEVEL RIGHTS")
	y += 12

	if len(resourceLevelAssignments) > 0 {
		for _, info := range resourceLevelAssignments {
			a := info.Assignment
			if y > 250 {
				pdf.AddPage()
				y = 20
			}

			roleID := ExtractRoleGUID(a.Properties.RoleDefinitionID)
			roleName := data.AzureRoleMap[roleID]
			if roleName == "" {
				roleName = data.AzureRoleMap[a.Properties.RoleDefinitionID]
			}
			if roleName == "" {
				roleName = roleID
			}

			rgName, resourceName := parseResourceScope(a.Properties.Scope)

			pdf.SetFont("Arial", "B", 11)
			pdf.SetXY(15, y)
			pdf.Cell(0, 6, fmt.Sprintf("Role: %s", roleName))

			pdf.SetFont("Arial", "", 10)
			if resourceName != "" {
				pdf.SetXY(20, y+8)
				pdf.Cell(0, 5, fmt.Sprintf("Resource: %s", resourceName))
				pdf.SetXY(20, y+14)
				pdf.Cell(0, 5, fmt.Sprintf("Resource Group: %s", rgName))
				y += 26
			} else {
				pdf.SetXY(20, y+8)
				pdf.Cell(0, 5, fmt.Sprintf("Resource Group: %s", rgName))
				y += 20
			}
		}
	} else {
		pdf.SetFont("Arial", "", 11)
		pdf.SetXY(15, y)
		pdf.Cell(0, 6, "No direct resource-level rights found.")
		y += 12
	}

	// Section 2: Subscription-Level Rights
	y += 8
	if y > 250 {
		pdf.AddPage()
		y = 20
	}
	pdf.SetY(y)
	pdf.SetFont("Arial", "B", 14)
	pdf.Cell(0, 8, "Direct Assignment: SUBSCRIPTION-LEVEL RIGHTS")
	y += 12

	if len(subscriptionLevelAssignments) > 0 {
		for _, info := range subscriptionLevelAssignments {
			a := info.Assignment
			if y > 250 {
				pdf.AddPage()
				y = 20
			}

			roleID := ExtractRoleGUID(a.Properties.RoleDefinitionID)
			roleName := data.AzureRoleMap[roleID]
			if roleName == "" {
				roleName = data.AzureRoleMap[a.Properties.RoleDefinitionID]
			}
			if roleName == "" {
				roleName = roleID
			}

			pdf.SetFont("Arial", "B", 11)
			pdf.SetXY(15, y)
			pdf.Cell(0, 6, fmt.Sprintf("Role: %s", roleName))

			pdf.SetFont("Arial", "", 10)
			pdf.SetXY(20, y+8)
			pdf.Cell(0, 5, "Scope: Subscription")
			y += 20
		}
	} else {
		pdf.SetFont("Arial", "", 11)
		pdf.SetXY(15, y)
		pdf.Cell(0, 6, "No direct subscription-level rights found.")
		y += 12
	}

	// Section 3: Group-Based Rights
	y += 8
	if y > 250 {
		pdf.AddPage()
		y = 20
	}
	pdf.SetY(y)
	pdf.SetFont("Arial", "B", 14)
	pdf.Cell(0, 8, "GROUP-BASED RIGHTS")
	y += 12

	if len(groupBasedAssignments) > 0 {
		for _, info := range groupBasedAssignments {
			a := info.Assignment
			if y > 250 {
				pdf.AddPage()
				y = 20
			}

			roleID := ExtractRoleGUID(a.Properties.RoleDefinitionID)
			roleName := data.AzureRoleMap[roleID]
			if roleName == "" {
				roleName = data.AzureRoleMap[a.Properties.RoleDefinitionID]
			}
			if roleName == "" {
				roleName = roleID
			}

			// Check if this assignment overlaps with others (same role+scope from different groups)
			overlapKey := roleID + "|" + a.Properties.Scope
			isOverlapping := len(overlapMap[overlapKey]) > 1

			// Set red color for overlapping assignments
			if isOverlapping {
				pdf.SetTextColor(255, 0, 0) // Red
			}

			pdf.SetFont("Arial", "B", 11)
			pdf.SetXY(15, y)
			pdf.Cell(0, 6, fmt.Sprintf("Role: %s", roleName))

			// Reset to black
			pdf.SetTextColor(0, 0, 0)

			pdf.SetFont("Arial", "", 10)
			pdf.SetXY(20, y+8)
			pdf.Cell(0, 5, fmt.Sprintf("Assigned To: %s", info.GroupName))

			yOffset := 14.0

			// Show "Also granted via" in red for overlapping assignments
			if isOverlapping {
				var others []string
				for _, g := range overlapMap[overlapKey] {
					if g != info.GroupName {
						others = append(others, g)
					}
				}
				if len(others) > 0 {
					pdf.SetTextColor(255, 0, 0) // Red
					pdf.SetXY(20, y+yOffset)
					pdf.Cell(0, 5, fmt.Sprintf("Also granted via: %s", strings.Join(others, ", ")))
					pdf.SetTextColor(0, 0, 0) // Reset to black
					yOffset += 6
				}
			}

			// Show nested group chain if inherited
			if len(info.NestedChain) > 0 {
				chainStr := "User => " + strings.Join(info.NestedChain, " => ")
				pdf.SetXY(20, y+yOffset)
				pdf.Cell(40, 5, "Membership Path: ")
				pdf.SetX(60)
				// Use MultiCell for wrapping long paths (width 135mm to fit page)
				pdf.MultiCell(135, 5, chainStr, "", "L", false)
				// Calculate how many lines were used
				lines := pdf.GetY() - (y + yOffset)
				if lines < 5 {
					lines = 5
				}
				yOffset += lines + 1
			}

			// Show scope - display exact resource name
			rgName, resourceName := parseResourceScope(a.Properties.Scope)
			if resourceName != "" && rgName != "" {
				pdf.SetXY(20, y+yOffset)
				pdf.Cell(0, 5, fmt.Sprintf("Resource: %s", resourceName))
				yOffset += 6
				pdf.SetXY(20, y+yOffset)
				pdf.Cell(0, 5, fmt.Sprintf("Resource Group: %s", rgName))
				yOffset += 6
			} else if resourceName != "" {
				// Resource without resource group (subscription-level resource)
				pdf.SetXY(20, y+yOffset)
				pdf.Cell(0, 5, fmt.Sprintf("Resource: %s", resourceName))
				yOffset += 6
			} else if rgName != "" {
				pdf.SetXY(20, y+yOffset)
				pdf.Cell(0, 5, fmt.Sprintf("Resource Group: %s", rgName))
				yOffset += 6
			} else {
				pdf.SetXY(20, y+yOffset)
				pdf.Cell(0, 5, "Scope: Subscription")
				yOffset += 6
			}

			y += yOffset + 6
		}
	} else {
		pdf.SetFont("Arial", "", 11)
		pdf.SetXY(15, y)
		pdf.Cell(0, 6, "No group-based rights found.")
	}
}

func addNonSubscriptionRights(pdf *gofpdf.Fpdf, data PDFReportData) {
	pdf.AddPage()

	// Horizontal line
	pdf.SetDrawColor(0, 0, 0)
	pdf.SetLineWidth(0.5)
	pdf.Line(10, 15, 200, 15)

	// Title
	pdf.SetFont("Arial", "B", 16)
	pdf.SetXY(10, 20)
	pdf.Cell(0, 10, "NON SUBSCRIPTION RIGHTS")

	// Entra ID Administrative Roles
	y := 40.0
	pdf.SetY(y)
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(0, 8, "ENTRA ID ADMINISTRATIVE ROLES")

	if len(data.DirectoryRoles) > 0 {
		pdf.SetFont("Arial", "", 11)
		pdf.SetY(y + 12)
		pdf.SetX(15)
		pdf.Cell(0, 6, fmt.Sprintf("Directory Role Assignments (%d):", len(data.DirectoryRoles)))

		roleY := y + 22
		for _, dr := range data.DirectoryRoles {
			if roleY > 250 {
				pdf.AddPage()
				roleY = 20
			}

			roleName := data.EntraRoleMap[dr.RoleDefinitionID]
			if roleName == "" {
				roleName = dr.RoleDefinitionID
			}

			scope := dr.DirectoryScopeID
			if scope == "" {
				scope = "/" // Tenant-wide
			}

			pdf.SetFont("Arial", "B", 10)
			pdf.SetXY(20, roleY)
			pdf.Cell(0, 5, fmt.Sprintf("Role: %s", roleName))

			pdf.SetFont("Arial", "", 10)
			pdf.SetXY(25, roleY+6)
			pdf.Cell(0, 5, fmt.Sprintf("Scope: %s", scope))
			pdf.SetXY(25, roleY+12)
			pdf.Cell(0, 5, "Source: Directory Role Assignment")

			roleY += 22
		}
		y = roleY
	} else {
		pdf.SetFont("Arial", "", 11)
		pdf.SetY(y + 12)
		pdf.SetX(15)
		pdf.Cell(0, 6, "No Entra ID administrative role assignments found.")
		y += 22
	}

	// Management Group Level Assignments section
	if y > 240 {
		pdf.AddPage()
		y = 20
	}

	pdf.SetY(y + 10)
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(0, 8, "MANAGEMENT GROUP LEVEL ASSIGNMENTS")

	// Collect management group assignments and track which subscriptions they affect
	type mgAssignmentInfo struct {
		Assignment    azure.RoleAssignment
		Subscriptions []string
	}
	mgAssignmentMap := make(map[string]*mgAssignmentInfo)

	if len(data.Subscriptions) > 0 {
		// Multi-subscription mode
		for _, subData := range data.Subscriptions {
			for _, a := range subData.Assignments {
				if strings.Contains(strings.ToLower(a.Properties.Scope), "/managementgroups/") {
					key := a.Properties.RoleDefinitionID + "|" + a.Properties.Scope + "|" + a.Properties.PrincipalID
					if existing, ok := mgAssignmentMap[key]; ok {
						// Add subscription to existing entry if not already there
						found := false
						for _, s := range existing.Subscriptions {
							if s == subData.SubscriptionName {
								found = true
								break
							}
						}
						if !found {
							existing.Subscriptions = append(existing.Subscriptions, subData.SubscriptionName)
						}
					} else {
						mgAssignmentMap[key] = &mgAssignmentInfo{
							Assignment:    a,
							Subscriptions: []string{subData.SubscriptionName},
						}
					}
				}
			}
			// Also check group-based assignments
			for _, assignments := range subData.GroupRoleAssignments {
				for _, a := range assignments {
					if strings.Contains(strings.ToLower(a.Properties.Scope), "/managementgroups/") {
						key := a.Properties.RoleDefinitionID + "|" + a.Properties.Scope + "|" + a.Properties.PrincipalID
						if existing, ok := mgAssignmentMap[key]; ok {
							found := false
							for _, s := range existing.Subscriptions {
								if s == subData.SubscriptionName {
									found = true
									break
								}
							}
							if !found {
								existing.Subscriptions = append(existing.Subscriptions, subData.SubscriptionName)
							}
						} else {
							mgAssignmentMap[key] = &mgAssignmentInfo{
								Assignment:    a,
								Subscriptions: []string{subData.SubscriptionName},
							}
						}
					}
				}
			}
		}
	} else {
		// Single subscription mode
		for _, a := range data.Assignments {
			if strings.Contains(strings.ToLower(a.Properties.Scope), "/managementgroups/") {
				key := a.Properties.RoleDefinitionID + "|" + a.Properties.Scope + "|" + a.Properties.PrincipalID
				if _, ok := mgAssignmentMap[key]; !ok {
					mgAssignmentMap[key] = &mgAssignmentInfo{
						Assignment:    a,
						Subscriptions: []string{data.SubscriptionName},
					}
				}
			}
		}
		for _, assignments := range data.GroupRoleAssignments {
			for _, a := range assignments {
				if strings.Contains(strings.ToLower(a.Properties.Scope), "/managementgroups/") {
					key := a.Properties.RoleDefinitionID + "|" + a.Properties.Scope + "|" + a.Properties.PrincipalID
					if _, ok := mgAssignmentMap[key]; !ok {
						mgAssignmentMap[key] = &mgAssignmentInfo{
							Assignment:    a,
							Subscriptions: []string{data.SubscriptionName},
						}
					}
				}
			}
		}
	}

	if len(mgAssignmentMap) > 0 {
		pdf.SetFont("Arial", "", 11)
		pdf.SetY(y + 22)
		pdf.SetX(15)
		pdf.Cell(0, 6, fmt.Sprintf("Management Group Assignments (%d):", len(mgAssignmentMap)))

		mgY := y + 32
		for _, info := range mgAssignmentMap {
			a := info.Assignment
			if mgY > 240 {
				pdf.AddPage()
				mgY = 20
			}

			roleID := ExtractRoleGUID(a.Properties.RoleDefinitionID)
			roleName := data.AzureRoleMap[roleID]
			if roleName == "" {
				roleName = data.AzureRoleMap[a.Properties.RoleDefinitionID]
			}
			if roleName == "" {
				roleName = roleID
			}

			// Extract management group name from scope
			_, mgTarget := parseScopeInfo(a.Properties.Scope, "", "")

			principalName := data.PrincipalMap[a.Properties.PrincipalID]
			if principalName == "" {
				principalName = a.Properties.PrincipalID
			}

			assignmentType := "Group Membership"
			if data.UserInfo != nil && a.Properties.PrincipalID == data.UserInfo.ID {
				assignmentType = "Direct Assignment"
			}

			// Build inherited subscriptions string
			inheritedSubs := strings.Join(info.Subscriptions, ", ")

			pdf.SetFont("Arial", "B", 10)
			pdf.SetXY(20, mgY)
			pdf.Cell(0, 5, fmt.Sprintf("Role: %s", roleName))

			pdf.SetFont("Arial", "", 10)
			pdf.SetXY(25, mgY+6)
			pdf.Cell(0, 5, fmt.Sprintf("Target: %s", mgTarget))
			pdf.SetXY(25, mgY+12)
			pdf.Cell(0, 5, fmt.Sprintf("Assigned To: %s", principalName))
			pdf.SetXY(25, mgY+18)
			pdf.Cell(0, 5, fmt.Sprintf("Type: %s", assignmentType))
			pdf.SetXY(25, mgY+24)
			pdf.Cell(0, 5, fmt.Sprintf("Inherited By: %s", inheritedSubs))

			mgY += 34
		}
		y = mgY
	} else {
		pdf.SetFont("Arial", "", 11)
		pdf.SetY(y + 22)
		pdf.SetX(15)
		pdf.Cell(0, 6, "No management group level assignments found.")
	}
}

// parseResourceScope extracts resource group name and resource name from a scope string
// Handles both resource-group-scoped resources and subscription-level resources
func parseResourceScope(scope string) (resourceGroup, resourceName string) {
	// Use lowercase for case-insensitive matching (Azure API can return mixed case)
	scopeLower := strings.ToLower(scope)

	// Case 1: Resource within a resource group
	// e.g., /subscriptions/{id}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{name}
	if strings.Contains(scopeLower, "/resourcegroups/") {
		// Find the index in lowercase, then extract from original scope to preserve case
		idx := strings.Index(scopeLower, "/resourcegroups/")
		afterRG := scope[idx+len("/resourcegroups/"):]
		rgParts := strings.Split(afterRG, "/")
		resourceGroup = rgParts[0]

		// Check if there's a resource after the resource group
		if len(rgParts) > 2 {
			// Resource name is the last part of the path
			resourceName = rgParts[len(rgParts)-1]
		}

		return resourceGroup, resourceName
	}

	// Case 2: Subscription-level resource (no resource group in path)
	// e.g., /subscriptions/{id}/providers/Microsoft.Storage/storageAccounts/{name}
	if strings.Contains(scopeLower, "/providers/") {
		idx := strings.Index(scopeLower, "/providers/")
		afterProviders := scope[idx+len("/providers/"):]
		// Extract resource name from the provider path
		providerParts := strings.Split(afterProviders, "/")
		if len(providerParts) >= 3 {
			// Format: Microsoft.xxx/resourceType/resourceName
			resourceName = providerParts[len(providerParts)-1]
			return "", resourceName // No resource group, but has resource name
		}
	}

	return "", ""
}

func getSubscriptionDisplayName(data PDFReportData) string {
	if data.SubscriptionName != "" {
		return data.SubscriptionName
	}
	// Fallback to truncated ID if no name provided
	if len(data.SubscriptionID) > 8 {
		return fmt.Sprintf("Subscription %s...", data.SubscriptionID[:8])
	}
	return data.SubscriptionID
}

func parseScopeInfo(scope string, subscriptionID string, subscriptionName string) (scopeType, target string) {
	scopeLower := strings.ToLower(scope)

	// Check for management group scope
	if strings.Contains(scopeLower, "/providers/microsoft.management/managementgroups/") {
		idx := strings.Index(scopeLower, "/providers/microsoft.management/managementgroups/")
		afterMG := scope[idx+len("/providers/microsoft.management/managementgroups/"):]
		mgName := strings.Split(afterMG, "/")[0]
		if mgName != "" {
			return "Management Group", fmt.Sprintf("Management Group: %s", mgName)
		}
		return "Management Group", scope
	}

	if strings.Contains(scopeLower, "/resourcegroups/") {
		idx := strings.Index(scopeLower, "/resourcegroups/")
		afterRG := scope[idx+len("/resourcegroups/"):]
		rgParts := strings.Split(afterRG, "/")
		rgName := rgParts[0]
		if len(rgParts) > 2 {
			// Resource-level scope: extract resource type and name
			// Format: resourceGroup/providers/Microsoft.xxx/resourceType/resourceName
			resourceName := rgParts[len(rgParts)-1]
			return "Resource", fmt.Sprintf("Resource: %s (RG: %s)", resourceName, rgName)
		}
		return "ResourceGroup", fmt.Sprintf("Resource Group: %s", rgName)
	}

	if strings.HasSuffix(scopeLower, strings.ToLower(subscriptionID)) || strings.Contains(scopeLower, "/subscriptions/") {
		displayName := subscriptionName
		if displayName == "" {
			// Fallback to truncated ID
			if len(subscriptionID) > 8 {
				displayName = subscriptionID[:8] + "..."
			} else {
				displayName = subscriptionID
			}
		}
		return "Subscription", fmt.Sprintf("Subscription: %s", displayName)
	}

	return "Unknown", scope
}
