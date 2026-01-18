# Azure-PDF-Reports

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://golang.org/)

A CLI tool for generating Azure role assignment reports in PDF format. This tool provides comprehensive security auditing capabilities for Azure permissions by analyzing role assignments across multiple subscriptions, including nested group memberships and Entra ID administrative roles.

## About

Azure-PDF-Reports is designed for security teams and Azure administrators who need to audit and document user access across their Azure environment. The tool performs a deep analysis of:

- Azure RBAC role assignments at subscription scope
- Group-based role assignments with nested membership chain tracking
- Entra ID (Azure AD) directory roles and administrative units
- Management group level role assignments

The interactive CLI guides you through selecting subscriptions and target users/groups, then generates a professional PDF report suitable for security reviews and compliance documentation.

## Features

- **Interactive CLI** - Survey-based interface for easy navigation
- **Multi-subscription support** - Analyze role assignments across multiple subscriptions simultaneously
- **Direct and group-based role assignments** - Captures both direct user assignments and those inherited through groups
- **Nested group membership tracking** - Traces the complete chain of nested group memberships
- **Entra ID administrative roles** - Includes Microsoft Entra ID directory role assignments
- **Management group level assignments** - Detects role assignments at management group scope
- **PDF report generation** with:
  - Cover page with user information and summary statistics
  - Executive summary with access matrix
  - Non-subscription rights section (Entra ID roles)
  - Detailed subscription breakdowns
  - Overlapping permission detection
  - High-risk permission calculations
- **Azure Blob Storage upload** - Optional cloud-only storage mode with automatic local cleanup

## Prerequisites

- **Go 1.21+** - For building from source
- **Azure service principal** - With appropriate permissions (see Required Permissions below)
- **API Access**:
  - Azure Management API (`https://management.azure.com/`)
  - Microsoft Graph API (`https://graph.microsoft.com/`)

## Installation

### Clone the Repository

```bash
git clone https://github.com/yourusername/Azure-PDF-Reports.git
cd Azure-PDF-Reports
```

### Build from Source

```bash
# Standard build (outputs binary for current platform)
go build -o azure-role-report

# Cross-platform release build (creates releases/ directory)
./build_releases.sh
```

### Binary Output

After running `build_releases.sh`, binaries are created in the `releases/` directory:
- `azure-role-report-linux-amd64`
- `azure-role-report-darwin-amd64`
- `azure-role-report-windows-amd64.exe`

## Configuration

Create a `config.toml` file from the provided example:

```bash
cp config.example.toml config.toml
```

### Required Configuration

```toml
[authentication.service_principal]
tenant_id = "your-tenant-id-here"
client_id = "your-client-id-here"
client_secret = "your-client-secret-here"
```

### Optional Azure Blob Storage

```toml
[storage]
enabled = true
storage_account_name = "yourstorageaccount"
container_name = "pdf-reports"
sas_token = "your-sas-token"
```

When storage is enabled, PDFs are uploaded to Azure Blob Storage and the local file is automatically deleted (cloud-only mode).

## Required Permissions

The service principal requires the following permissions:

### Azure RBAC (assigned via IAM or at Management Group scope)

- `Microsoft.Authorization/roleAssignments/read`
- `Microsoft.Authorization/roleDefinitions/read`
- `Microsoft.Subscription/subscriptions/read`

### Microsoft Graph API (Application Permissions)

Configure these in **App Registrations > API Permissions > Microsoft Graph > Application permissions**:

- `User.Read.All` - For user lookup and profile data
- `GroupMember.Read.All` - For group membership enumeration
- `RoleManagement.Read.Directory` - For Entra ID directory roles

After adding permissions, click **Grant admin consent** for your organization.

## Usage

### Basic Usage

```bash
./azure-role-report
```

### Debug Logging

```bash
./azure-role-report --debug
```

Debug logs are written to `azure-role-report.log` in the current directory.

### Interactive Flow

1. **Select Subscriptions** - Choose one or more subscriptions to analyze
2. **Choose Search Type** - Search for a User or Group
3. **Enter Search Term** - Type the name to search for
4. **Select Target** - Choose the specific user or group from results
5. **Generate Report** - PDF is generated locally (and optionally uploaded)

### Example Session

```bash
$ ./azure-role-report
Authenticating with Azure Management API...
Authenticating with Microsoft Graph API...

=== Interactive Mode ===
Fetching available subscriptions...

? Select subscriptions to analyze:
  [x] Production (12345678-1234-1234-1234-123456789012)
  [ ] Development (87654321-4321-4321-4321-210987654321)

Selected 1 subscription(s)

? Search for:
  User
  Group

? Enter user name to search: John Doe

Searching for users matching 'John Doe'...

? Select user:
  John Doe (john.doe@example.com)
  John Smith (john.smith@example.com)

Processing: John Doe...
  Generated: john_doe_2025-01-18_14-30-22.pdf

=== Summary ===
Generated 1 PDF report(s)
```

## Example Output

The generated PDF includes the following sections:

### 1. Cover Page
- User display name and email
- Report generation timestamp (UK timezone)
- Summary statistics (total subscriptions, role assignments, groups)

### 2. Executive Summary
- Access matrix showing all subscriptions and role assignments
- High-risk permissions highlight
- Non-subscription rights summary

### 3. Non-Subscription Rights
- Entra ID directory roles
- Management group level assignments

### 4. Subscription Details
For each subscription:
- Direct role assignments
- Group-based role assignments
- Nested group membership chains

### 5. Appendices
- Complete list of group memberships
- Principal name resolution

### Filename Format

PDFs are named using the format: `{username}_{timestamp}.pdf`

Example: `john_doe_2025-01-18_14-30-22.pdf`

Timestamps use UK timezone (Europe/London) format: `YYYY-MM-DD_HH-MM-SS`

## Project Structure

```
Azure-PDF-Reports/
├── main.go              # CLI entry point and interactive flow
├── config/              # Configuration management
│   └── config.go        # TOML config loading and struct
├── auth/                # Azure & Graph authentication
│   └── auth.go          # OAuth token acquisition
├── azure/               # Azure Management API calls
│   └── roles.go         # Role assignments and definitions
├── graph/               # Microsoft Graph API calls
│   └── graph.go         # Users, groups, directory roles
├── output/              # PDF generation
│   ├── pdf.go           # PDF creation with gofpdf
│   └── formatter.go     # Data formatting for output
├── storage/             # Azure Blob Storage integration
│   └── storage.go       # PDF upload functionality
├── logger/              # Logging utilities
│   └── logger.go        # File and console logging
├── config.example.toml  # Configuration template
├── build_releases.sh    # Cross-platform build script
├── go.mod               # Go module definition
└── go.sum               # Dependency checksums
```

## Building from Source

### Standard Build

```bash
go build -o azure-role-report
```

This creates a binary named `azure-role-report` for your current platform.

### Cross-Platform Release Build

```bash
./build_releases.sh
```

This builds binaries for:
- Linux (amd64)
- macOS (amd64)
- Windows (amd64)

Binaries are placed in `releases/` directory with platform-specific naming.

## Security Considerations

1. **Credential Storage** - The `config.toml` file contains sensitive credentials. Add it to `.gitignore` and never commit it to version control:
   ```bash
   echo "config.toml" >> .gitignore
   ```

2. **Principle of Least Privilege** - Grant the service principal only the permissions required for its intended use. Consider limiting access to specific subscriptions.

3. **Report Sensitivity** - Generated PDFs contain detailed access information and should be treated as sensitive documents. Consider using Azure Blob Storage with appropriate access controls.

4. **Service Principal Security** - Rotate client secrets regularly and monitor usage through Azure AD sign-in logs.

## Dependencies

- [github.com/spf13/cobra](https://github.com/spf13/cobra) - CLI framework
- [github.com/AlecAivazis/survey/v2](https://github.com/AlecAivazis/survey) - Interactive prompts
- [github.com/jung-kurt/gofpdf](https://github.com/jung-kurt/gofpdf) - PDF generation
- [github.com/BurntSushi/toml](https://github.com/BurntSushi/toml) - TOML parsing
- [github.com/Azure/azure-storage-blob-go](https://github.com/Azure/azure-storage-blob-go) - Azure Blob Storage
