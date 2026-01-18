package storage

import (
	"azure-role-report/config"
	"azure-role-report/logger"
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/Azure/azure-storage-blob-go/azblob"
)

// UploadPDFReport uploads a PDF file to Azure Blob Storage using SAS authentication
// Parameters:
//   - cfg: Storage configuration containing account name, container, and SAS token
//   - localFilePath: Absolute path to the PDF file to upload
// Returns error if upload fails, nil on success
func UploadPDFReport(cfg config.StorageConfig, localFilePath string) error {
	// Step 1: Validate file exists
	fileInfo, err := os.Stat(localFilePath)
	if err != nil {
		return fmt.Errorf("cannot access file: %w", err)
	}

	// Step 2: Build blob URL
	blobName := generateBlobName(localFilePath)
	blobURL, err := buildBlobURL(cfg.StorageAccountName, cfg.ContainerName, blobName, cfg.SASToken)
	if err != nil {
		return fmt.Errorf("failed to build blob URL: %w", err)
	}

	// Step 3: Open file
	file, err := os.Open(localFilePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	// Step 4: Upload with context timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	_, err = azblob.UploadFileToBlockBlob(ctx, file, *blobURL, azblob.UploadToBlockBlobOptions{
		BlockSize:   4 * 1024 * 1024, // 4MB blocks
		Parallelism: 16,               // 16 parallel uploads
	})

	if err != nil {
		return fmt.Errorf("upload failed: %w", err)
	}

	logger.Info("Successfully uploaded %s (%d bytes) to %s/%s",
		filepath.Base(localFilePath), fileInfo.Size(), cfg.ContainerName, blobName)

	return nil
}

// buildBlobURL constructs the Azure Blob Storage URL with SAS token
func buildBlobURL(accountName, containerName, blobName, sasToken string) (*azblob.BlockBlobURL, error) {
	// Construct URL: https://{account}.blob.core.windows.net/{container}/{blob}{sas}
	u, err := url.Parse(fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s%s",
		accountName, containerName, blobName, sasToken))
	if err != nil {
		return nil, err
	}

	// Create blob URL
	blobURL := azblob.NewBlockBlobURL(*u, azblob.NewPipeline(azblob.NewAnonymousCredential(), azblob.PipelineOptions{}))
	return &blobURL, nil
}

// generateBlobName creates a blob name from the local file name with date folder structure
// Returns: YYYY/MM/DD/filename.pdf
func generateBlobName(localFilePath string) string {
	// Get UK timezone (matches the timestamp format used in main.go)
	ukLocation, err := time.LoadLocation("Europe/London")
	if err != nil {
		ukLocation = time.UTC
	}
	ukTime := time.Now().In(ukLocation)

	// Create date folder structure: YYYY/MM/DD
	dateFolder := ukTime.Format("2006/01/02")

	// Extract filename
	filename := filepath.Base(localFilePath)

	// Combine: YYYY/MM/DD/filename.pdf
	return fmt.Sprintf("%s/%s", dateFolder, filename)
}
