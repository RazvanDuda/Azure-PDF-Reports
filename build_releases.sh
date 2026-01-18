#!/bin/bash

# Define the application name and version (optional, but good for release management)
APP_NAME="azure"
VERSION="1.0.0"
OUTPUT_DIR="releases"

# Create the output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Copy config example to release folder
cp config.example.toml "$OUTPUT_DIR/"

# Define the target platforms and architectures
# Format: "OS/ARCH"
PLATFORMS=(
    "linux/amd64"
    "windows/amd64"
)

echo "Starting Go cross-compilation for version $VERSION..."

for platform in "${PLATFORMS[@]}"; do
    # Split the platform string into GOOS and GOARCH
    IFS='/' read -r GOOS GOARCH <<< "$platform"

    # Define the output filename with appropriate extension for Windows
    OUTPUT_NAME="$APP_NAME-$VERSION-$GOOS-$GOARCH"
    if [ "$GOOS" == "windows" ]; then
        OUTPUT_NAME+=".exe"
    fi
    OUTPUT_PATH="$OUTPUT_DIR/$OUTPUT_NAME"

    echo "Building for $GOOS/$GOARCH..."
    
    # Run the go build command with specific environment variables
    # CGO_ENABLED=0 ensures static, pure Go binaries for easier cross-platform compatibility
    env GOOS="$GOOS" GOARCH="$GOARCH" CGO_ENABLED=0 go build -ldflags="-s -w" -o "$OUTPUT_PATH" .
    
    if [ $? -eq 0 ]; then
        echo "Successfully built $OUTPUT_PATH"
    else
        echo "Failed to build for $GOOS/$GOARCH"
    fi
done

echo "Build process completed. Binaries are in the '$OUTPUT_DIR' directory."
