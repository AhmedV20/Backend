#!/bin/bash
set -e

echo "Starting DotnetAuth API..."

# Create required directories
mkdir -p wwwroot/profile-pictures/defaults

# Set environment variables
export ASPNETCORE_ENVIRONMENT=Production
export ASPNETCORE_URLS=http://0.0.0.0:$PORT

# Start the application
dotnet DotnetAuth.dll
