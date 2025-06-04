#!/bin/bash
set -e

echo "Starting build process..."

# Navigate to project directory
cd DotnetAuth

echo "Restoring dependencies..."
dotnet restore

echo "Building application..."
dotnet build -c Release

echo "Publishing application..."
dotnet publish -c Release -o /app/out

echo "Build completed successfully!"
