#!/bin/bash

# Check if a version type is provided (major, minor, patch)
if [ -z "$1" ]; then
    echo "Usage: $0 [major|minor|patch]"
    exit 1
fi

# Get the latest version tag (default to v0.0.0 if no tags exist)
LATEST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")

# Extract version numbers
IFS='.' read -r -a VERSION_PARTS <<< "${LATEST_TAG#v}"
MAJOR=${VERSION_PARTS[0]}
MINOR=${VERSION_PARTS[1]}
PATCH=${VERSION_PARTS[2]}

# Increment version based on input
case $1 in
    major)
        ((MAJOR+=1))
        MINOR=0
        PATCH=0
        ;;
    minor)
        ((MINOR+=1))
        PATCH=0
        ;;
    patch)
        ((PATCH+=1))
        ;;
    *)
        echo "Invalid option: Use 'major', 'minor', or 'patch'"
        exit 1
        ;;
esac

# Create new version
NEW_VERSION="v$MAJOR.$MINOR.$PATCH"

echo "📢 New version: $NEW_VERSION"

# Generate changelog
echo "## $NEW_VERSION - $(date +"%Y-%m-%d")" > NEW_CHANGELOG.md
echo "" >> NEW_CHANGELOG.md
git log --pretty=format:"- %s (%an)" "$LATEST_TAG"..HEAD >> NEW_CHANGELOG.md
echo "" >> NEW_CHANGELOG.md
cat CHANGELOG.md >> NEW_CHANGELOG.md
mv NEW_CHANGELOG.md CHANGELOG.md

# Commit changes
git add .
git commit -m "Release $NEW_VERSION - Updated CHANGELOG.md"
git push origin main

# Create and push tag
git tag -a "$NEW_VERSION" -m "Version $NEW_VERSION"
git push origin "$NEW_VERSION"

echo "✅ Version $NEW_VERSION pushed successfully with changelog update!"