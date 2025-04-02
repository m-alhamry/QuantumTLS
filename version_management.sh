#!/bin/bash
set -e

# Ensure we are in a Git repository
if [ ! -d .git ]; then
    echo "Error: Not in a Git repository"
    exit 1
fi

# Check for uncommitted changes
if [ -n "$(git status --porcelain)" ]; then
    echo "Error: There are uncommitted changes. Please commit or stash them."
    exit 1
fi

# Get current version from VERSION file
if [ -f VERSION ]; then
    version=$(cat VERSION)
else
    version="0.0.0"
fi

# Get bump type from argument
bump_type=$1
if [ -z "$bump_type" ]; then
    echo "Usage: $0 [major|minor|patch]"
    exit 1
fi

# Parse version into major, minor, patch
major=${version%%.*}
rest=${version#*.}
minor=${rest%%.*}
patch=${rest#*.}

# Bump version based on type
case $bump_type in
    major)
        major=$((major + 1))
        minor=0
        patch=0
        ;;
    minor)
        minor=$((minor + 1))
        patch=0
        ;;
    patch)
        patch=$((patch + 1))
        ;;
    *)
        echo "Error: Invalid bump type: $bump_type"
        exit 1
        ;;
esac

new_version="${major}.${minor}.${patch}"

# Get last tag
last_tag=$(git describe --tags --abbrev=0 2>/dev/null || echo "")

# Get commit messages since last tag
if [ -z "$last_tag" ]; then
    commits=$(git log --pretty=format:"%s")
else
    commits=$(git log ${last_tag}..HEAD --pretty=format:"%s")
fi

# Format changelog section
changelog="## [${new_version}] - $(date +%Y-%m-%d)\n"
while read -r line; do
    changelog="${changelog}- ${line}\n"
done <<< "$commits"

# Prepend to CHANGELOG.md
if [ -f CHANGELOG.md ]; then
    temp_file=$(mktemp)
    echo -e "$changelog\n$(cat CHANGELOG.md)" > "$temp_file"
    mv "$temp_file" CHANGELOG.md
else
    echo -e "$changelog" > CHANGELOG.md
fi

# Update VERSION file
echo "$new_version" > VERSION

# Commit changes
git add VERSION CHANGELOG.md
git commit -m "Prepare for version ${new_version}"

echo "Version bumped to ${new_version} and changelog updated."