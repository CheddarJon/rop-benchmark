#!/bin/bash


BASE_DIR="$(dirname "$0")/../binaries/x86/synthetic/vuln"

# Loop through each file matching the pattern ex<xxx>.vuln64.gadgetplanner.output
for FILE in "$BASE_DIR"/ex*.vuln64.gadgetplanner.output; do
    if [[ -f "$FILE" ]]; then
        echo "Checking file: $FILE"
        # Grep for the keyword "Plan_found"
        grep "Plan_found" "$FILE" && echo "Keyword 'Plan_found' found in $FILE"
    else
        echo "No matching files found."
    fi
done

