#!/bin/bash

# Cookie Analysis Script

# This script reads a list of URLs from an input file, fetches each URL,
# extracts cookies along with their attributes, compiles statistics, and
# generates a Markdown report as per the assignment requirements.

# Usage:
#     ./cookie_analysis.sh input_file.txt [output_file.md]

# If the output file is not specified, it defaults to 'README.md'.

# Ensure that we have at least one argument (input file)
if [ $# -lt 1 ]; then
    echo "Usage: $0 input_file.txt [output_file.md]"
    exit 1
fi

input_file="$1"
output_file="${2:-README.md}"

# Initialize counters
total_sites=0
total_cookies=0
httponly_count=0
secure_count=0
samesite_count=0
samesite_strict=0
samesite_lax=0
samesite_none=0
path_count=0
path_non_root=0

# Create an array to store per-site cookie counts
declare -a cookies_per_site=()

# Create a temporary file to store per-site data
tmp_site_data=$(mktemp)

# Read the input file line by line
while IFS= read -r url; do
    # Skip empty lines
    [ -z "$url" ] && continue

    # Limit to 100 sites
    if [ "$total_sites" -ge 100 ]; then
        break
    fi

    total_sites=$((total_sites + 1))

    echo "Processing URL: $url"

    # Prepend http:// if missing
    if [[ ! "$url" =~ ^https?:// ]]; then
        url="http://$url"
    fi

    # Use curl to fetch headers, follow redirects, accept invalid SSL certs, use HEAD method
    # We also set max redirects to avoid infinite loops
    curl_output=$(curl -s -I -L -k --max-redirs 10 "$url")

    # Get the final status code
    # The status codes are in lines starting with "HTTP/"
    # We'll extract the last one
    status_code=$(echo "$curl_output" | grep -E "^HTTP/" | tail -1 | awk '{print $2}')

    # Extract Set-Cookie headers
    # Set-Cookie headers can appear multiple times
    # We'll collect them all
    set_cookies=$(echo "$curl_output" | grep -i '^Set-Cookie:')

    # Count the number of cookies for this site
    num_cookies=$(echo "$set_cookies" | grep -c '^')
    total_cookies=$((total_cookies + num_cookies))
    cookies_per_site+=("$num_cookies")

    # For each Set-Cookie header, parse the attributes
    echo "$set_cookies" | while IFS= read -r cookie_header; do
        # Remove "Set-Cookie:" prefix
        cookie_string=$(echo "$cookie_header" | sed 's/^Set-Cookie:[ \t]*//I')

        # The cookie_string has the format: NAME=VALUE; attr1; attr2=val2; ...

        # Get the cookie name (before the first '=' and first ';')
        cookie_name=$(echo "$cookie_string" | awk -F'=' '{print $1}' | awk -F';' '{print $1}')

        # Initialize flags
        httponly=false
        secure=false
        samesite=""
        path=""
        # Parse attributes
        # Split the cookie_string by ';'
        IFS=';' read -ra attr_array <<< "$cookie_string"

        for attr in "${attr_array[@]}"; do
            attr=$(echo "$attr" | xargs) # Trim whitespace
            attr_lower=$(echo "$attr" | tr '[:upper:]' '[:lower:]') # Convert to lowercase
            # Check for attributes
            if [[ "$attr_lower" == "httponly" ]]; then
                httponly=true
                httponly_count=$((httponly_count + 1))
            elif [[ "$attr_lower" == "secure" ]]; then
                secure=true
                secure_count=$((secure_count + 1))
            elif [[ "$attr_lower" =~ ^samesite= ]]; then
                samesite_value=$(echo "$attr" | cut -d'=' -f2)
                samesite=${samesite_value}
                samesite_count=$((samesite_count + 1))
                samesite_value_lower=$(echo "$samesite_value" | tr '[:upper:]' '[:lower:]')
                case "$samesite_value_lower" in
                    strict)
                        samesite_strict=$((samesite_strict + 1))
                        ;;
                    lax)
                        samesite_lax=$((samesite_lax + 1))
                        ;;
                    none)
                        samesite_none=$((samesite_none + 1))
                        ;;
                esac
            elif [[ "$attr_lower" =~ ^path= ]]; then
                path_value=$(echo "$attr" | cut -d'=' -f2)
                path_count=$((path_count + 1))
                if [[ "$path_value" != "/" ]]; then
                    path_non_root=$((path_non_root + 1))
                fi
            fi
        done
    done

    # Write per-site data to temporary file
    echo "$url|$status_code|$num_cookies" >> "$tmp_site_data"

done < "$input_file"

# Now compute statistics
# cookies_per_site is an array of numbers

# Compute min, max, mean, median
min_cookies=999999
max_cookies=0
sum_cookies=0
for n in "${cookies_per_site[@]}"; do
    if [ "$n" -lt "$min_cookies" ]; then
        min_cookies="$n"
    fi
    if [ "$n" -gt "$max_cookies" ]; then
        max_cookies="$n"
    fi
    sum_cookies=$((sum_cookies + n))
done

mean_cookies=$(echo "scale=2; $sum_cookies / $total_sites" | bc)

# To compute median, we need to sort the array
sorted_cookies=($(printf '%s\n' "${cookies_per_site[@]}" | sort -n))

if [ $((total_sites % 2)) -eq 1 ]; then
    # Odd number of sites
    median_index=$((total_sites / 2))
    median_cookies=${sorted_cookies[$median_index]}
else
    # Even number of sites
    index1=$((total_sites / 2 - 1))
    index2=$((total_sites / 2))
    median_cookies=$(echo "scale=2; (${sorted_cookies[$index1]} + ${sorted_cookies[$index2]}) / 2" | bc)
fi

# Generate the Markdown report

{
    echo "# Cookie Analysis Report"
    echo
    echo "## Summary Statistics"
    echo
    echo "- **Total Sites Analyzed**: $total_sites"
    echo "- **Total Cookies Collected**: $total_cookies"
    echo "- **Min Cookies per Site**: $min_cookies"
    echo "- **Max Cookies per Site**: $max_cookies"
    echo "- **Mean Cookies per Site**: $mean_cookies"
    echo "- **Median Cookies per Site**: $median_cookies"
    echo
    echo "### Cookie Attribute Counts"
    echo
    echo "- **Cookies with HttpOnly**: $httponly_count"
    echo "- **Cookies with Secure**: $secure_count"
    echo "- **Cookies with SameSite**: $samesite_count"
    echo "  - **SameSite Strict**: $samesite_strict"
    echo "  - **SameSite Lax**: $samesite_lax"
    echo "  - **SameSite None**: $samesite_none"
    echo "- **Cookies with Path**: $path_count"
    echo "  - **Non-Root Path ('/')**: $path_non_root"
    echo
    echo "## Site Summary Table"
    echo
    echo "| URL | Final Status Code | Number of Cookies |"
    echo "|-----|-------------------|-------------------|"

    # Read the per-site data from temporary file and output it
    while IFS='|' read -r url status_code num_cookies; do
        echo "| $url | $status_code | $num_cookies |"
    done < "$tmp_site_data"

} > "$output_file"

echo "Report generated and saved to '$output_file'."

# Clean up temporary file
rm "$tmp_site_data"

exit 0
