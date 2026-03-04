#!/bin/bash

# Define the input file with the URLs and output directory
input_file="SFLOR001@ODU.EDU"  # Replace with your actual filename if necessary
output_dir="/home/samuelflores/cs533-f24/assignments/Flores/3/output_dir"

# Ensure the output directory exists and clear it
mkdir -p "$output_dir"
rm -f "$output_dir"/*.txt  # Remove old response files to ensure a clean run

# Loop through each URL in the input file
while IFS= read -r url; do
  # Skip empty lines or comments
  if [[ -z "$url" || "$url" == \#* ]]; then
    continue
  fi

  # Clean the URL to create a valid filename
  clean_url=$(echo "$url" | sed 's/[^a-zA-Z0-9]/_/g')

  # Debugging output
  echo "Processing $url"

  # Use curl to fetch headers, following redirects and forcing HEAD method
  # Adjusted to prevent hanging and ensure compliance with assignment requirements
  response=$(timeout 40s curl -s -k -I -L -X HEAD --connect-timeout 10 --max-time 30 --max-redirs 10 "$url" -w "Final-URL: %{url_effective}\n")

  # Check if curl command succeeded
  if [ $? -ne 0 ]; then
    echo "Warning: $url could not be processed (curl error)."
    echo "$url" >> "$output_dir/failed_urls.txt"
    continue
  fi

  # Check if the response contains HTML content
  if echo "$response" | grep -qi "<html"; then
    echo "Warning: $url returned HTML content in response to HEAD request."
    echo "$response" > "$output_dir/${clean_url}_invalid.txt"
    continue  # Skip processing this response
  fi

  # Save the response headers to a file
  echo "$response" > "$output_dir/${clean_url}.txt"
  echo "Processed $url and saved to ${clean_url}.txt"

done < "$input_file"

