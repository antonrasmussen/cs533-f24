import os
import re
import pandas as pd

# Directories for reading and writing
input_dir = '/home/samuelflores/cs533-f24/assignments/Flores/3/output_dir'
output_dir = '/home/samuelflores/cs533-f24/assignments/Flores/3'

# Ensure the output directory exists
os.makedirs(output_dir, exist_ok=True)

# Function to check for HTML content
def contains_html(content):
    return '<html' in content.lower()

# Function to extract cookie information from each response file
def extract_cookie_data(response_file):
    with open(response_file, 'r', encoding='utf-8', errors='ignore') as file:
        content = file.read()

    # Check for HTML content
    if contains_html(content):
        print(f"Warning: {response_file} contains HTML content.")
        return {
            'site': os.path.basename(response_file).replace('.txt', ''),
            'status_code': 'Invalid (HTML content)',
            'num_cookies': 0,
            'http_only': 0,
            'secure': 0,
            'same_site': 0,
            'same_site_strict': 0,
            'same_site_lax': 0,
            'same_site_none': 0,
            'path_count': 0,
            'path_non_root_count': 0,
            'paths': 'N/A',
            'paths_not_root': 'N/A',
            'final_url': 'N/A',
        }

    # Extract all HTTP status codes, including HTTP/2 responses
    status_codes = re.findall(r'HTTP/\d(?:\.\d)?\s+(\d{3})', content)
    status_code = status_codes[-1] if status_codes else "No Status Code Found"

    # Extract Final URL from response (assuming it's included)
    final_url_match = re.search(r'^Final-URL:\s*(.*)$', content, flags=re.MULTILINE)
    if final_url_match:
        final_url = final_url_match.group(1)
    else:
        final_url = 'N/A'

    # Extract all "Set-Cookie" headers from all responses (case-insensitive)
    cookies = re.findall(r'(?i)^Set-Cookie:\s*(.*)$', content, flags=re.MULTILINE)
    num_cookies = len(cookies)

    # Initialize counts and lists
    http_only_count = 0
    secure_count = 0
    same_site_count = 0
    same_site_strict_count = 0
    same_site_lax_count = 0
    same_site_none_count = 0
    path_count = 0
    path_non_root_count = 0
    paths = []
    paths_not_root = []

    # Process each cookie
    for cookie in cookies:
        attributes = [attr.strip() for attr in cookie.split(';')]
        attributes_lower = [attr.lower() for attr in attributes]
        if 'httponly' in attributes_lower:
            http_only_count += 1
        if 'secure' in attributes_lower:
            secure_count += 1
        # Check for SameSite attribute
        same_site_attr = next((attr for attr in attributes_lower if attr.startswith('samesite=')), None)
        if same_site_attr:
            same_site_count += 1
            same_site_value = same_site_attr.split('=', 1)[1].strip().lower()
            if same_site_value == 'strict':
                same_site_strict_count += 1
            elif same_site_value == 'lax':
                same_site_lax_count += 1
            elif same_site_value == 'none':
                same_site_none_count += 1
        # Extract Path
        path_attr = next((attr for attr in attributes if attr.lower().startswith('path=')), None)
        if path_attr:
            path_count += 1
            path = path_attr.split('=', 1)[1].strip()
            paths.append(path)
            if path != '/':
                path_non_root_count += 1
                paths_not_root.append(path)

    unique_paths = ', '.join(set(paths)) if paths else "No path set"
    unique_paths_not_root = ', '.join(set(paths_not_root)) if paths_not_root else "N/A"

    return {
        'site': os.path.basename(response_file).replace('.txt', ''),
        'status_code': status_code,
        'num_cookies': num_cookies,
        'http_only': http_only_count,
        'secure': secure_count,
        'same_site': same_site_count,
        'same_site_strict': same_site_strict_count,
        'same_site_lax': same_site_lax_count,
        'same_site_none': same_site_none_count,
        'path_count': path_count,
        'path_non_root_count': path_non_root_count,
        'paths': unique_paths,
        'paths_not_root': unique_paths_not_root,
        'final_url': final_url,
    }

# Create a summary list
summary = []

# Process all the .txt files in the input directory
for filename in os.listdir(input_dir):
    if filename.endswith('.txt') and not filename.endswith('_invalid.txt'):
        response_file = os.path.join(input_dir, filename)
        site_data = extract_cookie_data(response_file)
        summary.append(site_data)

# Convert summary into a DataFrame
df = pd.DataFrame(summary)

# Filter out invalid responses
valid_df = df[df['status_code'] != 'Invalid (HTML content)']

# Compute total counts
total_sites = len(valid_df)
total_cookies = valid_df['num_cookies'].sum()
httponly_count = valid_df['http_only'].sum()
secure_count = valid_df['secure'].sum()
samesite_count = valid_df['same_site'].sum()
samesite_strict = valid_df['same_site_strict'].sum()
samesite_lax = valid_df['same_site_lax'].sum()
samesite_none = valid_df['same_site_none'].sum()
path_count = valid_df['path_count'].sum()
path_non_root = valid_df['path_non_root_count'].sum()
min_cookies = valid_df['num_cookies'].min()
max_cookies = valid_df['num_cookies'].max()
mean_cookies = valid_df['num_cookies'].mean()
median_cookies = valid_df['num_cookies'].median()

# Generate the summary statistics markdown table
summary_stats = f"""
## Summary Statistics

| Statistic                  | Value          |
|----------------------------|----------------|
| Total Sites Analyzed       | {total_sites} |
| Total Cookies Collected    | {total_cookies} |
| HttpOnly Cookies           | {httponly_count} |
| Secure Cookies             | {secure_count} |
| SameSite Cookies           | {samesite_count} |
| SameSite Strict            | {samesite_strict} |
| SameSite Lax               | {samesite_lax} |
| SameSite None              | {samesite_none} |
| Cookies with Path          | {path_count} |
| Cookies with Non-Root Path | {path_non_root} |
| Min Cookies Per Site       | {min_cookies} |
| Max Cookies Per Site       | {max_cookies} |
| Mean Cookies Per Site      | {mean_cookies:.2f} |
| Median Cookies Per Site    | {median_cookies:.2f} |
"""

# Create 'Cookie Attributes' column
def format_cookie_attributes(row):
    return (f"HttpOnly: {row['http_only']}, Secure: {row['secure']}, "
            f"SameSite: {row['same_site']} (Strict: {row['same_site_strict']}, "
            f"Lax: {row['same_site_lax']}, None: {row['same_site_none']}), "
            f"Paths: {row['path_count']} (Non-root: {row['path_non_root_count']})")

df['Cookie Attributes'] = df.apply(format_cookie_attributes, axis=1)

# Prepare the detailed site information
detailed_df = df[['site', 'status_code', 'num_cookies', 'Cookie Attributes', 'final_url']].rename(columns={
    'site': 'URL',
    'status_code': 'Status Code',
    'num_cookies': 'Number of Cookies',
    'final_url': 'Final URL'
})

detailed_table = detailed_df.to_markdown(index=False)

# Write the summary and detailed information to 'stats.md'
markdown_output_file = os.path.join(output_dir, 'stats.md')
with open(markdown_output_file, 'w', encoding='utf-8') as f:
    f.write('# Cookie Report for 100 Websites\n\n')
    f.write(summary_stats)
    f.write('\n\n## Detailed Site Information\n\n')
    f.write(detailed_table)

print(f"Markdown table and statistics saved to {markdown_output_file}")

