#!/usr/bin/env python3
"""
Assignment 3, CS 433/533 Web Security, Fall 2024
Anton Rasmussen

Cookie report for 100 of the Mozilla top 500 web sites

This script reads a list of URLs from an input file, fetches each URL,
extracts cookies along with their attributes, compiles statistics, and
generates a Markdown report that includes HTTP response details.

Usage:
    nohup python cookie_summary.py input_file.txt [output_report.md] > output.txt &

Note:
- If the [output_report.md] is not specified, it defaults to 'README.md'.
- 'output.txt' allows us to see a run log.
"""

import argparse
import logging
import os
import statistics
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException


def is_valid_url(url):
    """
    Validate a URL to ensure it has a proper scheme/protocol.

    Parameters:
    - url (str): The URL to validate.

    Returns:
    - bool: True if the URL is valid, False otherwise.
    """
    parsed = urlparse(url)
    return all([parsed.scheme in ('http', 'https'), parsed.netloc])


def parse_set_cookie_headers(set_cookie_headers, default_domain):
    """
    Parse 'Set-Cookie' headers to extract cookie attributes.

    Parameters:
    - set_cookie_headers (list): List of 'Set-Cookie' header strings.
    - default_domain (str): The domain of the URL if 'Domain' attribute is absent.

    Returns:
    - list: List of dictionaries containing cookie attributes.
    """
    cookies = []
    for header in set_cookie_headers:
        parts = header.split(';')
        name_value = parts[0].strip()
        if '=' in name_value:
            name, value = name_value.split('=', 1)
        else:
            # Skip invalid cookie
            continue

        cookie_info = {
            'name': name.strip(),
            'httponly': False,
            'secure': False,
            'samesite': False,
            'path': '/',
            'domain': default_domain,
            'expires': None,
        }

        # Extract attributes
        for attr in parts[1:]:
            attr = attr.strip()
            if attr.lower() == 'httponly':
                cookie_info['httponly'] = True
            elif attr.lower() == 'secure':
                cookie_info['secure'] = True
            elif attr.lower().startswith('samesite='):
                samesite_value = attr.split('=', 1)[1]
                cookie_info['samesite'] = f"True: {samesite_value}"
            elif attr.lower().startswith('path='):
                path_value = attr.split('=', 1)[1]
                cookie_info['path'] = path_value
            elif attr.lower().startswith('domain='):
                domain_value = attr.split('=', 1)[1]
                cookie_info['domain'] = domain_value
            elif attr.lower().startswith('expires='):
                expires_value = attr.split('=', 1)[1]
                cookie_info['expires'] = expires_value

        cookies.append(cookie_info)
    return cookies


def get_cookies(url):
    """
    Fetch headers and cookies from a given URL using HEAD and GET methods.

    Parameters:
    - url (str): The URL to fetch headers and cookies from.

    Returns:
    - dict: A dict containing the URL, final URL after redirects, status code, headers, and cookie data.
    """
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    headers = {
        'User-Agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/91.0.4472.124 Safari/537.36'
        )
    }

    response_details = {'status_code': None, 'headers': {}}
    cookie_data = []
    final_url = url

    # Step 1: Use HEAD request to get headers and avoid downloading content
    try:
        response = requests.head(url, allow_redirects=True, headers=headers, timeout=10)
        final_url = response.url
        response_details['status_code'] = response.status_code
        response_details['headers'] = dict(response.headers)
    except RequestException as e:
        logging.error(f"Error processing HEAD request for {url}: {str(e)}")

    # Step 2: Use GET request to collect cookies without downloading the full content
    try:
        response = requests.get(url, allow_redirects=True, headers=headers, timeout=10, stream=True)
        final_url = response.url  # Update final URL in case of redirects
        # Collect raw cookies from headers
        default_domain = urlparse(final_url).hostname
        raw_cookies = response.headers.get('Set-Cookie', None)
        
        if raw_cookies:
            # Multiple cookies might be separated by commas
            raw_cookies = raw_cookies.split(',')
            cookie_data = parse_set_cookie_headers(raw_cookies, default_domain)
    except RequestException as e:
        logging.error(f"Error processing GET request for {url}: {str(e)}")

    # Return both header and cookie data
    return {
        'url': url,
        'final_url': final_url,
        'status_code': response_details['status_code'],
        'cookies': cookie_data,
        'response_details': response_details,
    }




def get_cookie_stats(all_cookie_data):
    """
    Compile statistics from the collected cookie data and generate Markdown content.
    Saves raw headers to individual files.
    """
    os.makedirs('response_files_2', exist_ok=True)
    
    for site in all_cookie_data:
        url_parsed = urlparse(site['url'])
        hostname = url_parsed.netloc.replace(':', '_')  # Windows compatibility
        filename = f"response_files_2/{hostname}.txt"
        
        with open(filename, 'w', encoding='utf-8') as f:
            response_details = site.get('response_details', {})
            f.write(f"URL: {site['url']}\n")
            f.write(f"Final URL: {site.get('final_url', 'N/A')}\n")
            f.write(f"Status Code: {response_details.get('status_code', 'N/A')}\n")
            f.write("\nHeaders:\n")
            headers = response_details.get('headers', {})
            for header_name, header_value in headers.items():
                f.write(f"{header_name}: {header_value}\n")

    # Initialize counters
    total_cookies = 0
    httponly_count = 0
    secure_count = 0
    samesite_count = 0
    samesite_strict = 0
    samesite_lax = 0
    samesite_none = 0
    path_count = 0
    path_non_root = 0
    cookies_per_site = []

    for site in all_cookie_data:
        num_cookies = len(site['cookies'])
        cookies_per_site.append(num_cookies)
        cookies = site['cookies']
        total_cookies += len(cookies)

        for cookie in cookies:
            if cookie.get('httponly'):
                httponly_count += 1

            if cookie.get('secure'):
                secure_count += 1

            samesite = cookie.get('samesite')
            if samesite != False:
                samesite_count += 1
                samesite_value = samesite.lower()
                if 'strict' in samesite_value:
                    samesite_strict += 1
                elif 'lax' in samesite_value:
                    samesite_lax += 1
                elif 'none' in samesite_value:
                    samesite_none += 1

            path = cookie.get('path')
            if path:
                path_count += 1
                if path != '/':
                    path_non_root += 1

    # Compute statistical summaries
    min_cookies = min(cookies_per_site)
    max_cookies = max(cookies_per_site)
    mean_cookies = statistics.mean(cookies_per_site)
    median_cookies = statistics.median(cookies_per_site)

    markdown_content = (
        f"""## Assignment 3, CS 433/533 Web Security, Fall 2024 
### Anton Rasmussen

For this assignment, we created a script to analyze 100 of the Mozilla top 500 web sites.

This script (`cookie_summary.py`) reads a list of URLs from an input file (`ARASM002@ODU.EDU`), 
fetches each URL, extracts cookies along with their attributes, compiles statistics, and
generates a Markdown report that includes HTTP response details.

```
.
|__ README.md -- the markdown file that you are reading; this is this assignment's final report
|__ cookie_summary.py -- a Python script that reads a list of URLs and helps us produce the final report
|__ output.txt -- the cookie_summary.py script run log (Note that there were two ERRORs)
|__ output_2.txt -- the cookie_summary.py script run log for getting response_files_2
|__ response_files -- directory containing detailed HTTP responses for each site
|__ response_files_2 -- the directory containing raw HTTP response headers for each site
```

## Extra Credit

- The title of slide 48 in week 4 is a literary reference. Briefly describe this literary reference, both the origin and the meaning in the slides.

I believe the reference in question is "Turtles All The Way Down." From my understanding this comes from a conversation with a teacher 
and a student where the student asks about the Earth and the teacher says the Earth rests on the back of a turtle. 
Then the student asks, "Well, what does the turtle rest on?" and the teacher says "It's turtles all the way down." 
Often this is used when people ask about philosophical concepts like "if God made everything, who made God?" It's this idea that 
at a certain point we have to admit that the problem results in saying something like "God made God," which is infitely recursive. 

Similarly, in the example cited on the slide, if only top-level windows are checked for vulnerabilities then frames can hold malicious code; but, 
if only the first frame within a window is checked then frames within frames can hold vulnerabilites, etc. etc. 

Another way of looking at it is to say that we must be vigilant at every level, all the way down!


## Summary Statistics

| Statistic                  | Value          |
|----------------------------|----------------|
| Total Sites Analyzed       | {len(all_cookie_data)} |
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

## Detailed Site Information

| URL | Status Code | Number of Cookies | Cookie Attributes | Final URL |
|-----|-------------|-------------------|-------------------|-----------|
"""
    )

    # Add detailed site information
    for site in all_cookie_data:
        url = site['url']
        status_code = site['status_code']
        num_cookies = len(site['cookies'])
        
        # Format cookie attributes
        cookie_attrs = []
        for cookie in site['cookies']:
            attrs = []
            if cookie['httponly']:
                attrs.append('HttpOnly')
            if cookie['secure']:
                attrs.append('Secure')
            if cookie['samesite']:
                attrs.append(f"SameSite={cookie['samesite']}")
            cookie_attrs.append(f"{cookie['name']}: {', '.join(attrs)}")
        
        cookie_attr_str = '; '.join(cookie_attrs)
        final_url = site['final_url'] if site['final_url'] else 'N/A'
        
        markdown_content += f"| {url} | {status_code} | {num_cookies} | {cookie_attr_str} | {final_url} |\n"

    markdown_content += """

## HTTP Response Details

Response details for each site have been saved to individual files in the 'response_files' directory.
"""

    return markdown_content


def main():
    """
    Main function to orchestrate cookie analysis.
    """
    parser = argparse.ArgumentParser(description="Cookie Analysis Script")
    parser.add_argument(
        'input_file', help='Path to the input file containing URLs'
    )
    parser.add_argument(
        'output_report',
        nargs='?',
        default='README.md',
        help='Path to the output Markdown report file',
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO, format='%(levelname)s: %(message)s'
    )

    if not os.path.exists(args.input_file):
        logging.error(f"Input file '{args.input_file}' does not exist.")
        return

    with open(args.input_file, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]

    # Prepend 'http://' since it's missing and validate URLs
    urls = [
        url if url.startswith(('http://', 'https://')) else 'http://' + url
        for url in urls
    ]
    urls = [url for url in urls if is_valid_url(url)]

    if not urls:
        logging.error('No valid URLs found in the input file.')
        return

    all_cookie_data = []
    for url in urls:
        logging.info(f"Processing URL: {url}")
        cookie_data = get_cookies(url)
        all_cookie_data.append(cookie_data)

    markdown_content = get_cookie_stats(all_cookie_data)

    with open(args.output_report, 'w', encoding='utf-8') as f:
        f.write(markdown_content)
    logging.info(f"Report generated and saved to '{args.output_report}'.")


if __name__ == '__main__':
    main()