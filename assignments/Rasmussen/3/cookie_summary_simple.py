#!/usr/bin/env python3
"""
Cookie Analysis Script

This script reads a list of URLs from an input file, fetches each URL,
extracts cookies along with their attributes, compiles statistics, and
generates a Markdown report as per the assignment requirements.

Usage:
    python cookie_analysis.py input_file.txt [output_file.md]

If the output file is not specified, it defaults to 'README.md'.
"""

import argparse
import logging
import os
import statistics
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException
from http.cookies import SimpleCookie


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
        simple_cookie = SimpleCookie()
        simple_cookie.load(header)
        for key, morsel in simple_cookie.items():
            cookie_info = {
                'name': key,
                # 'value': morsel.value,  # Omit or mask sensitive value
                'httponly': False,
                'secure': False,
                'samesite': None,
                'path': morsel['path'] if morsel['path'] else '/',
                'domain': morsel['domain'] if morsel['domain'] else default_domain,
                'expires': morsel['expires'] if morsel['expires'] else None,
            }
            # Extract flags and attributes
            attributes = header.split(';')
            for attr in attributes[1:]:
                attr = attr.strip()
                if attr.lower() == 'httponly':
                    cookie_info['httponly'] = True
                elif attr.lower() == 'secure':
                    cookie_info['secure'] = True
                elif attr.lower().startswith('samesite='):
                    samesite_value = attr.split('=', 1)[1]
                    cookie_info['samesite'] = samesite_value
            cookies.append(cookie_info)
    return cookies


def get_cookies(url):
    """
    Fetch cookies from a given URL.

    Parameters:
    - url (str): The URL to fetch cookies from.

    Returns:
    - dict: A dictionary containing the URL, final URL after redirects, status code, and cookies.
    """
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        headers = {
            'User-Agent': (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) '
                'Chrome/91.0.4472.124 Safari/537.36'
            )
        }
        response = requests.get(
            url, allow_redirects=True, headers=headers, timeout=10
        )
        final_url = response.url
        status_code = response.status_code

        # Get the default domain from the final URL
        parsed_url = urlparse(final_url)
        default_domain = parsed_url.hostname

        # Parse 'Set-Cookie' headers
        raw_cookies = []
        try:
            # Access the raw HTTP response
            raw_headers = response.raw._original_response.msg
            raw_cookies = raw_headers.get_all('Set-Cookie')
            if raw_cookies is None:
                raw_cookies = []
        except AttributeError:
            logging.warning(f"Could not access raw 'Set-Cookie' headers for {url}")
            # Fallback to response.headers (may not get all cookies)
            set_cookie = response.headers.get('Set-Cookie')
            if set_cookie:
                raw_cookies = [set_cookie]
            else:
                raw_cookies = []

        cookie_data = parse_set_cookie_headers(raw_cookies, default_domain)

        return {
            'url': url,
            'final_url': final_url,
            'status_code': status_code,
            'cookies': cookie_data
        }

    except RequestException as e:
        logging.error(f"Error processing {url}: {str(e)}")
        return {
            'url': url,
            'final_url': None,
            'status_code': None,
            'cookies': []
        }


def generate_report(all_cookie_data):
    """
    Generate a Markdown report based on the collected cookie data.

    Parameters:
    - all_cookie_data (list): A list of dictionaries containing cookie data for each URL.

    Returns:
    - str: A string containing the Markdown-formatted report.
    """
    # Collect statistics
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
        total_cookies += num_cookies

        for cookie in site['cookies']:
            if cookie.get('httponly'):
                httponly_count += 1
            if cookie.get('secure'):
                secure_count += 1
            samesite = cookie.get('samesite')
            if samesite:
                samesite_count += 1
                if samesite.lower() == 'strict':
                    samesite_strict += 1
                elif samesite.lower() == 'lax':
                    samesite_lax += 1
                elif samesite.lower() == 'none':
                    samesite_none += 1
            if cookie.get('path'):
                path_count += 1
                if cookie.get('path') != '/':
                    path_non_root += 1

    # Compute statistical summaries
    min_cookies = min(cookies_per_site)
    max_cookies = max(cookies_per_site)
    mean_cookies = statistics.mean(cookies_per_site)
    median_cookies = statistics.median(cookies_per_site)

    markdown_content = f"""# Cookie Analysis Report

## Summary Statistics

- **Total Sites Analyzed**: {len(all_cookie_data)}
- **Total Cookies Collected**: {total_cookies}
- **Min Cookies per Site**: {min_cookies}
- **Max Cookies per Site**: {max_cookies}
- **Mean Cookies per Site**: {mean_cookies:.2f}
- **Median Cookies per Site**: {median_cookies}

### Cookie Attribute Counts

- **Cookies with HttpOnly**: {httponly_count}
- **Cookies with Secure**: {secure_count}
- **Cookies with SameSite**: {samesite_count}
  - **SameSite Strict**: {samesite_strict}
  - **SameSite Lax**: {samesite_lax}
  - **SameSite None**: {samesite_none}
- **Cookies with Path**: {path_count}
  - **Non-Root Path ('/')**: {path_non_root}

## Site Summary Table

| URL | Final Status Code | Number of Cookies |
|-----|-------------------|-------------------|
"""

    for site in all_cookie_data:
        markdown_content += (
            f"| {site['url']} | {site.get('status_code', 'N/A')} | {len(site['cookies'])} |\n"
        )

    return markdown_content


def is_valid_url(url):
    """
    Validate a URL to ensure it has a proper scheme and network location.

    Parameters:
    - url (str): The URL to validate.

    Returns:
    - bool: True if the URL is valid, False otherwise.
    """
    parsed = urlparse(url)
    return all([parsed.scheme in ('http', 'https'), parsed.netloc])


def main():
    """
    Main function to orchestrate the cookie analysis.
    """
    parser = argparse.ArgumentParser(description="Cookie Analysis Script")
    parser.add_argument('input_file', help='Path to the input file containing URLs')
    parser.add_argument(
        'output_file', nargs='?', default='README.md', help='Path to the output Markdown file'
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    if not os.path.exists(args.input_file):
        logging.error(f"Input file '{args.input_file}' does not exist.")
        return

    with open(args.input_file, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]

    # Limit to 100 sites if more are provided
    urls = urls[:100]

    # Prepend 'http://' if missing and validate URLs
    urls = [
        url if url.startswith(('http://', 'https://')) else 'http://' + url
        for url in urls
    ]
    urls = [url for url in urls if is_valid_url(url)]

    if not urls:
        logging.error("No valid URLs found in the input file.")
        return

    all_cookie_data = []
    for url in urls:
        logging.info(f"Processing URL: {url}")
        cookie_data = get_cookies(url)
        all_cookie_data.append(cookie_data)

    markdown_content = generate_report(all_cookie_data)

    if os.path.exists(args.output_file):
        overwrite = 'y'  # Overwrite without prompt for the assignment
    else:
        overwrite = 'y'

    if overwrite.lower() != 'y':
        print("Operation cancelled.")
        return

    with open(args.output_file, "w") as f:
        f.write(markdown_content)

    logging.info(f"Report generated and saved to '{args.output_file}'.")


if __name__ == "__main__":
    main()
