#! /usr/bin/env python3
'''
'''
import sys
import requests
from urllib.parse import urlparse
from collections import defaultdict
import markdown
import os

def get_cookies(url):
    # Assume no protocol/scheme is provided, so add http://
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    try:
        # Use a custom User-Agent to mimic a real browser
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, allow_redirects=True, headers=headers, timeout=10)
        final_url = response.url
        status_code = response.status_code
        
        cookies = response.cookies
        cookie_data = []

        # Include both cookies from the response and any set-cookie headers
        for cookie in cookies:
            cookie_info = {
                'name': cookie.name,
                'value': cookie.value,  # Include the cookie value
                'httponly': cookie.has_nonstandard_attr('HttpOnly'),
                'secure': cookie.secure,
                'samesite': cookie.get_nonstandard_attr('SameSite'),
                'path': cookie.path,
                'domain': cookie.domain,  # Include the domain
                'expires': cookie.expires  # Include expiration
            }
            cookie_data.append(cookie_info)

        # Check for additional cookies in Set-Cookie headers
        for header, value in response.headers.items():
            if header.lower() == 'set-cookie':
                # Parse the Set-Cookie header and add it to cookie_data
                # You may need to implement a custom parser for this
                continue

        return {
            'url': url,
            'final_url': final_url,
            'status_code': status_code,
            'cookies': cookie_data
        }

    except Exception as e:
        print(f"Error processing {url}: {str(e)}")
        return {
            'url': url,
            'final_url': None,
            'status_code': None,
            'cookies': []
        }

def get_cookie_stats(all_cookie_data):
    total_cookies = sum(len(site['cookies']) for site in all_cookie_data)
    httponly_count = sum(cookie['httponly'] for site in all_cookie_data for cookie in site['cookies'])
    secure_count = sum(cookie['secure'] for site in all_cookie_data for cookie in site['cookies'])
    
    samesite_count = 0
    samesite_strict = 0
    samesite_lax = 0
    samesite_none = 0
    
    path_count = 0
    path_non_root = 0

    for site in all_cookie_data:
        for cookie in site['cookies']:
            if cookie['samesite']:
                samesite_count += 1
                if cookie['samesite'].lower() == 'strict':
                    samesite_strict += 1
                elif cookie['samesite'].lower() == 'lax':
                    samesite_lax += 1
                elif cookie['samesite'].lower() == 'none':
                    samesite_none += 1
            
            if cookie['path']:
                path_count += 1
                if cookie['path'] != '/':
                    path_non_root += 1

    markdown_content = f"""
# Cookie Analysis Report

## Summary Statistics

| Statistic | Value |
|-----------|-------|
| Total Cookies | {total_cookies} |
| HttpOnly Cookies | {httponly_count} |
| Secure Cookies | {secure_count} |
| SameSite Cookies | {samesite_count} |
| SameSite Strict | {samesite_strict} |
| SameSite Lax | {samesite_lax} |
| SameSite None | {samesite_none} |
| Cookies with Path | {path_count} |
| Cookies with Non-Root Path | {path_non_root} |

## Detailed Site Information

| URL | Final URL | Status Code | Number of Cookies | Cookie:Attribute:Policy | Path |
|-----|-----------|-------------|-------------------|-------------------------|------|
"""

    for site in all_cookie_data:
        cookie_attributes = []
        paths = set()
        
        for cookie in site['cookies']:
            attributes = []
            if cookie['httponly']:
                attributes.append('HttpOnly')
            if cookie['secure']:
                attributes.append('Secure')
            if cookie['samesite']:
                attributes.append(f"SameSite={cookie['samesite']}")
            
            cookie_attributes.append(f"{cookie['name']}:{','.join(attributes)}")
            
            if cookie['path']:
                paths.add(cookie['path'])
        
        cookie_attribute_policy = "<br>".join(cookie_attributes)
        path_value = ", ".join(paths)
        
        markdown_content += f"| {site['url']} | {site['final_url']} | {site['status_code']} | {len(site['cookies'])} | {cookie_attribute_policy} | {path_value} |\n"

    markdown_content += """

## Individual Cookie Details

| URL | Cookie Name | Value | HttpOnly | Secure | SameSite | Path | Domain | Expires |
|-----|-------------|-------|----------|--------|----------|------|--------|---------|
"""

    for site in all_cookie_data:
        for cookie in site['cookies']:
            markdown_content += f"| {site['url']} | {cookie['name']} | {cookie['value']} | {cookie['httponly']} | {cookie['secure']} | {cookie['samesite']} | {cookie['path']} | {cookie['domain']} | {cookie['expires']} |\n"

    return markdown_content

def main():
    # Get ARASM002@ODU.EDU file from ../../Nelson/3 path starting from the current working directory
    # input_file = os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, "Nelson", "3", "ARASM002@ODU.EDU")
    input_file = os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, "Nelson", "3", "ARASM002_test")
    
    with open(input_file, 'r') as f:
        urls = [line.strip() for line in f.readlines()]


    all_cookie_data = []
    for url in urls:
        cookie_data = get_cookies(url)
        all_cookie_data.append(cookie_data)

    markdown_content = get_cookie_stats(all_cookie_data)
    
    with open("README.md", "w") as f:
        f.write(markdown_content)


if __name__ == "__main__":
    main()
