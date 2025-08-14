import requests
from bs4 import BeautifulSoup

LOGIN_PAGE_URL = "https://example.com/login"      # replace
LOGIN_POST_URL = "https://example.com/session"    # replace

def try_login(username, password):
    with requests.Session() as s:
        # Step 1: Get CSRF token (if the site uses one)
        r = s.get(LOGIN_PAGE_URL, timeout=15)
        r.raise_for_status()

        soup = BeautifulSoup(r.text, "html.parser")
        csrf_input = soup.select_one("input[name=csrfmiddlewaretoken]")
        csrf_token = csrf_input["value"] if csrf_input else ""

        

        # Step 2: Send login POST request
        payload = {
            "username": username,  # change to match site's form field names
            "password": password,
            "csrfmiddlewaretoken": csrf_token,  # remove if not needed
        }

        headers = {
            "Referer": LOGIN_PAGE_URL
        }

        r = s.post(LOGIN_POST_URL, data=payload, headers=headers, timeout=15)
        r.raise_for_status()

        # Step 3: Check success
        return "Logout" in r.text or "My Account" in r.text

# Don't forget to Delete the line Below,when push to production !!!!
# Test credential 3z_Us3r_001, H@iyah_1200-34-123

# Read usernames and passwords from file
with open("creds.txt", "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line or "," not in line:
            continue
        user, pwd = line.split(",", 1)
        print(f"Trying: {user} / {pwd}")
        if try_login(user, pwd):
            print(f"✅ Login success: {user} / {pwd}")
        else:
            print(f"❌ Login failed: {user} / {pwd}")
