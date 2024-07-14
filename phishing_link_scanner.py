import tkinter as tk
from tkinter import messagebox
import re
import requests

class PhishingLinkChecker:
    def __init__(self):
        self.suspicious_keywords = [
            "login", "secure", "account", "update", "verify", "confirm", "bank", "signin", "webmail"
        ]
        self.suspicious_tld = ['.top', '.xyz', '.club', '.info', '.gq']
        self.url_pattern = re.compile(
            r'^(?:http|https)://(?:www\.)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}.*$'
        )

    def is_suspicious(self, url):
        # Check for suspicious keywords and TLDs
        for keyword in self.suspicious_keywords:
            if keyword in url:
                return True
        if any(url.endswith(tld) for tld in self.suspicious_tld):
            return True
        return False

    def is_valid_url(self, url):
        return self.url_pattern.match(url)

    def check_url(self, url):
        if not self.is_valid_url(url):
            return None  # Invalid URL format
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                return self.is_suspicious(url)
            else:
                return False
        except requests.exceptions.RequestException:
            return False

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Phishing Link Checker")
        self.root.geometry("400x200")

        self.checker = PhishingLinkChecker()

        tk.Label(root, text="Enter URL to check:", font=("Helvetica", 12)).pack(pady=10)

        self.url_entry = tk.Entry(root, width=40)
        self.url_entry.pack(pady=5)

        self.check_button = tk.Button(root, text="Check URL", command=self.check_url, font=("Helvetica", 12))
        self.check_button.pack(pady=10)

        self.result_label = tk.Label(root, text="", font=("Helvetica", 12))
        self.result_label.pack(pady=10)

    def check_url(self):
        url = self.url_entry.get().strip()  # Strip whitespace
        if not url:
            self.result_label.config(text="Please enter a URL.", fg="orange")
            return
        
        result = self.checker.check_url(url)
        if result is None:
            self.result_label.config(text="Invalid URL format.", fg="orange")
        elif result:
            self.result_label.config(text=f"The URL '{url}' is potentially a phishing link.", fg="red")
        else:
            self.result_label.config(text=f"The URL '{url}' appears to be safe.", fg="green")

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()



