import getpass  # to prevent shoulder surfing
import hashlib
import re
import requests

def check_password_strength(password):
    score = 0
    feedback = []

    # length
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 charachters long (12+ recommended).")

    # uppercase check
    if re.search(r"[A-Z]",password):
        score += 1
    else:
        feedback.append("Add at least one uppercase letter (A-Z).")

    # lowercase check
    if re.search(r"[a-z]",password):
        score += 1
    else:
        feedback.append("Add at least one lowercase letter (a-z).")

    # digit check
    if re.search(r"\d",password):
        score += 1
    else:
        feedback.append("Add at least one number (0-9).")

    # special character check
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]",password):
        score += 1
    else:
        feedback.append("Add at least one special character (!@#$%^&*...).")

    # score rating
    if score >= 5:
        strength = "Strong"
    elif score >= 3:
        strength = "Moderate"
    else:
        strength = "Weak"

    return strength,score,feedback


# password hash

def hash_password(password):
    # SHA 1 compute
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

    # prefix - suffix split (k-anonymity)
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    return prefix, suffix, sha1_hash


# breach check

def check_pwned_api(prefix, suffix):
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {
        "User-Agent": "CyberSecurity-Password-Checker"
    }

    try:
        response = requests.get(url,headers=headers,timeout=5)

        # raise exception for error (404,500)
        response.raise_for_status()

    except requests.RequestException as e:
        print(f"[!] Network or API Error: {e}")
        return None


    # response text
    lines = response.text.splitlines()

    for line in lines:
        parts = line.split(":")
        returned_suffix = parts[0]
        breach_count = int(parts[1])

        # suffix comparison
        if returned_suffix == suffix:
            return breach_count

    return 0



def main():
    print("=" * 50)
    print("    CYBERSECURITY PASSWORD & PWNED CHECKER    ")
    print("=" * 50)

    # secure input to avoid shoulder surfing - hides input in terminal
    password = getpass.getpass("Enter password to check (input is hidden):")

    if not password:
        print("[-] Password cannot be empty.")
        return

    print("\n[*] Analyzing password complexity (IAM Policy)...")
    strength, score, feedback = check_password_strength(password)

    print(f"    - Strength Rating : {strength}")
    print(f"    - Complexity Score : {score}/6")

    if feedback:
        print("\n[!] Recommendations to improve strength:")
        for tip in feedback:
            print(f"    * {tip}")
    else:
        print("    * Password satisfies all standard IAM complexity rules!")

    print("\n[*] Generating SHA-1 Hash & applying k-Annonymity...")
    prefix, suffix, full_hash = hash_password(password)
    print(f"    - Full SHA-1 Hash : {full_hash}")
    print(f"    - Sent to API (5) ; {prefix} (k-Annonymity Prefix)")
    print(f"    - Checked locally : {suffix} (Remaining Suffix)")

    print("\n[*] Checking 'Have I Been Pwned' database...")
    breach_count = check_pwned_api(prefix, suffix)

    print("\n" + "=" * 50)
    print("        FINAL AUDIT REPORT        ")
    print("=" * 50)

    if breach_count is None:
        print("[!] Could not complete breach check due to network/API error.")
    elif breach_count > 0:
        print(f"[CRITICAL ALERT] This password has been PWNED {breach_count:,} times!")
        print("        Do not use this password online.")
    else:
        print("[SAFE] Good news! This password was NOT found in any known breaches.")
    print("=" * 50)


if __name__ == "__main__":
    main()