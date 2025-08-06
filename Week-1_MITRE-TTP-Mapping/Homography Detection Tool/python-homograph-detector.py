import difflib
import unicodedata
import idna

# ✅ STEP 1: Commonly Abused Unicode Homoglyphs
homoglyph_map = {
    'а': 'a', 'Α': 'A', 'ɑ': 'a',
    'е': 'e', 'Ε': 'E',
    'о': 'o', 'Ο': 'O',
    'р': 'p', 'Р': 'P',
    'с': 'c', 'С': 'C',
    'у': 'y', 'Υ': 'Y',
    'і': 'i', 'Ι': 'I',
    'ӏ': 'l', 'ⅼ': 'l',
    'ԁ': 'd', 'ԛ': 'q',
    'ԍ': 'g', 'һ': 'h',
    'ӽ': 'x', 'ⅰ': 'i',
}

# ✅ STEP 2: Safe whitelist domains
trusted_domains = [
    "google.com", "facebook.com", "apple.com",
    "microsoft.com", "amazon.com", "paypal.com",
    "github.com", "twitter.com", "linkedin.com"
]

def normalize_unicode(text):
    """Replace homoglyphs with Latin equivalents."""
    return ''.join(homoglyph_map.get(char, char) for char in text)

def detect_homoglyph_attack(domain):
    """Detect similarity to trusted domains using normalized forms."""
    suspicious_domain = domain.strip().lower()

    try:
        # Convert Unicode (IDN) to ASCII
        ascii_domain = idna.encode(suspicious_domain).decode('utf-8')
    except idna.IDNAError:
        print("Invalid domain name.")
        return

    normalized_domain = normalize_unicode(ascii_domain)

    print(f"\n[INFO] Checking: {domain}")
    print(f"[INFO] Normalized: {normalized_domain}")

    for safe in trusted_domains:
        similarity = difflib.SequenceMatcher(None, normalized_domain, safe).ratio()
        if similarity > 0.8 and normalized_domain != safe:
            print(f"Potential Homograph Detected: Similar to '{safe}' (Similarity: {similarity*100:.2f}%)")

def main():
    print("Homoglyph Domain Detector")
    user_input = input("Enter a domain to check (e.g. apple.com): ")
    detect_homoglyph_attack(user_input)
    
    # ...existing code...
if __name__ == "__main__":
    main()