# SecretScan 🔐

SecretScan is a simple source-code security scanner that detects potentially exposed credentials such as API keys, passwords, tokens, and private-key blocks.

## Features

- Pattern-based secret detection
- Entropy check for suspicious high-randomness strings
- Risk classification
- Secret masking in the results
- Simple web dashboard
- Basic automated tests

## Project Structure

```text
SecretScan/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
├── scanner/
│   ├── __init__.py
│   ├── detector.py
│   ├── patterns.py
│   └── entropy.py
├── templates/
│   └── index.html
├── static/
│   └── style.css
└── tests/
    └── test_detector.py
```

## Run Locally

1. Install Python 3.10+.
2. Open a terminal inside the project folder.
3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Start the application:

```bash
python app.py
```

5. Open `http://127.0.0.1:5000` in your browser.

## Example

Paste safe demo text such as:

```text
API_KEY = "sk_test_1234567890abcdef"
password = "DemoPassword123!"
```

SecretScan reports the type and risk without displaying the complete value.

> Use only test data or credentials you are authorized to scan. Never paste real production secrets into a public repository or demo website.

## Technologies

- Python
- Flask
- Regular expressions
- Shannon entropy
- HTML/CSS/JavaScript

## Future Improvements

- Scan complete project folders
- Git pre-commit hook
- More secret signatures
- JSON/PDF reports
- GitHub Actions integration
- False-positive reduction
