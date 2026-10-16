# PhishGuard Lite — Email Phishing Analysis Tool

PhishGuard Lite is a Python-based educational cybersecurity tool that analyzes saved email files, identifies selected phishing indicators, calculates an explainable risk score, and generates JSON reports.

## Features

- Parses `.eml` email files.
- Extracts sender, recipient, subject, and text body.
- Detects selected suspicious phrases.
- Extracts URLs without opening them.
- Flags selected URL patterns, including unencrypted HTTP links.
- Calculates a risk score from 0 to 10.
- Classifies results as Low, Medium, or High risk.
- Generates timestamped JSON reports.
- Includes automated tests for normal and suspicious examples.

## Technologies

- Python 3.12
- Python standard library
- `unittest`
- Git and GitHub

## Project Structure

```text
PhishGuard/
|-- samples/
|   |-- sample_email.eml
|   |-- suspicious_email.eml
|-- reports/
|-- src/
|   |-- email_analyzer.py
|   |-- phishing_detector.py
|   |-- main.py
|   |-- test_phishguard.py
|-- README.md
```

## Setup

Create and activate a virtual environment.

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

No third-party Python packages are required for the current version.

## Usage

Analyze the default sample email:

```powershell
python src/main.py
```

Analyze a specific email:

```powershell
python src/main.py samples/suspicious_email.eml
```

Run the automated tests:

```powershell
python -m unittest discover -s src -p "test_*.py" -v
```

## Risk Scoring

PhishGuard assigns points to selected indicators and caps the total score at 10.

- **Low:** 0–2 points
- **Medium:** 3–5 points
- **High:** 6–10 points

The score is a heuristic based on configured rules. It is not a probability that an email is malicious.

## Reports

Analysis reports are saved as timestamped JSON files in the `reports` directory. They include email metadata, the risk score, detected indicators, and extracted URLs.

## Testing

The automated tests cover a normal email and a suspicious email containing selected warning phrases and an HTTP URL.

## Limitations

- This project uses simple rules, not machine learning.
- It may produce false positives or miss phishing attempts.
- A low score does not prove that an email is safe.
- It does not verify sender identity or perform full SPF, DKIM, or DMARC validation.
- URLs are inspected as text and are not opened.
- Attachments are not executed or analyzed.
- Use only emails you are authorized to inspect, and remove sensitive information before sharing test data.

PhishGuard Lite is an educational project and is not a replacement for a production email security gateway.

## Author

Prathvi Kumar

