
from email import policy
from email.parser import BytesParser
from pathlib import Path


def analyze_email(file_path):
    """Read an .eml file and extract its headers and text body."""

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"Email file not found: {path}")

    with path.open("rb") as file:
        message = BytesParser(policy=policy.default).parse(file)

    body_parts = []

    if message.is_multipart():
        for part in message.walk():
            if part.get_content_type() == "text/plain":
                try:
                    content = part.get_content()
                    if isinstance(content, str):
                        body_parts.append(content)
                except (LookupError, UnicodeError):
                    continue
    elif message.get_content_type() == "text/plain":
        try:
            body_parts.append(message.get_content())
        except (LookupError, UnicodeError):
            body_parts.append("")

    return {
        "sender": str(message.get("From", "")),
        "recipient": str(message.get("To", "")),
        "subject": str(message.get("Subject", "")),
        "body": "\n".join(body_parts),
        "headers": {
            str(name): str(value)
            for name, value in message.items()
        },
    }


if __name__ == "__main__":
    sample_path = Path("samples/sample_email.eml")

    try:
        result = analyze_email(sample_path)
        print("Email parsed successfully!")
        print(f"Sender: {result['sender']}")
        print(f"Recipient: {result['recipient']}")
        print(f"Subject: {result['subject']}")
        print(f"Body:\n{result['body']}")
    except (OSError, ValueError) as error:
        print(f"Error: {error}")
