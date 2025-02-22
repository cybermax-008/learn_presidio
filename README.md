# Presidio-Based Data Sanitization for LLMs

## Description

This project provides a set of tools and techniques for sanitizing sensitive data in text, specifically tailored for preparing data for use with Large Language Models (LLMs). It leverages the power of the Presidio library to identify and anonymize Personally Identifiable Information (PII) and other sensitive entities, ensuring data privacy and compliance. The focus is on creating LLM-ready formats that maintain data utility while minimizing the risk of exposing sensitive information.  This includes techniques for anonymizing, de-anonymizing, and redacting sensitive entities.

## Key Features

*   **PII Detection:** Utilizes Presidio's robust PII detection capabilities to identify a wide range of sensitive entities.
*   **Customizable Sanitization:** Offers flexible sanitization strategies, including redaction, substitution, and pseudonymization.
*   **LLM-Ready Formatting:**  Ensures that the sanitized data is suitable for use with LLMs, preserving data structure and relationships where possible.
*   **Anonymization and De-anonymization:** Provides methods for both anonymizing sensitive data and, when necessary and authorized, de-anonymizing it in a controlled manner.
*   **Extensible Architecture:** Designed to be easily extended with custom PII recognizers and sanitization rules.

## Installation

1.  **Install Presidio and other dependencies:**

    ```bash
    pip install presidio_analyzer presidio_anonymizer
    # Install any other project-specific dependencies here
    pip install -r requirements.txt
    ```

2.  **Clone the repository:**

    ```bash
    git clone [repository_url]
    cd [project_directory]
    ```

## Usage

 **Basic Sanitization:**

    ```python
    from sanitization import sanitize_text

    text = "My name is John Doe and my phone number is 555-123-4567."
    sanitized_text = sanitize_text(text)
    print(sanitized_text)
    # Expected output (example): My name is <PERSON> and my phone number is <PHONE_NUMBER>.
    ```
## Reference

- Documentation of [Microsoft Presidio](https://microsoft.github.io/presidio/)



