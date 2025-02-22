from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

# Initialize Presidio engines
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

# Store mappings in a variable (in production, move to a secure database)
anonymized_mapping = {}

def anonymize_ticket(ticket_text):
    # Analyze text to detect PII
    analysis_results = analyzer.analyze(
        text=ticket_text,
        entities=["PERSON", "PHONE_NUMBER", "EMAIL_ADDRESS", "URL", "IP_ADDRESS"],
        language="en"
    )
    print(analysis_results)
    # Counters for unique placeholders
    entity_counters = {
        "PERSON": 0,
        "PHONE_NUMBER": 0,
        "EMAIL_ADDRESS": 0,
        "URL": 0,
        "IP_ADDRESS": 0
    }

    # Custom anonymization logic
    def generate_placeholder(entity_type):
        entity_counters[entity_type] += 1
        return f"[{entity_type}_{entity_counters[entity_type]}]"

    operators = {
        "PERSON": OperatorConfig("custom", {"lambda": lambda x: generate_placeholder("PERSON")}),
        "PHONE_NUMBER": OperatorConfig("custom", {"lambda": lambda x: generate_placeholder("PHONE_NUMBER")}),
        "EMAIL_ADDRESS": OperatorConfig("custom", {"lambda": lambda x: generate_placeholder("EMAIL_ADDRESS")}),
        "URL": OperatorConfig("custom", {"lambda": lambda x: generate_placeholder("URL")}),
        "IP_ADDRESS": OperatorConfig("custom", {"lambda": lambda x: generate_placeholder("IP_ADDRESS")}),
    }

    # Anonymize the text
    anonymized_result = anonymizer.anonymize(
        text=ticket_text,
        analyzer_results=analysis_results,
        operators=operators
    )

    # Store original-to-anonymized mappings
    for result in analysis_results:
        original_value = ticket_text[result.start:result.end]
        entity_type = result.entity_type
        placeholder = f"[{entity_type}_{entity_counters[entity_type]}]"
        anonymized_mapping[placeholder] = original_value

    return anonymized_result.text

def deanonymize_ticket(anonymized_text):
    # Use regex to find all placeholders like [ENTITY_TYPE_N]
    import re
    pattern = r"\[([A-Z_]+_\d+)\]"
    deanonymized_text = anonymized_text

    # Replace each placeholder with its original value
    for placeholder in re.findall(pattern, anonymized_text):
        full_placeholder = f"[{placeholder}]"
        if full_placeholder in anonymized_mapping:
            original_value = anonymized_mapping[full_placeholder]
            deanonymized_text = deanonymized_text.replace(full_placeholder, original_value)
        else:
            deanonymized_text = deanonymized_text.replace(full_placeholder, "[NOT_FOUND]")

    return deanonymized_text

# Example usage
ticket = """
Customer: John Doe
Phone: 555-123-4567
Email: john.doe@example.com
Website: https://example.com
IP: 192.168.1.1
Issue: Unable to login
687987y9
9u9u9
575756869
"""

anonymized_text = anonymize_ticket(ticket)
print("Anonymized Ticket:")
print(anonymized_text)


# Test de-anonymization
deanonymized_text = deanonymize_ticket(anonymized_text)
print("De-anonymized Ticket:")
print(deanonymized_text)