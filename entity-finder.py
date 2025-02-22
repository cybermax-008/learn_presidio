import google.generativeai as genai
import json
import os
from dotenv import load_dotenv
from presidio_analyzer import PatternRecognizer

load_dotenv()

def setup_gemini(api_key: str):
    """Initialize Gemini with API key."""
    genai.configure(api_key=api_key)
    return genai.GenerativeModel('gemini-2.0-flash')

def create_prompt(text: str) -> str:
    """Create a structured prompt for Gemini."""
    return f"""Analyze the following text and identify potential custom entities that should be detected as PII:

Text: {text}

For each entity type you identify, provide:
1. Entity name (in UPPERCASE)
2. Regular expression patterns that could match it
3. Context words that might appear around it
4. Confidence score (between 0 and 1)

Format the response as a JSON array with objects containing:
{{
    "entity_name": "ENTITY_NAME",
    "patterns": ["regex_pattern1", "regex_pattern2"],
    "context": ["context_word1", "context_word2"],
    "score": 0.8
}}"""

def analyze_text(model, text: str) -> list:
    """Analyze text using Gemini and return custom entities."""
    try:
        response = model.generate_content(create_prompt(text))
        # Extract JSON from response
        json_str = response.text.strip()
        if json_str.startswith("```json"):
            json_str = json_str[7:-3]
        
        return json.loads(json_str)
            
    except Exception as e:
        print(f"Error analyzing text: {e}")
        return []

def create_recognizers(entities: list) -> list:
    """Create Presidio PatternRecognizers from custom entities."""
    recognizers = []
    for entity in entities:
        recognizer = PatternRecognizer(
            supported_entity=entity["entity_name"],
            patterns=[{"regex": pattern, "score": entity["score"]} for pattern in entity["patterns"]],
            context=entity["context"]
        )
        recognizers.append(recognizer)
    return recognizers

def main():
    # Get API key from environment
    api_key = os.getenv("GEMINI_API_KEY")
    print(api_key)
    if not api_key:
        raise ValueError("Please set GEMINI_API_KEY environment variable")
    
    # Initialize Gemini
    model = setup_gemini(api_key)
    
    # Example text
    text = """Customer reported issue with account #ACC123456. 
              Their employee ID is EMP-2024-789 and they're calling from 
              department code DEP/IT/2024."""
    
    # Analyze text and get custom entities
    entities = analyze_text(model, text)
    
    # Print identified entities
    for entity in entities:
        print("\nIdentified Entity:")
        print(f"Name: {entity['entity_name']}")
        print(f"Patterns: {entity['patterns']}")
        print(f"Context: {entity['context']}")
        print(f"Score: {entity['score']}")
    
    # Create Presidio recognizers
    recognizers = create_recognizers(entities)
    print(f"\nCreated {len(recognizers)} Presidio recognizers")
    
    return recognizers

if __name__ == "__main__":
    main() 