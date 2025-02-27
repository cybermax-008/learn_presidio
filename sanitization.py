from presidio_analyzer import AnalyzerEngine
from typing import Dict
from presidio_anonymizer import AnonymizerEngine, DeanonymizeEngine, OperatorConfig
from presidio_anonymizer.operators import Operator, OperatorType
from presidio_analyzer import PatternRecognizer, Pattern
import json
import os

class InstanceCounterAnonymizer(Operator):
    """
    Anonymizer which replaces the entity value
    with an instance counter per entity.
    """

    REPLACING_FORMAT = "<{entity_type}_{index}>"

    def operate(self, text: str, params: Dict = None) -> str:
        """Anonymize the input text."""

        entity_type: str = params["entity_type"]

        # entity_mapping is a dict of dicts containing mappings per entity type
        entity_mapping: Dict[Dict:str] = params["entity_mapping"]

        entity_mapping_for_type = entity_mapping.get(entity_type)
        if not entity_mapping_for_type:
            # Initialize the dictionary for this entity type
            entity_mapping[entity_type] = {}
            new_text = self.REPLACING_FORMAT.format(
                entity_type=entity_type, index=0
            )
            # Add the first entity to the mapping
            entity_mapping[entity_type][text] = new_text
        else:
            if text in entity_mapping_for_type:
                return entity_mapping_for_type[text]

            previous_index = self._get_last_index(entity_mapping_for_type)
            new_text = self.REPLACING_FORMAT.format(
                entity_type=entity_type, index=previous_index + 1
            )
            # Add the new entity to the mapping
            entity_mapping[entity_type][text] = new_text

        return new_text

    @staticmethod
    def _get_last_index(entity_mapping_for_type: Dict) -> int:
        """Get the last index for a given entity type."""

        def get_index(value: str) -> int:
            return int(value.split("_")[-1][:-1])

        indices = [get_index(v) for v in entity_mapping_for_type.values()]
        if not indices:
            return -1  # Return -1 if there are no indices yet, so the next index will be 0
        return max(indices)

    def validate(self, params: Dict = None) -> None:
        """Validate operator parameters."""

        if "entity_mapping" not in params:
            raise ValueError("An input Dict called `entity_mapping` is required.")
        if "entity_type" not in params:
            raise ValueError("An entity_type param is required.")

    def operator_name(self) -> str:
        return "entity_counter"

    def operator_type(self) -> OperatorType:
        return OperatorType.Anonymize

class InstanceCounterDeanonymizer(Operator):
    """
    Deanonymizer which replaces the unique identifier 
    with the original text.
    """

    def operate(self, text: str, params: Dict = None) -> str:
        """Anonymize the input text."""

        entity_type: str = params["entity_type"]

        # entity_mapping is a dict of dicts containing mappings per entity type
        entity_mapping: Dict[Dict:str] = params["entity_mapping"]

        if entity_type not in entity_mapping:
            raise ValueError(f"Entity type {entity_type} not found in entity mapping!")
        if text not in entity_mapping[entity_type].values():
            raise ValueError(f"Text {text} not found in entity mapping for entity type {entity_type}!")

        return self._find_key_by_value(entity_mapping[entity_type], text)

    @staticmethod
    def _find_key_by_value(entity_mapping, value):
        for key, val in entity_mapping.items():
            if val == value:
                return key
        return None
    
    def validate(self, params: Dict = None) -> None:
        """Validate operator parameters."""

        if "entity_mapping" not in params:
            raise ValueError("An input Dict called `entity_mapping` is required.")
        if "entity_type" not in params:
            raise ValueError("An entity_type param is required.")

    def operator_name(self) -> str:
        return "entity_counter_deanonymizer"

    def operator_type(self) -> OperatorType:
        return OperatorType.Deanonymize

def save_entity_mapping(mapping, analyzed_entities=None, filename="entity_mapping.json", original_text=None, min_score_threshold=0.6):
    """Save the entity mapping and analyzed entities to a JSON file.
    
    Args:
        mapping: Dictionary containing entity mappings
        analyzed_entities: List of analyzed entity results from Presidio
        filename: Path to the output JSON file
        original_text: The original text used for extracting entity values
        min_score_threshold: Minimum confidence score threshold for entities (default: 0.6)
    """
    try:
        # Convert the nested dict to a serializable format
        output_data = {
            "mappings": {},
            "analyzed_entities": [],
            "metadata": {
                "min_score_threshold": min_score_threshold,
                "total_entities_detected": len(analyzed_entities) if analyzed_entities else 0,
                "entities_above_threshold": 0
            }
        }
        
        # Process mappings
        for entity_type, entities in mapping.items():
            output_data["mappings"][entity_type] = {}
            for original, anonymized in entities.items():
                output_data["mappings"][entity_type][original] = anonymized
        
        # Process analyzed entities if provided
        if analyzed_entities and original_text:
            # Count entities above threshold
            entities_above_threshold = 0
            
            for entity in analyzed_entities:
                entity_text = original_text[entity.start:entity.end]
                
                # Only include entities with score >= threshold in the JSON
                if entity.score >= min_score_threshold:
                    entities_above_threshold += 1
                    output_data["analyzed_entities"].append({
                        "entity_type": entity.entity_type,
                        "entity_text": entity_text,
                        "score": entity.score
                    })
            
            # Update metadata
            output_data["metadata"]["entities_above_threshold"] = entities_above_threshold
        
        with open(filename, 'w') as f:
            json.dump(output_data, f, indent=2)
        print(f"Entity data saved to {filename}")
        print(f"Included {output_data['metadata']['entities_above_threshold']} entities with score >= {min_score_threshold}")
        return True
    except Exception as e:
        print(f"Error saving entity data: {e}")
        return False

def load_custom_entities(filename="custom_entities.json"):
    """Load custom entities from a JSON file."""
    try:
        with open(filename, 'r') as f:
            entities = json.load(f)
        print(f"Loaded {len(entities)} custom entities from {filename}")
        return entities
    except Exception as e:
        print(f"Error loading custom entities from {filename}: {e}")
        return []

def create_custom_recognizers(entities):
    """Create Presidio recognizers from custom entity definitions."""
    recognizers = []
    for entity in entities:
        try:
            # Create Pattern objects for each regex pattern
            patterns = []
            for pattern in entity["patterns"]:
                patterns.append(
                    Pattern(
                        name=f"{entity['entity_name']}_pattern",
                        regex=pattern,
                        score=entity["score"]
                    )
                )
            
            # Create the recognizer
            recognizer = PatternRecognizer(
                supported_entity=entity["entity_name"],
                patterns=patterns,
                context=entity.get("context", [])
            )
            recognizers.append(recognizer)
            print(f"Created recognizer for {entity['entity_name']}")
        except Exception as e:
            print(f"Error creating recognizer for {entity['entity_name']}: {e}")
    
    return recognizers

def anonymize_ticket(ticket_text, min_score_threshold=0.6):
    """
    Anonymize ticket text by replacing PII entities with unique identifiers.
    
    Args:
        ticket_text: The text to anonymize
        min_score_threshold: Minimum confidence score threshold for entities (default: 0.6)
    """
    # Initialize Presidio engines
    analyzer = AnalyzerEngine()

    # Load custom entities and create recognizers
    custom_entities = load_custom_entities()
    custom_recognizers = create_custom_recognizers(custom_entities)
    
    # Add custom recognizers to the analyzer
    for recognizer in custom_recognizers:
        analyzer.registry.add_recognizer(recognizer)

    anonymizer = AnonymizerEngine()
    anonymizer.add_anonymizer(InstanceCounterAnonymizer)
    
    # Create a mapping between entity types and counters
    entity_mapping = dict()

    # Define entity types to detect (standard + custom)
    entity_types = ["PERSON", "PHONE_NUMBER", "EMAIL_ADDRESS", "URL", "IP_ADDRESS"]
    
    # Add custom entity types
    for entity in custom_entities:
        entity_types.append(entity["entity_name"])
    
    # Analyze text to detect PII
    all_analysis_results = analyzer.analyze(
        text=ticket_text,
        entities=entity_types,
        language="en"
    )
    
    # Filter out entities with score below the threshold
    analysis_results = [entity for entity in all_analysis_results if entity.score >= min_score_threshold]
    
    print(f"Analyzed the ticket for PII entities! Found {len(all_analysis_results)} entities.")
    print(f"After filtering (score >= {min_score_threshold}): {len(analysis_results)} entities.")
    
    # Create operator config for all entity types
    operator_config = {
        "DEFAULT": OperatorConfig("entity_counter", {"entity_mapping": entity_mapping})
    }
    
    # Anonymize the text
    anonymized_result = anonymizer.anonymize(
        text=ticket_text,
        analyzer_results=analysis_results,
        operators=operator_config
    )
    print("Anonymized the ticket!")
    
    # Print summary of entity mapping
    print(f"Entity mapping contains {sum(len(entities) for entities in entity_mapping.values())} total entities")
    for entity_type, entities in entity_mapping.items():
        print(f"  {entity_type}: {len(entities)} unique entities")

    # Return both filtered and unfiltered results for the JSON file
    return anonymized_result, entity_mapping, all_analysis_results

def deanonymize_ticket(anonymized_result, anonymized_mapping):
    deanonymizer_engine = DeanonymizeEngine()
    deanonymizer_engine.add_deanonymizer(InstanceCounterDeanonymizer)

    # Check if there are any entities to deanonymize
    if not anonymized_mapping:
        print("No entities to deanonymize!")
        return anonymized_result.text
        
    # Create operator config for all entity types
    operator_config = {
        "DEFAULT": OperatorConfig("entity_counter_deanonymizer", {"entity_mapping": anonymized_mapping})
    }

    deanonymized_result = deanonymizer_engine.deanonymize(
        anonymized_result.text, 
        anonymized_result.items,
        operators=operator_config
    )   
    print("Deanonymized the ticket!")
    return deanonymized_result

def main():
    # Set the minimum confidence score threshold
    min_score_threshold = 0.6
    
    with open("raw_ticket_conversation.txt", "r") as file:
        ticket = file.read()

    anonymized_result, mapping, analyzed_entities = anonymize_ticket(
        ticket, 
        min_score_threshold=min_score_threshold
    )
    
    with open("anonymized_ticket_conversation.txt", "w") as file:
        file.write(anonymized_result.text)
    
    # Save the entity mapping and analyzed entities to a JSON file
    save_entity_mapping(
        mapping, 
        analyzed_entities, 
        original_text=ticket,
        min_score_threshold=min_score_threshold
    )
    
    deanonymized_result = deanonymize_ticket(anonymized_result, mapping)
    with open("deanonymized_ticket_conversation.txt", "w") as file:
        if isinstance(deanonymized_result, str):
            file.write(deanonymized_result)
        else:
            file.write(deanonymized_result.text)
    
    print("\nSanitization process complete!")
    print(f"Files created: anonymized_ticket_conversation.txt, entity_mapping.json, deanonymized_ticket_conversation.txt")

if __name__ == "__main__":
    main()
