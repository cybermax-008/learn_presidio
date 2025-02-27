from presidio_analyzer import AnalyzerEngine
from typing import Dict
from presidio_anonymizer import AnonymizerEngine, DeanonymizeEngine, OperatorConfig
from presidio_anonymizer.operators import Operator, OperatorType

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
            new_text = self.REPLACING_FORMAT.format(
                entity_type=entity_type, index=0
            )
            entity_mapping[entity_type] = {}

        else:
            if text in entity_mapping_for_type:
                return entity_mapping_for_type[text]

            previous_index = self._get_last_index(entity_mapping_for_type)
            new_text = self.REPLACING_FORMAT.format(
                entity_type=entity_type, index=previous_index + 1
            )

        entity_mapping[entity_type][text] = new_text
        return new_text

    @staticmethod
    def _get_last_index(entity_mapping_for_type: Dict) -> int:
        """Get the last index for a given entity type."""

        def get_index(value: str) -> int:
            return int(value.split("_")[-1][:-1])

        indices = [get_index(v) for v in entity_mapping_for_type.values()]
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

def anonymize_ticket(ticket_text):
    # Initialize Presidio engines
    analyzer = AnalyzerEngine()

    anonymizer = AnonymizerEngine()
    anonymizer.add_anonymizer(InstanceCounterAnonymizer)
    # Create a mapping between entity types and counters
    entity_mapping = dict()

    # Analyze text to detect PII
    analysis_results = analyzer.analyze(
        text=ticket_text,
        entities=["PERSON", "PHONE_NUMBER", "EMAIL_ADDRESS", "URL", "IP_ADDRESS"],
        language="en"
    )
    print("Analyzed the ticket for PII entities!")
    # Anonymize the text
    anonymized_result = anonymizer.anonymize(
        text=ticket_text,
        analyzer_results=analysis_results,
        operators={"entity_counter": OperatorConfig("entity_counter", {"entity_mapping": entity_mapping})}
    )
    print("Anonymized the ticket!")
    print(entity_mapping)

    return anonymized_result , entity_mapping

def deanonymize_ticket(anonymized_result, anonymized_mapping):
    deanonymizer_engine = DeanonymizeEngine()
    deanonymizer_engine.add_deanonymizer(InstanceCounterDeanonymizer)

    deanonymized_result = deanonymizer_engine.deanonymize(
    anonymized_result.text, 
    anonymized_result.items,
    operators={"entity_counter_deanonymizer": OperatorConfig("entity_counter_deanonymizer", {"entity_mapping": anonymized_mapping})}
    )   
    print("Deanonymized the ticket!")
    return deanonymized_result

def main():
    with open("raw_ticket_conversation.txt", "r") as file:
        ticket = file.read()

    anonymized_result,mapping = anonymize_ticket(ticket)
    with open("anonymized_ticket_conversation.txt", "w") as file:
        file.write(anonymized_result.text)
    print(mapping)
    deanonymized_result = deanonymize_ticket(anonymized_result, mapping)
    with open("deanonymized_ticket_conversation.txt", "w") as file:
        file.write(deanonymized_result.text)

if __name__ == "__main__":
    main()
