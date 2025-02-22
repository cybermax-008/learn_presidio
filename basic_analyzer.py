from presidio_analyzer import AnalyzerEngine

analyzer =AnalyzerEngine()

input_text = """During a financial audit on 2023-10-15 14:30, analysts uncovered cross-border irregularities. A transaction involving ₿1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 was traced to an IP 192.168.1.1 linked to an individual in New York City named John A. Doe. Records showed a payment via 4111-1111-1111-1111 to an account with GB29NWBK60161331926819, while an email j.doe@example.com included a link to https://secureportal.com requesting sensitive details.

In the U.S., documents referenced 123-45-6789, 123456789, and A123-4567-8910 tied to 12345678. A UK citizen associated with AB123456C and 123 456 7890 was linked to an Italian entity holding RSSMRA85M10Z100X and IT12345678901. In Spain, identifiers like X-1234567-L and 12345678A surfaced, while a Polish national with 65071209876 had ties to a Singaporean firm (123456789A) and an Indian tax ID ABCDE1234F.

Medical records under license MED-123-XYZ listed an Australian Medicare 1234 56789 1-1 and business ID 51 004 085 616. A Finnish citizen with 311280-999Y, contacted via +1-555-123-4567, was tied to an Indian vehicle MH01AB1234 and voter ID ABC1234567. The audit revealed affiliations with specific political groups and flagged risks in global data flows, urging tighter compliance measures."""

input_text2 = "During a recent customer service inquiry on 2024-07-22 at 09:15, Emily J. Carter submitted a complaint via emily.carter@domain.org regarding a billing discrepancy. She noted a charge of $299.99 to her card 5222-3344-5566-7788 while accessing her account from IP 203.0.113.45. The transaction was linked to a login attempt from http://suspicious-portal.net/login, which she claims to have never visited. For verification, she provided her contact number +1 (415) 555-0199 and requested a callback."
results = analyzer.analyze(input_text2, language='en')

for result in results:
    print(f"type:{result.entity_type},            Entity: {input_text2[int(result.start):int(result.end)]},                Score:{result.score}")
