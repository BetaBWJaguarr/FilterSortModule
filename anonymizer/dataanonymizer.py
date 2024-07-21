import traceback
from typing import Dict, Any, List, Optional
from cryptography.fernet import Fernet
from pymongo import MongoClient
from errorhandling.errormanager import CustomValueError
from faker import Faker


class Anonymizer:
    def __init__(self, connection_string: str, db_name: str, collection_name: str, key: Optional[bytes] = None):
        self.cipher_suite = Fernet(key) if key else None
        self.client = MongoClient(connection_string)
        self.db = self.client[db_name]
        self.collection = self.db[collection_name]
        self.faker = Faker()

    def encrypt_field(self, value: str) -> str:
        if self.cipher_suite is None:
            raise ValueError("No key provided for encryption")
        encrypted_value = self.cipher_suite.encrypt(value.encode())
        return encrypted_value.decode()

    def decrypt_field(self, value: str) -> str:
        if self.cipher_suite is None:
            raise ValueError("No key provided for decryption")
        decrypted_value = self.cipher_suite.decrypt(value.encode())
        return decrypted_value.decode()

    def anonymize_fields(self, json_data: Dict[str, Any], fields_to_anonymize: List[str], anonymize_func) -> Dict[str, Any]:
        try:
            if not isinstance(json_data, dict):
                raise TypeError("Input data must be a dictionary")

            anonymized_data = json_data.copy()
            for field in fields_to_anonymize:
                if isinstance(anonymized_data.get(field), dict):
                    anonymized_data[field] = self.anonymize_fields(anonymized_data[field], anonymized_data[field].keys(), anonymize_func)
                elif field in anonymized_data:
                    anonymized_data[field] = anonymize_func(anonymized_data[field])

            return anonymized_data

        except Exception as e:
            traceback.print_exc()
            raise CustomValueError("Anonymization error", str(e))

    def anonymize_text_fields(self, json_data: Dict[str, Any], fields_to_anonymize: List[str]) -> Dict[str, Any]:
        return self.anonymize_fields(json_data, fields_to_anonymize, lambda x: "********")

    def anonymize_numerical_fields(self, json_data: Dict[str, Any], fields_to_anonymize: List[str]) -> Dict[str, Any]:
        return self.anonymize_fields(json_data, fields_to_anonymize, lambda x: 0)

    def replace_with_fake_email(self, document: Dict[str, Any], field: str) -> Dict[str, Any]:
        if field in document:
            document[field] = self.faker.email()
        return document

    def mask_credit_card_number(self, document: Dict[str, Any], field: str) -> Dict[str, Any]:
        if field in document:
            document[field] = self.faker.credit_card_number(card_type='visa')
        return document

    def anonymize_sensitive_fields(self, document: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if not isinstance(document, dict):
                raise TypeError("Input document must be a dictionary")

            sensitive_fields = ["email", "password", "username"]
            return self.anonymize_fields(document, sensitive_fields, lambda x: "********")

        except Exception as e:
            traceback.print_exc()
            raise CustomValueError("Anonymization error", str(e))
