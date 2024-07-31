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

    def _check_cipher_suite(self):
        if self.cipher_suite is None:
            raise ValueError("Encryption key is not provided")

    def encrypt_field(self, value: str) -> str:
        self._check_cipher_suite()
        encrypted_value = self.cipher_suite.encrypt(value.encode())
        return encrypted_value.decode()

    def decrypt_field(self, value: str) -> str:
        self._check_cipher_suite()
        decrypted_value = self.cipher_suite.decrypt(value.encode())
        return decrypted_value.decode()

    def _anonymize_field(self, value: Any, anonymize_func) -> Any:
        return anonymize_func(value)

    def _anonymize_dict(self, data: Dict[str, Any], fields: List[str], anonymize_func) -> Dict[str, Any]:
        anonymized_data = data.copy()
        for field in fields:
            if isinstance(anonymized_data.get(field), dict):
                anonymized_data[field] = self._anonymize_dict(anonymized_data[field], anonymized_data[field].keys(), anonymize_func)
            elif field in anonymized_data:
                anonymized_data[field] = self._anonymize_field(anonymized_data[field], anonymize_func)
        return anonymized_data

    def anonymize_fields(self, json_data: Dict[str, Any], fields_to_anonymize: List[str], anonymize_func) -> Dict[str, Any]:
        if not isinstance(json_data, dict):
            raise TypeError("Input data must be a dictionary")

        try:
            return self._anonymize_dict(json_data, fields_to_anonymize, anonymize_func)
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
        if not isinstance(document, dict):
            raise TypeError("Input document must be a dictionary")

        sensitive_fields = ["email", "password", "username"]
        return self.anonymize_fields(document, sensitive_fields, lambda x: "********")