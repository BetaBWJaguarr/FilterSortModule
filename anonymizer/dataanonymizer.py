import traceback

from cryptography.fernet import Fernet
from pymongo import MongoClient
from errorhandling.errormanager import CustomValueError
from faker import Faker


class Anonymizer:
    def __init__(self, connection_string, db_name, collection_name, key=None):
        self.cipher_suite = Fernet(key) if key else None
        self.client = MongoClient(connection_string)
        self.db = self.client[db_name]
        self.collection = self.db[collection_name]
        self.faker = Faker()

    def encrypt_field(self, value):
        if self.cipher_suite is None:
            raise ValueError("No key provided for encryption")
        if isinstance(value, str):
            value = value.encode()
        encrypted_value = self.cipher_suite.encrypt(value)
        return encrypted_value.decode()

    def decrypt_field(self, value):
        if self.cipher_suite is None:
            raise ValueError("No key provided for decryption")
        decrypted_value = self.cipher_suite.decrypt(value.encode())
        return decrypted_value.decode()

    def anonymize_text_fields(self, json_data, fields_to_anonymize):
        try:
            if not isinstance(json_data, dict):
                raise TypeError("Input data must be a dictionary")

            anonymized_data = json_data.copy()

            for field in fields_to_anonymize:
                if isinstance(anonymized_data.get(field), dict):
                    anonymized_data[field] = self.anonymize_text_fields(anonymized_data[field], anonymized_data[field].keys())
                elif field in anonymized_data:
                    anonymized_data[field] = "********"

            return anonymized_data

        except Exception as e:
            traceback.print_exc()
            raise CustomValueError("Anonymization error", str(e))

    def replace_with_fake_email(self, document, field):
        if field in document:
            document[field] = self.faker.email()
        return document

    def mask_credit_card_number(self, document, field):
        if field in document:
            document[field] = self.faker.credit_card_number(card_type='visa')
        return document

    def anonymize_numerical_fields(self, json_data, fields_to_anonymize):
        try:
            anonymized_data = json_data.copy()

            for field in fields_to_anonymize:
                if isinstance(anonymized_data.get(field), dict):
                    anonymized_data[field] = self.anonymize_numerical_fields(anonymized_data[field], anonymized_data[field].keys())
                else:
                    anonymized_data[field] = 0

            return anonymized_data

        except Exception as e:
            traceback.print_exc()
            raise CustomValueError("Anonymization error", str(e))

    def anonymize_sensitive_fields(self, document):
        try:
            if not isinstance(document, dict):
                raise TypeError("Input document must be a dictionary")

            anonymized_document = document.copy()

            sensitive_fields = ["email", "password", "username"]

            for field, value in anonymized_document.items():
                if isinstance(value, dict):
                    anonymized_document[field] = self.anonymize_sensitive_fields(value)
                elif isinstance(value, list):
                    anonymized_document[field] = [self.anonymize_sensitive_fields(item) if isinstance(item, dict) else item for item in value]
                elif field in sensitive_fields:
                    anonymized_document[field] = "********"

            return anonymized_document

        except Exception as e:
            traceback.print_exc()
            raise CustomValueError("Anonymization error", str(e))