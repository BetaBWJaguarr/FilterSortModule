import traceback
from pymongo import MongoClient
from errorhandling.errormanager import CustomValueError

class Anonymizer:
    def __init__(self, connection_string, db_name, collection_name):
        self.client = MongoClient(connection_string)
        self.db = self.client[db_name]
        self.collection = self.db[collection_name]

    def anonymize_text_fields(self, json_data, fields_to_anonymize):
        try:
            if not isinstance(json_data, dict):
                raise TypeError("Input data must be a dictionary")

            anonymized_data = json_data.copy()

            for field in fields_to_anonymize:
                if field in anonymized_data:
                    anonymized_data[field] = "********"

            return anonymized_data

        except Exception as e:
            traceback.print_exc()
            raise CustomValueError("Anonymization error", str(e))


    def anonymize_numerical_fields(self, fields_to_anonymize):
        try:
            anonymized_data = {}

            for field in fields_to_anonymize:
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


            sensitive_fields = ["email", "password"]

            for field in sensitive_fields:
                if field in anonymized_document:
                    anonymized_document[field] = "********"

            return anonymized_document

        except Exception as e:
            traceback.print_exc()
            raise CustomValueError("Anonymization error", str(e))
