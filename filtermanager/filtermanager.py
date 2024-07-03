from pymongo import MongoClient
from bson.objectid import ObjectId
import json
from utils.jsonencoder import JSONEncoder
from errorhandling.errormanager import CustomValueError

class DataManager:
    def __init__(self, db_name, collection_name, connection_string):
        try:
            self.client = MongoClient(connection_string)
            self.db = self.client[db_name]
            self.collection = self.db[collection_name]
        except Exception as e:
            raise CustomValueError(f"Error initializing DataManager: {str(e)}")

    def match(self, filter_data, page=None, items_per_page=None, projection=None, sort_data=None, text_search=None, regex_search=None):
        try:
            query = filter_data if filter_data else {}

            if text_search:
                query["$text"] = {"$search": text_search}

            if regex_search:
                for field, pattern in regex_search.items():
                    query[field] = {"$regex": pattern, "$options": "i"}

            if page is not None and items_per_page is not None:
                skip = (page - 1) * items_per_page
            else:
                skip = 0
                items_per_page = 0

            if sort_data:
                sort = list(sort_data.items())
            else:
                sort = None

            cursor = self.collection.find(query, projection).skip(skip).limit(items_per_page)
            if sort:
                cursor = cursor.sort(sort)

            results = list(cursor)
            return json.loads(JSONEncoder().encode(results))
        except Exception as e:
            raise CustomValueError(f"Error in match method: {str(e)}")

    def sort(self, filter_data, sort_data, compare_field=None):
        try:
            if sort_data is None:
                sort_data = {}

            if compare_field:
                results = self.collection.find(filter_data).sort([(compare_field, sort_data.get(compare_field, 1))])
            else:
                results = self.collection.find(filter_data).sort(list(sort_data.items()))

            return json.loads(JSONEncoder().encode(list(results)))
        except Exception as e:
            raise CustomValueError(f"Error in sort method: {str(e)}")
