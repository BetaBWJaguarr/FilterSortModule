from pymongo import MongoClient
from bson.objectid import ObjectId
import json
from utils.jsonencoder import JSONEncoder

class DataManager:
    def __init__(self, db_name, collection_name, connection_string):
        self.client = MongoClient(connection_string)
        self.db = self.client[db_name]
        self.collection = self.db[collection_name]

    def match(self, filter_data, page=None, items_per_page=None, projection=None):
        if page is None or items_per_page is None:
            results = self.collection.find(filter_data, projection)
        else:
            skip = (page - 1) * items_per_page
            results = self.collection.find(filter_data, projection).skip(skip).limit(items_per_page)
        return json.loads(JSONEncoder().encode(list(results)))

    def sort(self, sort_data):
        if sort_data is None:
            sort_data = {}

        results = self.collection.find().sort(list(sort_data.items()))

        return json.loads(JSONEncoder().encode(list(results)))