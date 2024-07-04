from pymongo import MongoClient, ASCENDING, DESCENDING
from bson.objectid import ObjectId
import json
from utils.jsonencoder import JSONEncoder

class DataManager:
    def __init__(self, db_name, collection_name, connection_string):
        self.client = MongoClient(connection_string, maxPoolSize=50)
        self.db = self.client[db_name]
        self.collection = self.db[collection_name]

    def match(self, filter_data=None, page=None, items_per_page=None, projection=None, sort_data=None, text_search=None, regex_search=None):
        query = filter_data if filter_data else {}

        if text_search:
            query["$text"] = {"$search": text_search}

        if regex_search:
            for field, pattern in regex_search.items():
                query[field] = {"$regex": pattern, "$options": "i"}

        skip = (page - 1) * items_per_page if page and items_per_page else 0
        limit = items_per_page if items_per_page else 0

        cursor = self.collection.find(query, projection).skip(skip).limit(limit)

        if sort_data:
            sort = [(k, ASCENDING if v == 1 else DESCENDING) for k, v in sort_data.items()]
            cursor = cursor.sort(sort)

        results = list(cursor)
        return json.loads(JSONEncoder().encode(results))

    def sort(self, filter_data=None, sort_data=None, compare_field=None):
        filter_data = filter_data if filter_data else {}
        sort_data = sort_data if sort_data else {}

        if compare_field:
            sort_order = sort_data.get(compare_field, 1)
            results = self.collection.find(filter_data).sort(compare_field, ASCENDING if sort_order == 1 else DESCENDING)
        else:
            sort = [(k, ASCENDING if v == 1 else DESCENDING) for k, v in sort_data.items()]
            results = self.collection.find(filter_data).sort(sort)

        return json.loads(JSONEncoder().encode(list(results)))

    def multi_filter(self, filters, sort_data=None, limit=None, skip=None, unwind_field=None, group_by=None, projection=None):
        pipeline = []


        for filter_data in filters:
            match_stage = {"$match": filter_data}
            pipeline.append(match_stage)


        if unwind_field:
            unwind_stage = {"$unwind": f"${unwind_field}"}
            pipeline.append(unwind_stage)

        if group_by:
            group_stage = {"$group": {"_id": group_by, "count": {"$sum": 1}}}
            pipeline.append(group_stage)


        if sort_data:
            sort_stage = {"$sort": {k: ASCENDING if v == 1 else DESCENDING for k, v in sort_data.items()}}
            pipeline.append(sort_stage)


        if skip is not None:
            skip_stage = {"$skip": skip}
            pipeline.append(skip_stage)

        if limit is not None:
            limit_stage = {"$limit": limit}
            pipeline.append(limit_stage)


        if projection:
            project_stage = {"$project": projection}
            pipeline.append(project_stage)

        results = list(self.collection.aggregate(pipeline))
        return json.loads(JSONEncoder().encode(results))
