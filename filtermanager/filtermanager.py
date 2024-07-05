from pymongo import MongoClient, ASCENDING, DESCENDING
from bson.objectid import ObjectId
from collections import OrderedDict
import json
from utils.jsonencoder import JSONEncoder
from datetime import datetime, timedelta
from filtermanager.managers.cachemanager import CacheManager


cache_manager = None

class DataManager:
    def __init__(self, db_name, collection_name, connection_string):
        self.client = MongoClient(connection_string, maxPoolSize=50)
        self.db = self.client[db_name]
        self.collection = self.db[collection_name]
        self.cache_manager = CacheManager()

    def _get_cache_manager(self):
        return self.cache_manager

    def _generate_cache_key(self, *args, **kwargs):
        return self._get_cache_manager()._generate_cache_key(*args, **kwargs)

    def _get_from_cache(self, cache_key):
        return self._get_cache_manager()._get_from_cache(cache_key)

    def _set_to_cache(self, cache_key, data, ttl_seconds=300):
        self._get_cache_manager()._set_to_cache(cache_key, data, ttl_seconds)

    def match(self, filter_data=None, page=None, items_per_page=None, projection=None, sort_data=None, text_search=None, regex_search=None):
        self._get_cache_manager().print_cache()
        cache_key = self._generate_cache_key(filter_data, page, items_per_page, projection, sort_data, text_search, regex_search)
        cached_result = self._get_from_cache(cache_key)
        if cached_result:
            return cached_result

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
        encoded_results = json.loads(JSONEncoder().encode(results))
        self._set_to_cache(cache_key, encoded_results)
        return encoded_results

    def sort(self, filter_data=None, sort_data=None, compare_field=None, page_size=None, page_number=None):

        for field in sort_data.keys():
            self.collection.create_index([(field, ASCENDING if sort_data[field] == 1 else DESCENDING)])

        cache_key = self._generate_cache_key(filter_data, sort_data, compare_field)
        cached_result = self._get_from_cache(cache_key)
        if cached_result:
            return cached_result

        filter_data = filter_data if filter_data else {}
        sort_data = sort_data if sort_data else {}

        if compare_field:
            sort_order = sort_data.get(compare_field, 1)
            results = self.collection.find(filter_data).sort(compare_field, ASCENDING if sort_order == 1 else DESCENDING)
        else:
            sort = [(k, ASCENDING if v == 1 else DESCENDING) for k, v in sort_data.items()]
            results = self.collection.find(filter_data).sort(sort)

        if page_size and page_number:
            results = results.skip(page_size * (page_number - 1)).limit(page_size)


        encoded_results = json.loads(JSONEncoder().encode(list(results)))
        self._set_to_cache(cache_key, encoded_results)
        return encoded_results

    def multi_filter(self, filters, sort_data=None, limit=None, skip=None, unwind_field=None, group_by=None, projection=None,facet_fields=None):
        cache_key = self._generate_cache_key(filters, sort_data, limit, skip, unwind_field, group_by, projection,facet_fields)
        cached_result = self._get_from_cache(cache_key)
        if cached_result:
            return cached_result

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

        if facet_fields:
            facet_stage = {"$facet": OrderedDict(facet_fields)}
            pipeline.append(facet_stage)

        results = list(self.collection.aggregate(pipeline))
        encoded_results = json.loads(JSONEncoder().encode(results))
        self._set_to_cache(cache_key, encoded_results)
        return encoded_results

        def type_search(self, type_value, projection=None, sort_data=None):
            cache_key = self._generate_cache_key(type_value, projection, sort_data)
        cached_result = self._get_from_cache(cache_key)
        if cached_result:
            return cached_result

        query = {"type": type_value}


        cursor = self.collection.find(query, projection).skip(skip).limit(limit)

        if sort_data:
            sort = [(k, ASCENDING if v == 1 else DESCENDING) for k, v in sort_data.items()]
            cursor = cursor.sort(sort)

        results = list(cursor)
        encoded_results = json.loads(JSONEncoder().encode(results))
        self._set_to_cache(cache_key, encoded_results)
        return encoded_results
