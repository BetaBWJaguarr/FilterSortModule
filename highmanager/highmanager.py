from pymongo import ASCENDING, DESCENDING, MongoClient
import json

from pymongo.collation import Collation, CollationStrength

from utils.jsonencoder import JSONEncoder
from filtermanager.managers.cachemanager import CacheManager

class HighManager:
    def __init__(self, collection_name,db_name,connection_string, default_ttl_seconds=300, expiry_callback=None):
        self.client = MongoClient(connection_string, maxPoolSize=50)
        self.collection = self.db[collection_name]
        self.db = self.client[db_name]
        self.cache_manager = CacheManager(default_ttl_seconds=default_ttl_seconds, expiry_callback=expiry_callback)

    def _generate_cache_key(self, *args, **kwargs):
        return self.cache_manager._generate_cache_key(*args, **kwargs)

    def _get_from_cache(self, cache_key):
        return self.cache_manager._get_from_cache(cache_key)

    def _set_to_cache(self, cache_key, data, ttl_seconds=300):
        self.cache_manager._set_to_cache(cache_key, data, ttl_seconds)

    def high_level_query_optimization(self, filter_data=None, projection=None, sort_data=None, page=None, items_per_page=None):
        cache_key = self._generate_cache_key(filter_data, projection, sort_data, page, items_per_page)
        cached_result = self._get_from_cache(cache_key)

        if cached_result:
            print(f"Cache hit for key: {cache_key}")
            return cached_result


        query = filter_data if filter_data else {}


        if "$or" in query:
            original_or_conditions = query["$or"]
            simplified_conditions = []
            seen_conditions = set()
            for condition in original_or_conditions:
                condition_tuple = tuple(condition.items())
                if condition_tuple not in seen_conditions:
                    seen_conditions.add(condition_tuple)
                    simplified_conditions.append(condition)
            if len(simplified_conditions) < len(original_or_conditions):
                query["$or"] = simplified_conditions


        if "$and" in query:
            query["$and"] = self._optimize_conditions(query["$and"])
        if "$or" in query:
            query["$or"] = self._optimize_conditions(query["$or"])
        if "$nor" in query:
            query["$nor"] = self._optimize_conditions(query["$nor"])
        if "$not" in query:
            query["$not"] = self._optimize_conditions(query["$not"])


        for key, value in query.items():
            if isinstance(value, dict):
                if "$in" in value:
                    query[key]["$in"] = list(set(value["$in"]))
                if "$lte" in value:
                    query[key]["$lte"] = value["$lte"]
                if "$nin" in value:
                    query[key]["$nin"] = list(set(value["$nin"]))


        hint = None
        if sort_data:
            sort_keys = list(sort_data.keys())
            index_information = self.collection.index_information()
            for index in index_information.values():
                if set(sort_keys).issubset(index['key']):
                    hint = index['key']
                    break

        if projection:
            projection = {field: 1 for field in projection}


        skip = (page - 1) * items_per_page if page and items_per_page else 0
        limit = items_per_page if items_per_page else 0


        self.db.command('profile', 2)
        cursor = self.collection.find(query, projection).skip(skip).limit(limit)


        if sort_data:
            sort = [(k, ASCENDING if v == 1 else DESCENDING) for k, v in sort_data.items()]
            cursor = cursor.sort(sort)

        if hint:
            cursor = cursor.hint(hint)


        collation = Collation(locale='en', strength=CollationStrength.SECONDARY)
        cursor = cursor.collation(collation)


        if self.collection.sharded and filter_data:
            shard_key = self.collection.shard_key()
            if shard_key in filter_data:
                query[shard_key] = filter_data[shard_key]


        results = list(cursor)
        encoded_results = json.loads(JSONEncoder().encode(results))
        self._set_to_cache(cache_key, encoded_results)
        print(f"Cache set for key: {cache_key}")


        self.db.command('profile', 0)
        profile_data = list(self.db.system.profile.find().sort([('$natural', -1)]).limit(10))
        print(f"Query profiling data: {profile_data}")

        return encoded_results

    def _optimize_conditions(self, conditions):
        optimized_conditions = []
        seen_conditions = set()
        for condition in conditions:
            condition_tuple = tuple(condition.items())
            if condition_tuple not in seen_conditions:
                seen_conditions.add(condition_tuple)
                optimized_conditions.append(condition)
        return optimized_conditions

    def build_complex_query(self,cond):
        if not isinstance(cond, (dict, list)):
            raise ValueError("Conditions must be either a dictionary or a list.")

        query = {}

        if isinstance(cond, dict):
            for key, value in cond.items():
                if not isinstance(key, str):
                    raise ValueError("Keys must be strings.")

                if key in ['$and', '$or', '$nor']:
                    if not isinstance(value, list):
                        raise ValueError(f"The value of the {key} operator must be a list.")
                    query[key] = [self.build_complex_query(sub_cond) for sub_cond in value]
                elif key == '$not':
                    query[key] = self.build_complex_query(value)
                elif key == '$elemMatch':
                    query[key] = self.build_complex_query(value)
                elif key == '$exists':
                    if not isinstance(value, bool):
                        raise ValueError("$exists operator requires a boolean value.")
                    query[key] = value
                elif key == '$type':
                    if not isinstance(value, (int, str)):
                        raise ValueError("$type operator requires an integer or string value.")
                    query[key] = value
                elif key == '$in':
                    if not isinstance(value, list):
                        raise ValueError("$in operator requires a list of values.")
                    query[key] = [self.build_complex_query(item) for item in value]
                elif key == '$nin':
                    if not isinstance(value, list):
                        raise ValueError("$nin operator requires a list of values.")
                    query[key] = [self.build_complex_query(item) for item in value]
                elif key == '$gt':
                    if not isinstance(value, (int, float)):
                        raise ValueError("$gt operator requires a numeric value.")
                    query[key] = value
                elif key == '$lt':
                    if not isinstance(value, (int, float)):
                        raise ValueError("$lt operator requires a numeric value.")
                    query[key] = value
                elif key == '$gte':
                    if not isinstance(value, (int, float)):
                        raise ValueError("$gte operator requires a numeric value.")
                    query[key] = value
                elif key == '$lte':
                    if not isinstance(value, (int, float)):
                        raise ValueError("$lte operator requires a numeric value.")
                    query[key] = value
                elif isinstance(value, dict):
                    query[key] = self.build_complex_query(value)
                elif isinstance(value, list):
                    query[key] = [self.build_complex_query(item) for item in value]
                else:
                    query[key] = value
        elif isinstance(cond, list):
            query = [self.build_complex_query(item) for item in cond]
        else:
            return cond

        return query

