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
            query["$or"] = [dict(t) for t in {tuple(d.items()) for d in query["$or"]}]


        for op in ["$and", "$or", "$nor", "$not"]:
            if op in query:
                query[op] = [dict(t) for t in {tuple(d.items()) for d in query[op]}]


        for key, value in query.items():
            if isinstance(value, dict):
                for op in ["$in", "$nin"]:
                    if op in value:
                        value[op] = list(set(value[op]))


        if projection:
            projection = {field: 1 for field in projection}


        sort = None
        hint = None
        if sort_data:
            sort = [(k, ASCENDING if v == 1 else DESCENDING) for k, v in sort_data.items()]
            index_information = self.collection.index_information()
            for index in index_information.values():
                if set(sort_data.keys()).issubset([field for field, _ in index['key']]):
                    hint = index['key']
                    break


        skip = (page - 1) * items_per_page if page and items_per_page else 0
        limit = items_per_page if items_per_page else 0


        self.db.command('profile', 2)


        cursor = self.collection.find(query, projection).skip(skip).limit(limit)

        if sort:
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


        profile_data = list(self.db.system.profile.find().sort([('$natural', -1)]).limit(10))
        print(f"Query profiling data: {profile_data}")


        self.db.command('profile', 0)

        return encoded_results


    def build_complex_query(self, cond):
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
                    if not isinstance(value, dict):
                        raise ValueError("$elemMatch requires a dictionary value.")
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


                elif key == '$regex':
                    if not isinstance(value, str):
                        raise ValueError("$regex operator requires a string value.")
                    query[key] = value

                elif key == '$size':
                    if not isinstance(value, int):
                        raise ValueError("$size operator requires an integer value.")
                    query[key] = value

                elif key == '$all':
                    if not isinstance(value, list):
                        raise ValueError("$all operator requires a list of values.")
                    query[key] = value

                elif key == '$mod':
                    if not isinstance(value, list) or len(value) != 2:
                        raise ValueError("$mod operator requires a list of two numeric values.")
                    if not all(isinstance(i, (int, float)) for i in value):
                        raise ValueError("$mod operator requires numeric values.")
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

