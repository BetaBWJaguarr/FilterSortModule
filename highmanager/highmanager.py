from datetime import time

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
        cache_key = self._generate_cache_key(cond)
        cached_result = self._get_from_cache(cache_key)

        if cached_result:
            print(f"Cache hit for key: {cache_key}")
            return cached_result

        if not isinstance(cond, (dict, list)):
            raise ValueError("Conditions must be either a dictionary or a list.")

        def process_value(value):
            if isinstance(value, (dict, list)):
                return self.build_complex_query(value)
            return value

        def check_type(value, expected_type, operator):
            if not isinstance(value, expected_type):
                raise ValueError(f"{operator} operator requires a {expected_type} value.")

        query = {}

        if isinstance(cond, dict):
            for key, value in cond.items():
                if not isinstance(key, str):
                    raise ValueError("Keys must be strings.")

                if key in ['$and', '$or', '$nor', '$in', '$nin', '$elemMatch', '$all']:
                    if not isinstance(value, list):
                        raise ValueError(f"The value of the {key} operator must be a list.")
                    query[key] = [process_value(sub_cond) for sub_cond in value]

                elif key in ['$not', '$regex', '$size', '$mod', '$text', '$geoWithin', '$geoIntersects', '$near', '$nearSphere', '$expr', '$lookup', '$addFields', '$project']:
                    if not isinstance(value, dict):
                        raise ValueError(f"{key} operator requires a dictionary value.")
                    query[key] = process_value(value)

                elif key in ['$exists', '$type', '$gt', '$lt', '$gte', '$lte', '$count']:
                    if key == '$exists':
                        check_type(value, bool, "$exists")
                    elif key in ['$type', '$count']:
                        check_type(value, (int, str), key)
                    else:
                        check_type(value, (int, float), key)
                    query[key] = value

                elif key == '$unset':
                    if not isinstance(value, list):
                        raise ValueError("$unset operator requires a list of field names.")
                    query[key] = value

                elif isinstance(value, (dict, list)):
                    query[key] = process_value(value)
                else:
                    query[key] = value

        elif isinstance(cond, list):
            query = [process_value(item) for item in cond]
        else:
            return cond

        encoded_results = json.loads(JSONEncoder().encode(query))
        self._set_to_cache(cache_key, encoded_results)

        return encoded_results

    def utilize_index(self, query=None, sort_data=None, index_type=ASCENDING):
        cache_key = self._generate_cache_key(query, sort_data, index_type)
        cached_result = self._get_from_cache(cache_key)

        if cached_result:
            print(f"Cache hit for key: {cache_key}")
            return cached_result

        if not query and not sort_data:
            print("No query or sort data provided to optimize indexes.")
            return

        index_keys = set()
        if sort_data:
            index_keys.update(sort_data.keys())

        if query:
            def extract_fields(subquery):
                if isinstance(subquery, dict):
                    for key, value in subquery.items():
                        if key.startswith('$'):
                            if isinstance(value, (dict, list)):
                                extract_fields(value)
                        else:
                            index_keys.add(key)

            extract_fields(query)

        existing_indexes = self.collection.index_information()
        existing_index_keys = {tuple(index['key']): index for index in existing_indexes.values()}

        index_keys = list(index_keys)
        new_index_keys = [(key, index_type) for key in index_keys]

        missing_indexes = [index for index in new_index_keys if index not in existing_index_keys]

        if missing_indexes:
            for index in missing_indexes:
                start_time = time.time()
                self.collection.create_index(index, background=True)
                end_time = time.time()
                print(f"Created index: {index} (Time taken: {end_time - start_time:.2f} seconds)")
        else:
            print("All required indexes are already in place.")

        print("Index utilization completed.")
        self._set_to_cache(cache_key, {'status': 'completed'})

        return {'status': 'completed'}

    def list_existing_indexes(self):
        indexes = self.collection.index_information()
        encoded_indexes = json.loads(JSONEncoder().encode(indexes))
        return encoded_indexes

    def drop_index(self, index_name):
        cache_key = self._generate_cache_key(index_name)
        cached_result = self._get_from_cache(cache_key)

        if cached_result:
            print(f"Cache hit for key: {cache_key}")
            return cached_result

        try:
            self.collection.drop_index(index_name)
            result = {'status': 'dropped', 'index_name': index_name}
            print(f"Dropped index: {index_name}")
        except Exception as e:
            result = {'status': 'error', 'message': str(e)}
            print(f"Error dropping index: {e}")

        self._set_to_cache(cache_key, result)
        return result