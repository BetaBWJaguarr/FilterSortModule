from pymongo import MongoClient, ASCENDING, DESCENDING
import json
from utils.jsonencoder import JSONEncoder
from filtermanager.managers.cachemanager import CacheManager

class DataManager:
    def __init__(self, db_name, collection_name, connection_string, default_ttl_seconds=300, expiry_callback=None):
        self.client = MongoClient(connection_string, maxPoolSize=50)
        self.db = self.client[db_name]
        self.collection = self.db[collection_name]
        self.cache_manager = CacheManager(default_ttl_seconds=default_ttl_seconds, expiry_callback=expiry_callback)

    def _get_cache_manager(self):
        return self.cache_manager

    def get_cache_statistics(self):
        return self._get_cache_manager().get_statistics()

    def _generate_cache_key(self, *args, **kwargs):
        return self._get_cache_manager()._generate_cache_key(*args, **kwargs)

    def _get_from_cache(self, cache_key):
        return self._get_cache_manager()._get_from_cache(cache_key)

    def _set_to_cache(self, cache_key, data, ttl_seconds=300):
        self._get_cache_manager()._set_to_cache(cache_key, data, ttl_seconds)

    def match(self, filter_data=None, page=None, items_per_page=None, projection=None, sort_data=None, text_search=None, regex_search=None):
        cache_key = self._generate_cache_key(filter_data, page, items_per_page, projection, sort_data, text_search, regex_search)
        cached_result = self._get_from_cache(cache_key)
        if cached_result:
            print(f"Cache hit for key: {cache_key}")
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
        print(f"Cache set for key: {cache_key}")
        print(self.get_cache_statistics())
        return encoded_results

    def sort(self, filter_data=None, sort_data=None, compare_field=None, page_size=None, page_number=None, range_field=None):
        cache_key = self._generate_cache_key(filter_data, sort_data, compare_field, range_field)
        cached_result = self._get_from_cache(cache_key)
        if cached_result:
            print(f"Cache hit for key: {cache_key}")
            return cached_result

        filter_data = filter_data if filter_data else {}
        sort_data = sort_data if sort_data else {}

        if compare_field and isinstance(compare_field, list) and len(compare_field) == 2:
            filter_data["$expr"] = {"$gt": [f"${compare_field[0]}", f"${compare_field[1]}"]}

        if range_field and isinstance(range_field, dict) and len(range_field) == 2:
            field_name, range_values = list(range_field.items())[0]
            filter_data[field_name] = {"$gte": range_values[0], "$lte": range_values[1]}

        sort = [(k, ASCENDING if v == 1 else DESCENDING) for k, v in sort_data.items()]
        results = self.collection.find(filter_data).sort(sort)

        if page_size and page_number:
            results = results.skip(page_size * (page_number - 1)).limit(page_size)

        encoded_results = json.loads(JSONEncoder().encode(list(results)))
        self._set_to_cache(cache_key, encoded_results)
        print(f"Cache set for key: {cache_key}")
        print(self.get_cache_statistics())
        return encoded_results

    def multi_filter(self, filters, sort_data=None, limit=None, skip=None, unwind_field=None, group_by=None, projection=None, facet_fields=None):
        cache_key = self._generate_cache_key(filters, sort_data, limit, skip, unwind_field, group_by, projection, facet_fields)
        cached_result = self._get_from_cache(cache_key)
        if cached_result:
            print(f"Cache hit for key: {cache_key}")
            return cached_result

        pipeline = [{"$match": filter_data} for filter_data in filters]

        if unwind_field:
            pipeline.append({"$unwind": f"${unwind_field}"})

        if group_by:
            pipeline.append({"$group": {"_id": group_by, "count": {"$sum": 1}}})

        if sort_data:
            pipeline.append({"$sort": {k: ASCENDING if v == 1 else DESCENDING for k, v in sort_data.items()}})

        if skip is not None:
            pipeline.append({"$skip": skip})

        if limit is not None:
            pipeline.append({"$limit": limit})

        if facet_fields:
            pipeline.append({"$facet": OrderedDict(facet_fields)})

        results = list(self.collection.aggregate(pipeline))
        encoded_results = json.loads(JSONEncoder().encode(results))
        self._set_to_cache(cache_key, encoded_results)
        print(f"Cache set for key: {cache_key}")
        print(self.get_cache_statistics())
        return encoded_results

    def type_search(self, type_value, projection=None, sort_data=None, text_search=None, regex_search=None, date_range=None, greater_than=None, less_than=None, in_list=None, not_in_list=None):
        cache_key = self._generate_cache_key(type_value, projection, sort_data, text_search, regex_search, date_range, greater_than, less_than, in_list, not_in_list)
        cached_result = self._get_from_cache(cache_key)
        if cached_result:
            print(f"Cache hit for key: {cache_key}")
            return cached_result

        query = {"type": type_value}

        if text_search:
            query["$text"] = {"$search": text_search}

        if regex_search:
            for field, pattern in regex_search.items():
                query[field] = {"$regex": pattern, "$options": "i"}

        if date_range:
            for field, range_values in date_range.items():
                query[field] = {"$gte": range_values[0], "$lte": range_values[1]}

        if greater_than:
            for field, value in greater_than.items():
                query[field] = {"$gt": value}

        if less_than:
            for field, value in less_than.items():
                query[field] = {"$lt": value}

        if in_list:
            for field, values in in_list.items():
                query[field] = {"$in": values}

        if not_in_list:
            for field, values in not_in_list.items():
                query[field] = {"$nin": values}

        cursor = self.collection.find(query, projection)

        if sort_data:
            sort = [(k, ASCENDING if v == 1 else DESCENDING) for k, v in sort_data.items()]
            cursor = cursor.sort(sort)

        results = list(cursor)
        encoded_results = json.loads(JSONEncoder().encode(results))
        self._set_to_cache(cache_key, encoded_results)
        print(f"Cache set for key: {cache_key}")
        print(self.get_cache_statistics())
        return encoded_results

    def aggregate(
            self, pipeline, allow_disk_use=False, max_time_ms=None,
            bypass_document_validation=False, session=None,
            collation=None, hint=None, batch_size=None,
            comment=None, cursor=None,max_results=None
    ):
        cache_key = self._generate_cache_key(
        pipeline, allow_disk_use, max_time_ms,
            bypass_document_validation, session, collation,
            hint, batch_size, comment, cursor
        )
        cached_result = self._get_from_cache(cache_key)

        if cached_result:
            print(f"Cache hit for key: {cache_key}")
            return cached_result

        try:
            aggregation_options = {
                'allowDiskUse': allow_disk_use,
                'maxTimeMS': max_time_ms,
                'bypassDocumentValidation': bypass_document_validation,
                'session': session,
                'collation': collation,
                'hint': hint,
                'batchSize': batch_size,
                'comment': comment
            }

            if cursor is not None:
                aggregation_options['cursor'] = cursor

            results = list(self.collection.aggregate(pipeline, **aggregation_options))

            if max_results is not None:
                results = results[:max_results]

            encoded_results = json.loads(JSONEncoder().encode(results))

            self._set_to_cache(cache_key, encoded_results)
            print(f"Cache set for key: {cache_key}")
            print(self.get_cache_statistics())

            return encoded_results

        except Exception as e:
            raise CustomValueError(f"Aggregation error: {str(e)}")

    def searching_boolean(self, filter_data=None, and_conditions=None, or_conditions=None, not_conditions=None, projection=None, sort_data=None, page=None, items_per_page=None):
        cache_key = self._generate_cache_key(filter_data, and_conditions, or_conditions, not_conditions, projection, sort_data, page, items_per_page)
        cached_result = self._get_from_cache(cache_key)
        if cached_result:
            print(f"Cache hit for key: {cache_key}")
            return cached_result

        query = filter_data if filter_data else {}

        if and_conditions:
            query.update(and_conditions)

        if or_conditions:
            query["$or"] = or_conditions

        if not_conditions:
            query.update({"$nor": [not_conditions]})

        skip = (page - 1) * items_per_page if page and items_per_page else 0
        limit = items_per_page if items_per_page else 0

        cursor = self.collection.find(query, projection).skip(skip).limit(limit)

        if sort_data:
            sort = [(k, ASCENDING if v == 1 else DESCENDING) for k, v in sort_data.items()]
            cursor = cursor.sort(sort)

        results = list(cursor)
        encoded_results = json.loads(JSONEncoder().encode(results))
        self._set_to_cache(cache_key, encoded_results)
        print(f"Cache set for key: {cache_key}")
        print(self.get_cache_statistics())
        return encoded_results
