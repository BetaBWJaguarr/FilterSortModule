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
        cache_key = self._generate_cache_key(
            filters, sort_data, limit, skip, unwind_field, group_by, projection, facet_fields
        )
        cached_result = self._get_from_cache(cache_key)
        if cached_result:
            print(f"Cache hit for key: {cache_key}")
            return cached_result

        pipeline = []

        if filters:
            pipeline.append({"$match": {"$and": filters}})

        if unwind_field:
            pipeline.append({"$unwind": f"${unwind_field}"})

        if group_by:
            pipeline.append({"$group": {"_id": f"${group_by}", "count": {"$sum": 1}}})

        if sort_data:
            pipeline.append({"$sort": {k: ASCENDING if v == 1 else DESCENDING for k, v in sort_data.items()}})

        if skip is not None:
            pipeline.append({"$skip": skip})

        if limit is not None:
            pipeline.append({"$limit": limit})

        if facet_fields:
            pipeline.append({"$facet": OrderedDict(facet_fields)})

        try:
            results = list(self.collection.aggregate(pipeline))
            encoded_results = json.loads(JSONEncoder().encode(results))
            self._set_to_cache(cache_key, encoded_results)
            print(f"Cache set for key: {cache_key}")
            print(self.get_cache_statistics())

            return encoded_results

        except Exception as e:
            print(f"An error occurred: {e}")
            return []

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

    def searching_boolean(
            self,
            filter_data=None,
            and_conditions=None,
            or_conditions=None,
            not_conditions=None,
            in_conditions=None,
            nin_conditions=None,
            regex_conditions=None,
            range_conditions=None,
            exists_conditions=None,
            type_conditions=None,
            elem_match_conditions=None,
            projection=None,
            sort_data=None,
            page=None,
            items_per_page=None
    ):
        cache_key = self._generate_cache_key(
            filter_data,
            and_conditions,
            or_conditions,
            not_conditions,
            in_conditions,
            nin_conditions,
            regex_conditions,
            range_conditions,
            exists_conditions,
            type_conditions,
            elem_match_conditions,
            projection,
            sort_data,
            page,
            items_per_page
        )

        cached_result = self._get_from_cache(cache_key)
        if cached_result:
            print(f"Cache hit for key: {cache_key}")
            return cached_result

        query = {}

        if filter_data:
            query.update(filter_data)

        if and_conditions:
            if "$and" not in query:
                query["$and"] = []
            for condition in and_conditions:
                query["$and"].append(condition)

        if or_conditions:
            query["$or"] = or_conditions

        if not_conditions:
            query["$nor"] = not_conditions

        if in_conditions:
            for field, values in in_conditions.items():
                query[field] = {"$in": values}

        if nin_conditions:
            for field, values in nin_conditions.items():
                query[field] = {"$nin": values}

        if regex_conditions:
            for field, pattern in regex_conditions.items():
                query[field] = {"$regex": pattern}

        if range_conditions:
            for field, range_values in range_conditions.items():
                query[field] = {"$gte": range_values.get("gte"), "$lte": range_values.get("lte")}

        if exists_conditions:
            for field, exists in exists_conditions.items():
                query[field] = {"$exists": exists}

        if type_conditions:
            for field, type_value in type_conditions.items():
                query[field] = {"$type": type_value}

        if elem_match_conditions:
            for field, conditions in elem_match_conditions.items():
                query[field] = {"$elemMatch": conditions}

        skip = (page - 1) * items_per_page if page and items_per_page else 0
        limit = items_per_page if items_per_page else 0

        try:
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

        except PyMongoError as e:
            print(f"An error occurred: {e}")
            return []

    def fuzzysearch(
            self,
            search_field,
            search_term,
            filter_data=None,
            projection=None,
            sort_data=None,
            page=None,
            items_per_page=None,
            case_sensitive=False,
            highlight_field=None,
            phrase_matching=False,
            boost_fields=None
    ):
        cache_key = self._generate_cache_key(
            search_field, search_term, filter_data, projection, sort_data, page, items_per_page, case_sensitive, highlight_field, phrase_matching, boost_fields
        )
        cached_result = self._get_from_cache(cache_key)
        if cached_result:
            print(f"Cache hit for key: {cache_key}")
            return cached_result

        query = filter_data if filter_data else {}

        if phrase_matching:
            search_term = re.escape(search_term)
            search_term = '.*' + '.*'.join(search_term.split()) + '.*'

        if case_sensitive:
            query[search_field] = {"$regex": search_term, "$options": ""}
        else:
            query[search_field] = {"$regex": search_term, "$options": "i"}


        if highlight_field:
            projection = projection or {}
            projection[highlight_field] = 1

        skip = (page - 1) * items_per_page if page and items_per_page else 0
        limit = items_per_page if items_per_page else 0

        try:
            cursor = self.collection.find(query, projection).skip(skip).limit(limit)

            if sort_data:
                sort = [(k, ASCENDING if v == 1 else DESCENDING) for k, v in sort_data.items()]
                cursor = cursor.sort(sort)

            results = list(cursor)


            if boost_fields:
                results.sort(key=lambda x: sum(x.get(field, 0) for field in boost_fields), reverse=True)


            if highlight_field:
                for result in results:
                    if highlight_field in result:
                        result[highlight_field] = re.sub(search_term, lambda m: f'**{m.group()}**', result[highlight_field])

            encoded_results = json.loads(JSONEncoder().encode(results))
            self._set_to_cache(cache_key, encoded_results)
            print(f"Cache set for key: {cache_key}")
            print(self.get_cache_statistics())
            return encoded_results

        except PyMongoError as e:
            print(f"An error occurred: {e}")
            return []

    def keywordhighlighting(
            self,
            search_field,
            search_term,
            filter_data=None,
            projection=None,
            sort_data=None,
            page=None,
            items_per_page=None,
            highlight_tag='<mark>'
    ):
        cache_key = self._generate_cache_key(
            search_field, search_term, filter_data, projection, sort_data, page, items_per_page, highlight_tag
        )
        cached_result = self._get_from_cache(cache_key)
        if cached_result:
            print(f"Cache hit for key: {cache_key}")
            return cached_result

        query = filter_data if filter_data else {}

        if isinstance(search_field, list) and isinstance(search_term, list):
            query['$or'] = [
                {field: {"$regex": term, "$options": "i"}}
                for field in search_field for term in search_term
            ]
        elif isinstance(search_field, list):
            query['$or'] = [
                {field: {"$regex": search_term, "$options": "i"}}
                for field in search_field
            ]
        else:
            query[search_field] = {"$regex": search_term, "$options": "i"}  # Case-insensitive search

        skip = (page - 1) * items_per_page if page and items_per_page else 0
        limit = items_per_page if items_per_page else 0

        try:
            cursor = self.collection.find(query, projection).skip(skip).limit(limit)

            if sort_data:
                sort = [(k, ASCENDING if v == 1 else DESCENDING) for k, v in sort_data.items()]
                cursor = cursor.sort(sort)

            results = list(cursor)

            for result in results:
                if isinstance(search_field, list):
                    for field in search_field:
                        if field in result and result[field]:
                            result[field] = self._highlight_keywords(result[field], search_term, highlight_tag)
                else:
                    if search_field in result and result[search_field]:
                        result[search_field] = self._highlight_keywords(result[search_field], search_term, highlight_tag)

            encoded_results = json.loads(JSONEncoder().encode(results))
            self._set_to_cache(cache_key, encoded_results)
            print(f"Cache set for key: {cache_key}")
            print(self.get_cache_statistics())
            return encoded_results

        except PyMongoError as e:
            print(f"An error occurred: {e}")
            return []

    def _highlight_keywords(self, text, search_term, highlight_tag):
        if isinstance(search_term, list):
            for term in search_term:
                text = re.sub(re.escape(term), f'{highlight_tag}\\0{highlight_tag[1:]}', text, flags=re.IGNORECASE)
        else:
            text = re.sub(re.escape(search_term), f'{highlight_tag}\\0{highlight_tag[1:]}', text, flags=re.IGNORECASE)
        return text


    def customsortingoptions(self, query=None, custom_sort=None):
        cache_key = self._generate_cache_key(query, custom_sort)
        cached_result = self._get_from_cache(cache_key)

        if cached_result:
            print(f"Cache hit for key: {cache_key}")
            return cached_result

        if query is None:
            query = {}

        sort = []

        if custom_sort:
            for field, order in custom_sort:
                if order.lower() == 'asc':
                    sort.append((field, ASCENDING))
                elif order.lower() == 'desc':
                    sort.append((field, DESCENDING))
                elif order.lower() == 'lenasc':
                    sort.append((field, ASCENDING))
                elif order.lower() == 'lendesc':
                    sort.append((field, DESCENDING))
                elif order.lower() == 'custom':
                    sort.append((field, ASCENDING))
                else:
                    raise ValueError(f"Invalid sort order: {order}. Use 'asc', 'desc', 'lenasc', 'lendesc', or 'custom'.")

        try:
            cursor = self.collection.find(query)

            if sort:
                cursor = cursor.sort(sort)

            results = list(cursor)

            for field, order in custom_sort:
                if order.lower() == 'lenasc':
                    results.sort(key=lambda x: len(str(x.get(field, ""))))
                elif order.lower() == 'lendesc':
                    results.sort(key=lambda x: len(str(x.get(field, ""))), reverse=True)
                elif order.lower() == 'custom':
                    results.sort(key=lambda x: x.get(field, 0))

            encoded_results = json.loads(JSONEncoder().encode(results))
            self._set_to_cache(cache_key, encoded_results)
            print(f"Cache set for key: {cache_key}")
            print(self.get_cache_statistics())
            return encoded_results

        except Exception as e:
            print(f"An error occurred: {e}")
            return []

