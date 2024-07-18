from errorhandling.errormanager import CustomValueError

def get_data_manager(data):
    from filtermanager.filtermanager import DataManager
    db_name = data.get('db_name')
    collection_name = data.get('collection_name')
    connection_string = data.get('connection_string')

    return DataManager(db_name, collection_name, connection_string)

def match_request(data, filter_data, page=None, items_per_page=None, projection=None, sort_data=None, text_search=None, regex_search=None):
    data_manager = get_data_manager(data)
    try:
        results = data_manager.match(filter_data, page, items_per_page, projection, sort_data, text_search, regex_search)
        return results
    except CustomValueError as e:
        return {"error": str(e)}, 400

def sort_request(data, filter_data, sort_data, compare_field=None, page_size=None, page_number=None):
    data_manager = get_data_manager(data)
    try:
        results = data_manager.sort(filter_data, sort_data, compare_field, page_size, page_number)
        return results
    except CustomValueError as e:
        return {"error": str(e)}, 400

def multi_filter_request(data, filters, sort_data=None, limit=None, skip=None, unwind_field=None, group_by=None, projection=None, facet_fields=None):
    data_manager = get_data_manager(data)
    try:
        results = data_manager.multi_filter(filters, sort_data, limit, skip, unwind_field, group_by, projection, facet_fields)
        return results
    except CustomValueError as e:
        return {"error": str(e)}, 400

def type_search_request(data, type_value, projection=None, sort_data=None, text_search=None, regex_search=None, date_range=None, greater_than=None, less_than=None, in_list=None, not_in_list=None):
    data_manager = get_data_manager(data)
    try:
        results = data_manager.type_search(type_value, projection, sort_data, text_search, regex_search, date_range, greater_than, less_than, in_list, not_in_list)
        return results
    except CustomValueError as e:
        return {"error": str(e)}, 400

def aggregate_request(data, pipeline, allow_disk_use=False, max_time_ms=None, bypass_document_validation=False, session=None, collation=None, hint=None):
    data_manager = get_data_manager(data)
    try:
        results = data_manager.aggregate(pipeline, allow_disk_use, max_time_ms, bypass_document_validation, session, collation, hint)
        return results
    except CustomValueError as e:
        return {"error": str(e)}, 400