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

def sort_request(data, filter_data, sort_data, compare_field=None):
    data_manager = get_data_manager(data)
    try:
        results = data_manager.sort(filter_data, sort_data, compare_field)
        return results
    except CustomValueError as e:
        return {"error": str(e)}, 400

def multi_filter_request(data, filters, sort_data=None, limit=None, skip=None, unwind_field=None, group_by=None):
    data_manager = get_data_manager(data)
    try:
        results = data_manager.multi_filter(filters, sort_data, limit, skip, unwind_field, group_by)
        return results
    except CustomValueError as e:
        return {"error": str(e)}, 400
