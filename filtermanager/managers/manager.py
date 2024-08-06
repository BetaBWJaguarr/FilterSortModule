from errorhandling.errormanager import CustomValueError

def get_data_manager(data):
    from filtermanager.filtermanager import DataManager
    db_name = data.get('db_name')
    collection_name = data.get('collection_name')
    connection_string = data.get('connection_string')

    return DataManager(db_name, collection_name, connection_string)

def get_high_manager(data):
    from highmanager.highmanager import HighManager
    db_name = data.get('db_name')
    collection_name = data.get('collection_name')
    connection_string = data.get('connection_string')

    return HighManager(db_name, collection_name, connection_string)

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

def aggregate_request(data, pipeline, allow_disk_use=False, max_time_ms=None, bypass_document_validation=False, session=None, collation=None, hint=None, batch_size=None, comment=None, cursor=None,max_results=None):
    data_manager = get_data_manager(data)
    try:
        results = data_manager.aggregate(
            pipeline,
            allow_disk_use=allow_disk_use,
            max_time_ms=max_time_ms,
            bypass_document_validation=bypass_document_validation,
            session=session,
            collation=collation,
            hint=hint,
            batch_size=batch_size,
            comment=comment,
            cursor=cursor,
            max_results=max_results
        )
        return results
    except CustomValueError as e:
        return {"error": str(e)}, 400

def searching_boolean_request(
        data,
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
    data_manager = get_data_manager(data)
    try:
        results = data_manager.searching_boolean(
            filter_data=filter_data,
            and_conditions=and_conditions,
            or_conditions=or_conditions,
            not_conditions=not_conditions,
            in_conditions=in_conditions,
            nin_conditions=nin_conditions,
            regex_conditions=regex_conditions,
            range_conditions=range_conditions,
            exists_conditions=exists_conditions,
            type_conditions=type_conditions,
            elem_match_conditions=elem_match_conditions,
            projection=projection,
            sort_data=sort_data,
            page=page,
            items_per_page=items_per_page
        )
        return results
    except CustomValueError as e:
        return {"error": str(e)}, 400

def high_level_query_request(data, filter_data=None, projection=None, sort_data=None, page=None, items_per_page=None):
    high_manager = get_high_manager(data)
    try:
        results = high_manager.high_level_query_optimization(filter_data, projection, sort_data, page, items_per_page)
        return results
    except CustomValueError as e:
        return {"error": str(e)}, 400

def complex_query_request(data, cond):
    high_manager = get_high_manager(data)

    try:

        results = high_manager.build_complex_query(cond)

        return results
    except CustomValueError as e:
        return {"error": str(e)}, 400
    except Exception as e:
        return {"error": str(e)}, 500

def fuzzysearchrequest(
        data,
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
        boost_fields=None,
        exclude_fields=None,
        aggregations=None,
        timeout=5000
):
    data_manager = get_data_manager(data)
    try:
        results = data_manager.fuzzysearch(
            search_field,
            search_term,
            filter_data=filter_data,
            projection=projection,
            sort_data=sort_data,
            page=page,
            items_per_page=items_per_page,
            case_sensitive=case_sensitive,
            highlight_field=highlight_field,
            phrase_matching=phrase_matching,
            boost_fields=boost_fields,
            exclude_fields=exclude_fields,
            aggregations=aggregations,
            timeout=timeout
        )
        return results
    except CustomValueError as e:
        return {"error": str(e)}, 400

def keywordhighlightingrequest(data, search_field, search_term, filter_data=None, projection=None, sort_data=None, page=None, items_per_page=None, highlight_tag='<mark>',case_sensitive=False):
    data_manager = get_data_manager(data)
    try:
        results = data_manager.keywordhighlighting(
            search_field,
            search_term,
            filter_data=filter_data,
            projection=projection,
            sort_data=sort_data,
            page=page,
            items_per_page=items_per_page,
            highlight_tag=highlight_tag,
            case_sensitive=case_sensitive
        )
        return results
    except CustomValueError as e:
        return {"error": str(e)}, 400

def customsortingoptionsrequest(
        data,
        query=None,
        custom_sort=None,
        data_types=None,
        custom_sort_functions=None,
        null_handling='last',
        offset=None,
        limit=None,
        fields=None
):
    data_manager = get_data_manager(data)
    try:
        results = data_manager.customsortingoptions(
            query=query,
            custom_sort=custom_sort,
            data_types=data_types,
            custom_sort_functions=custom_sort_functions,
            null_handling=null_handling,
            offset=offset,
            limit=limit,
            fields=fields
        )
        return results
    except CustomValueError as e:
        return {"error": str(e)}, 400