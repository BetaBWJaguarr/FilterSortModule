from flask import request, jsonify, Blueprint
from pymongo import MongoClient
import configparser
from filtermanager.managers.manager import match_request, sort_request, multi_filter_request, aggregate_request, type_search_request, high_level_query_request,searching_boolean_request,complex_query_request,keywordhighlightingrequest,customsortingoptionsrequest
from anonymizer.dataanonymizer import Anonymizer
from errorhandling.errormanager import CustomValueError, CustomTypeError, CustomIndexError, CustomKeyError, CustomFileNotFoundError
from errorhandling.errormanager import setup_logging
from authentication.auth import login_required,limiter
from authentication.permissionsmanager.permissions import permission_required

# Load configuration from config.ini
config = configparser.ConfigParser()
config.read('config.ini')

connection_string = config.get('database', 'connection_string')
db_name = config.get('database', 'db_name')

# MongoDB setup
client = MongoClient(connection_string)
db = client[db_name]
users_collection = db['users']

app = Blueprint('restapi', __name__)

# Initialize logging
logger = setup_logging()

def anonymize_results(results, anonymizer):
    for index, document in enumerate(results):
        try:
            anonymized_fields = anonymizer.anonymize_sensitive_fields(document)
            if anonymized_fields:
                results[index] = {**document, **anonymized_fields}
        except CustomValueError as e:
            results[index] = {"error": str(e)}
            logger.error(f"Error anonymizing result at index {index}: {str(e)}", exc_info=True)
    return results

@app.route('/filtermanager/match', methods=['POST'])
@login_required
@permission_required('user_api_use')
@limiter.limit("5 per minute")
def match():
    try:
        data = request.get_json()
        connection_string = data.get('connection_string')
        db_name = data.get('db_name')
        collection_name = data.get('collection_name')
        filter_data = data.get('match')

        page = request.args.get('page', type=int)
        items_per_page = request.args.get('items_per_page', type=int)

        valid_keys = {'connection_string', 'db_name', 'collection_name', 'match'}
        if not set(data.keys()).issubset(valid_keys):
            invalid_keys = set(data.keys()) - valid_keys
            raise CustomValueError(f"Invalid keys: {', '.join(invalid_keys)}. Valid keys are: {', '.join(valid_keys)}.")

        results = match_request(data, filter_data, page, items_per_page)

        anonymizer = Anonymizer(connection_string, db_name, collection_name)
        results = anonymize_results(results, anonymizer)

        return jsonify(results)

    except (CustomValueError, CustomTypeError, CustomIndexError, CustomKeyError, CustomFileNotFoundError) as e:
        logger.error(f"Custom error occurred: {str(e)}", exc_info=True)
        return jsonify({"error": str(e), "details": e.details}), 400

    except Exception as e:
        logger.error(f"Unexpected error occurred: {str(e)}", exc_info=True)
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500

@app.route('/filtermanager/sort', methods=['POST'])
@login_required
@permission_required('user_api_use')
@limiter.limit("5 per minute")
def sort():
    try:
        data = request.get_json()
        connection_string = data.get('connection_string')
        db_name = data.get('db_name')
        collection_name = data.get('collection_name')
        filter_data = data.get('filter', {})
        sort_data = data.get('sort', None)
        compare_field = data.get('compare_field', None)

        valid_keys = {'db_name', 'collection_name', 'connection_string', 'filter', 'sort', 'compare_field'}
        if not set(data.keys()).issubset(valid_keys):
            invalid_keys = set(data.keys()) - valid_keys
            raise CustomValueError(f"Invalid keys: {', '.join(invalid_keys)}. Valid keys are: {', '.join(valid_keys)}.")

        results = sort_request(data, filter_data, sort_data, compare_field)
        anonymizer = Anonymizer(connection_string, db_name, collection_name)

        results = anonymize_results(results, anonymizer)

        return jsonify(results)

    except (CustomValueError, CustomTypeError, CustomIndexError, CustomKeyError, CustomFileNotFoundError) as e:
        logger.error(f"Custom error occurred: {str(e)}", exc_info=True)
        return jsonify({"error": str(e), "details": e.details, "traceback": e.traceback}), 400
    except Exception as e:
        logger.error(f"Unexpected error occurred: {str(e)}", exc_info=True)
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500

@app.route('/filtermanager/multi_filter', methods=['POST'])
@login_required
@permission_required('user_api_use')
@limiter.limit("5 per minute")
def multi_filter():
    try:
        data = request.get_json()
        connection_string = data.get('connection_string')
        db_name = data.get('db_name')
        collection_name = data.get('collection_name')
        filters = data.get('filters', [])
        sort_data = data.get('sort_data', None)
        limit = data.get('limit', None)
        skip = data.get('skip', None)
        unwind_field = data.get('unwind_field', None)
        group_by = data.get('group_by', None)
        projection = data.get('projection', None)
        facet_fields = data.get('facet_fields', None)

        valid_keys = {'db_name', 'collection_name', 'connection_string', 'filters', 'sort_data', 'limit', 'skip', 'unwind_field', 'group_by', 'projection', 'facet_fields'}
        if not set(data.keys()).issubset(valid_keys):
            invalid_keys = set(data.keys()) - valid_keys
            raise CustomValueError(f"Invalid keys: {', '.join(invalid_keys)}. Valid keys are: {', '.join(valid_keys)}.")

        results = multi_filter_request(data, filters, sort_data, limit, skip, unwind_field, group_by, projection, facet_fields)
        anonymizer = Anonymizer(connection_string, db_name, collection_name)

        results = anonymize_results(results, anonymizer)

        return jsonify(results)

    except (CustomValueError, CustomTypeError, CustomIndexError, CustomKeyError, CustomFileNotFoundError) as e:
        logger.error(f"Custom error occurred: {str(e)}", exc_info=True)
        return jsonify({"error": str(e), "details": e.details, "traceback": e.traceback}), 400
    except Exception as e:
        logger.error(f"Unexpected error occurred: {str(e)}", exc_info=True)
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500

@app.route('/filtermanager/type_search', methods=['POST'])
@login_required
@permission_required('user_api_use')
@limiter.limit("5 per minute")
def type_search():
    try:
        data = request.get_json()
        connection_string = data.get('connection_string')
        db_name = data.get('db_name')
        collection_name = data.get('collection_name')
        type_value = data.get('type_value')
        projection = data.get('projection')
        sort_data = data.get('sort_data')
        text_search = data.get('text_search')
        regex_search = data.get('regex_search')
        date_range = data.get('date_range')
        greater_than = data.get('greater_than')
        less_than = data.get('less_than')
        in_list = data.get('in_list')
        not_in_list = data.get('not_in_list')

        results = type_search_request(data, type_value, projection, sort_data, text_search, regex_search, date_range, greater_than, less_than, in_list, not_in_list)
        anonymizer = Anonymizer(connection_string, db_name, collection_name)

        results = anonymize_results(results, anonymizer)

        return jsonify(results)

    except (CustomValueError, CustomTypeError, CustomIndexError, CustomKeyError, CustomFileNotFoundError) as e:
        logger.error(f"Custom error occurred: {str(e)}", exc_info=True)
        return jsonify({"error": str(e), "details": e.details, "traceback": e.traceback}), 400
    except Exception as e:
        logger.error(f"Unexpected error occurred: {str(e)}", exc_info=True)
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500


@app.route('/filtermanager/aggregate', methods=['POST'])
@login_required
@permission_required('user_api_use')
@limiter.limit("5 per minute")
def aggregate():
    try:
        data = request.get_json()
        connection_string = data.get('connection_string')
        db_name = data.get('db_name')
        collection_name = data.get('collection_name')
        pipeline = data.get('pipeline', [])
        allow_disk_use = data.get('allow_disk_use', False)
        max_time_ms = data.get('max_time_ms', None)
        bypass_document_validation = data.get('bypass_document_validation', False)
        session = data.get('session', None)
        collation = data.get('collation', None)
        hint = data.get('hint', None)
        batch_size = data.get('batch_size', None)
        comment = data.get('comment', None)
        cursor = data.get('cursor', None)
        maxresult = data.get('max_results', None)

        valid_keys = {'db_name', 'collection_name', 'connection_string', 'pipeline', 'allow_disk_use', 'max_time_ms', 'bypass_document_validation', 'session', 'collation', 'hint', 'batch_size', 'comment', 'cursor'}
        if not set(data.keys()).issubset(valid_keys):
            invalid_keys = set(data.keys()) - valid_keys
            raise CustomValueError(f"Invalid keys: {', '.join(invalid_keys)}. Valid keys are: {', '.join(valid_keys)}.")

        results = aggregate_request(
            data,
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
            maxresult=maxresult
        )

        anonymizer = Anonymizer(connection_string, db_name, collection_name)
        results = anonymize_results(results, anonymizer)

        return jsonify(results)

    except (CustomValueError, CustomTypeError, CustomIndexError, CustomKeyError, CustomFileNotFoundError) as e:
        logger.error(f"Custom error occurred: {str(e)}", exc_info=True)
        return jsonify({"error": str(e), "details": e.details, "traceback": e.traceback}), 400
    except Exception as e:
        logger.error(f"Unexpected error occurred: {str(e)}", exc_info=True)
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500

@app.route('/filtermanager/highquery', methods=['POST'])
@login_required
@permission_required('user_api_use')
@limiter.limit("5 per minute")
def high_level_query():
    try:
        request_data = request.get_json()
        connection_string = request_data.get('connection_string')
        db_name = request_data.get('db_name')
        collection_name = request_data.get('collection_name')

        filter_data = request_data.get('filter_data')
        projection = request_data.get('projection')
        sort_data = request_data.get('sort_data')
        page = request_data.get('page')
        items_per_page = request_data.get('items_per_page')

        valid_keys = {'filter_data', 'projection', 'sort_data', 'page', 'items_per_page'}
        if not set(request_data.keys()).issubset(valid_keys):
            invalid_keys = set(request_data.keys()) - valid_keys
            raise CustomValueError(f"Invalid keys: {', '.join(invalid_keys)}. Valid keys are: {', '.join(valid_keys)}.")

        results = high_level_query_request(
            data=request_data,
            filter_data=filter_data,
            projection=projection,
            sort_data=sort_data,
            page=page,
            items_per_page=items_per_page
        )

        anonymizer = Anonymizer(connection_string, db_name, collection_name)
        results = anonymize_results(results, anonymizer)

        return jsonify(results)

    except (CustomValueError, CustomTypeError, CustomIndexError, CustomKeyError, CustomFileNotFoundError) as e:
        logger.error(f"Custom error occurred: {str(e)}", exc_info=True)
        return jsonify({"error": str(e), "details": e.details, "traceback": e.traceback}), 400
    except Exception as e:
        logger.error(f"Unexpected error occurred: {str(e)}", exc_info=True)
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500


@app.route('/filtermanager/searchboolean', methods=['POST'])
@login_required
@permission_required('user_api_use')
@limiter.limit("5 per minute")
def searching_boolean():
    try:
        data = request.get_json()
        connection_string = data.get('connection_string')
        db_name = data.get('db_name')
        collection_name = data.get('collection_name')
        filter_data = data.get('filter_data', {})
        and_conditions = data.get('and_conditions', [])
        or_conditions = data.get('or_conditions', [])
        not_conditions = data.get('not_conditions', [])
        in_conditions = data.get('in_conditions', {})
        nin_conditions = data.get('nin_conditions', {})
        regex_conditions = data.get('regex_conditions', {})
        range_conditions = data.get('range_conditions', {})
        exists_conditions = data.get('exists_conditions', {})
        type_conditions = data.get('type_conditions', {})
        elem_match_conditions = data.get('elem_match_conditions', {})
        projection = data.get('projection', None)
        sort_data = data.get('sort_data', None)
        page = data.get('page', 1)
        items_per_page = data.get('items_per_page', 10)

        valid_keys = {
            'filter_data', 'and_conditions', 'or_conditions', 'not_conditions',
            'in_conditions', 'nin_conditions', 'regex_conditions', 'range_conditions',
            'exists_conditions', 'type_conditions', 'elem_match_conditions',
            'projection', 'sort_data', 'page', 'items_per_page'
        }
        if not set(data.keys()).issubset(valid_keys):
            invalid_keys = set(data.keys()) - valid_keys
            raise CustomValueError(f"Invalid keys: {', '.join(invalid_keys)}. Valid keys are: {', '.join(valid_keys)}.")

        results = searching_boolean_request(
            data,
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

        anonymizer = Anonymizer(connection_string, db_name, collection_name)
        results = anonymize_results(results, anonymizer)

        return jsonify(results)

    except (CustomValueError, CustomTypeError, CustomIndexError, CustomKeyError, CustomFileNotFoundError) as e:
        logger.error(f"Custom error occurred: {str(e)}", exc_info=True)
        return jsonify({"error": str(e), "details": e.details, "traceback": e.traceback}), 400
    except Exception as e:
        logger.error(f"Unexpected error occurred: {str(e)}", exc_info=True)
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500

@app.route('/filtermanager/complex_query', methods=['POST'])
@login_required
@permission_required('user_api_use')
@limiter.limit("5 per minute")
def complex_query():
    try:
        request_data = request.get_json()
        connection_string = request_data.get('connection_string')
        db_name = request_data.get('db_name')
        collection_name = request_data.get('collection_name')
        cond = request_data.get('cond')

        valid_keys = {'cond'}
        if not set(request_data.keys()).issubset(valid_keys):
            invalid_keys = set(request_data.keys()) - valid_keys
            raise CustomValueError(f"Invalid keys: {', '.join(invalid_keys)}. Valid keys are: {', '.join(valid_keys)}.")

        results = complex_query_request(request_data, cond)

        anonymizer = Anonymizer(connection_string, db_name, collection_name)
        results = anonymize_results(results, anonymizer)

        return jsonify(results)

    except (CustomValueError, CustomTypeError, CustomIndexError, CustomKeyError, CustomFileNotFoundError) as e:
        logger.error(f"Custom error occurred: {str(e)}", exc_info=True)
        return jsonify({"error": str(e), "details": e.details, "traceback": e.traceback}), 400
    except Exception as e:
        logger.error(f"Unexpected error occurred: {str(e)}", exc_info=True)
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500

@app.route('/filtermanager/fuzzysearch', methods=['POST'])
@login_required
@permission_required('user_api_use')
@limiter.limit("5 per minute")
def fuzzysearch():
    try:
        data = request.get_json()
        connection_string = data.get('connection_string')
        db_name = data.get('db_name')
        collection_name = data.get('collection_name')
        search_field = data.get('search_field')
        search_value = data.get('search_value')
        filter_data = data.get('filter_data', None)
        projection = data.get('projection', None)
        sort_data = data.get('sort_data', None)
        page = data.get('page', None)
        items_per_page = data.get('items_per_page', None)
        case_sensitive = data.get('case_sensitive', False)
        highlight_field = data.get('highlight_field', None)
        phrase_matching = data.get('phrase_matching', False)
        boost_fields = data.get('boost_fields', None)

        valid_keys = {'search_field', 'search_value'}
        if not set(data.keys()).issubset(valid_keys.union({'filter_data', 'projection', 'sort_data', 'page', 'items_per_page', 'case_sensitive', 'highlight_field', 'phrase_matching', 'boost_fields'})):
            invalid_keys = set(data.keys()) - valid_keys
            raise CustomValueError(f"Invalid keys: {', '.join(invalid_keys)}. Valid keys are: {', '.join(valid_keys.union({'filter_data', 'projection', 'sort_data', 'page', 'items_per_page', 'case_sensitive', 'highlight_field', 'phrase_matching', 'boost_fields'}))}.")

        results = fuzzysearchrequest(
            data,
            search_field,
            search_value,
            filter_data=filter_data,
            projection=projection,
            sort_data=sort_data,
            page=page,
            items_per_page=items_per_page,
            case_sensitive=case_sensitive,
            highlight_field=highlight_field,
            phrase_matching=phrase_matching,
            boost_fields=boost_fields
        )

        anonymizer = Anonymizer(connection_string, db_name, collection_name)
        results = anonymize_results(results, anonymizer)

        return jsonify(results)

    except (CustomValueError, CustomTypeError, CustomIndexError, CustomKeyError, CustomFileNotFoundError) as e:
        logger.error(f"Custom error occurred: {str(e)}", exc_info=True)
        return jsonify({"error": str(e), "details": e.details}), 400
    except Exception as e:
        logger.error(f"Unexpected error occurred: {str(e)}", exc_info=True)
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500

@app.route('/filtermanager/keywordhighlighting', methods=['POST'])
@login_required
@permission_required('user_api_use')
@limiter.limit("5 per minute")
def keywordhighlighting():
    try:
        data = request.get_json()
        connection_string = data.get('connection_string')
        db_name = data.get('db_name')
        collection_name = data.get('collection_name')
        search_field = data.get('search_field')
        keywords = data.get('keywords', [])
        filter_data = data.get('filter_data', None)
        projection = data.get('projection', None)
        sort_data = data.get('sort_data', None)
        page = data.get('page', None)
        items_per_page = data.get('items_per_page', None)
        highlight_tag = data.get('highlight_tag', '<mark>')

        valid_keys = {'search_field', 'keywords'}
        if not set(data.keys()).issubset(valid_keys.union({'filter_data', 'projection', 'sort_data', 'page', 'items_per_page', 'highlight_tag'})):
            invalid_keys = set(data.keys()) - valid_keys
            raise CustomValueError(f"Invalid keys: {', '.join(invalid_keys)}. Valid keys are: {', '.join(valid_keys.union({'filter_data', 'projection', 'sort_data', 'page', 'items_per_page', 'highlight_tag'}))}.")

        results = keywordhighlightingrequest(
            data,
            search_field,
            keywords,
            filter_data=filter_data,
            projection=projection,
            sort_data=sort_data,
            page=page,
            items_per_page=items_per_page,
            highlight_tag=highlight_tag
        )

        return jsonify(results)

    except (CustomValueError, CustomTypeError, CustomIndexError, CustomKeyError, CustomFileNotFoundError) as e:
        logger.error(f"Custom error occurred: {str(e)}", exc_info=True)
        return jsonify({"error": str(e), "details": e.details}), 400
    except Exception as e:
        logger.error(f"Unexpected error occurred: {str(e)}", exc_info=True)
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500

@app.route('/filtermanager/customsortingoptions', methods=['POST'])
@login_required
@permission_required('user_api_use')
@limiter.limit("5 per minute")
def customsortingoptions():
    try:
        data = request.get_json()
        connection_string = data.get('connection_string')
        db_name = data.get('db_name')
        collection_name = data.get('collection_name')
        sort_options = data.get('sort_options', {})
        query = data.get('query', None)
        custom_sort = data.get('custom_sort', None)
        data_types = data.get('data_types', None)
        custom_sort_functions = data.get('custom_sort_functions', None)
        null_handling = data.get('null_handling', 'last')
        offset = data.get('offset', None)
        limit = data.get('limit', None)
        fields = data.get('fields', None)

        valid_keys = {'sort_options', 'query', 'custom_sort', 'data_types', 'custom_sort_functions', 'null_handling', 'offset', 'limit', 'fields'}
        if not set(data.keys()).issubset(valid_keys):
            invalid_keys = set(data.keys()) - valid_keys
            raise CustomValueError(f"Invalid keys: {', '.join(invalid_keys)}. Valid keys are: {', '.join(valid_keys)}.")

        results = customsortingoptionsrequest(
            data,
            query=query,
            custom_sort=sort_options,
            data_types=data_types,
            custom_sort_functions=custom_sort_functions,
            null_handling=null_handling,
            offset=offset,
            limit=limit,
            fields=fields
        )

        anonymizer = Anonymizer(connection_string, db_name, collection_name)
        results = anonymize_results(results, anonymizer)

        return jsonify(results)

    except (CustomValueError, CustomTypeError, CustomIndexError, CustomKeyError, CustomFileNotFoundError) as e:
        logger.error(f"Custom error occurred: {str(e)}", exc_info=True)
        return jsonify({"error": str(e), "details": e.details}), 400
    except Exception as e:
        logger.error(f"Unexpected error occurred: {str(e)}", exc_info=True)
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500

