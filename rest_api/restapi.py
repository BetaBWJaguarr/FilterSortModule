from flask import request, jsonify, Blueprint
from errorhandling.errormanager import CustomValueError, CustomTypeError, CustomIndexError, CustomKeyError, CustomFileNotFoundError
from filtermanager.managers.manager import match_request, sort_request,multi_filter_request

app = Blueprint('restapi', __name__)

@app.route('/filtermanager/match', methods=['POST'])
def match():
    try:
        data = request.get_json()
        filter_data = data.get('match')
        projection = data.get('projection')
        sort_data = data.get('sort')
        text_search = data.get('text_search')
        regex_search = data.get('regex_search')

        page = request.args.get('page', type=int)
        items_per_page = request.args.get('items_per_page', type=int)
        valid_keys = {'db_name', 'collection_name', 'connection_string', 'match', 'projection', 'sort', 'text_search', 'regex_search'}
        if not set(data.keys()).issubset(valid_keys):
            invalid_keys = set(data.keys()) - valid_keys
            raise CustomValueError(f"Invalid keys: {', '.join(invalid_keys)}. Valid keys are: {', '.join(valid_keys)}.")

        results = match_request(data, filter_data, page, items_per_page, projection, sort_data, text_search, regex_search)
        return jsonify(results)
    except (CustomValueError, CustomTypeError, CustomIndexError, CustomKeyError, CustomFileNotFoundError) as e:
        return jsonify({"error": str(e), "details": e.details, "traceback": e.traceback}), 400
    except Exception as e:
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500

@app.route('/filtermanager/sort', methods=['POST'])
def sort():
    try:
        data = request.get_json()
        filter_data = data.get('filter', {})
        sort_data = data.get('sort', None)
        compare_field = data.get('compare_field', None)

        valid_keys = {'db_name', 'collection_name', 'connection_string', 'filter', 'sort', 'compare_field'}
        if not set(data.keys()).issubset(valid_keys):
            invalid_keys = set(data.keys()) - valid_keys
            raise CustomValueError(f"Invalid keys: {', '.join(invalid_keys)}. Valid keys are: {', '.join(valid_keys)}.")

        results = sort_request(data, filter_data, sort_data, compare_field)
        return jsonify(results)
    except (CustomValueError, CustomTypeError, CustomIndexError, CustomKeyError, CustomFileNotFoundError) as e:
        return jsonify({"error": str(e), "details": e.details, "traceback": e.traceback}), 400
    except Exception as e:
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500

@app.route('/filtermanager/multi_filter', methods=['POST'])
def multi_filter():
    try:
        data = request.get_json()
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
        return jsonify(results)
    except (CustomValueError, CustomTypeError, CustomIndexError, CustomKeyError, CustomFileNotFoundError) as e:
        return jsonify({"error": str(e), "details": e.details, "traceback": e.traceback}), 400
    except Exception as e:
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500