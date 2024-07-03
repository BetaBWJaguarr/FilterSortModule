from flask import request, jsonify, Blueprint
from errorhandling.errormanager import CustomValueError
from filtermanager.filtermanager import DataManager

app = Blueprint('restapi', __name__)

def get_data_manager(data):
    db_name = data.get('db_name')
    collection_name = data.get('collection_name')
    connection_string = data.get('connection_string')
    return DataManager(db_name, collection_name, connection_string)

@app.route('/filtermanager/match', methods=['POST'])
def match_request():
    data = request.get_json()
    filter_data = data.get('filter')
    projection = data.get('projection')
    sort_data = data.get('sort')
    text_search = data.get('text_search')
    regex_search = data.get('regex_search')

    page = request.args.get('page', type=int)
    items_per_page = request.args.get('items_per_page', type=int)

    try:
        data_manager = get_data_manager(data)
        results = data_manager.match(filter_data, page, items_per_page, projection, sort_data, text_search, regex_search)
        return jsonify(results)
    except CustomValueError as e:
        return jsonify({"error": str(e)}), 400

@app.route('/filtermanager/sort', methods=['POST'])
def sort_request():
    data = request.get_json()
    sort_data = data.get('sort', None)
    compare_field = data.get('compare_field', None)

    try:
        data_manager = get_data_manager(data)
        results = data_manager.sort(sort_data, compare_field)
        return jsonify(results)
    except CustomValueError as e:
        return jsonify({"error": str(e)}), 400
