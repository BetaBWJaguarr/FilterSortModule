from flask import request, jsonify, Blueprint
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

    page = request.args.get('page', type=int)
    items_per_page = request.args.get('items_per_page', type=int)

    data_manager = get_data_manager(data)
    results = data_manager.match(filter_data, page, items_per_page, projection)

    return jsonify(results)

@app.route('/filtermanager/sort', methods=['POST'])
def sort_request():
    data = request.get_json()
    sort_data = data.get('sort', None)

    data_manager = get_data_manager(data)
    results = data_manager.sort({}, sort_data)

    return jsonify(results)