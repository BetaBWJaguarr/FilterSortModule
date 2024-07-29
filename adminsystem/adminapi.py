from flask import Blueprint, request, jsonify, send_file
import pandas as pd
from datetime import datetime
from pymongo import errors
from io import BytesIO
from authentication.shared import admin_logs
from authentication.permissionsmanager.permissions import permission_required

admin_api = Blueprint('admin_api', __name__)

@admin_api.route('/filtermanager/admin/activity_report', methods=['GET'])
@permission_required('admin_api_use')
def generate_report():
    try:
        start_date_str = request.args.get('start_date')
        end_date_str = request.args.get('end_date')
        action_filter = request.args.get('action')
        status_filter = request.args.get('status')

        if not start_date_str or not end_date_str:
            return jsonify({"error": "start_date and end_date parameters are required"}), 400

        try:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d')
        except ValueError:
            return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400

        if start_date > end_date:
            return jsonify({"error": "start_date cannot be after end_date"}), 400

        query = {
            "timestamp": {"$gte": start_date, "$lte": end_date}
        }

        if action_filter:
            query["action"] = action_filter

        if status_filter:
            query["status"] = status_filter

        logs = admin_logs.find(query)

        df = pd.DataFrame(list(logs))

        if df.empty:
            return jsonify({"message": "No data available for the given date range"}), 404

        df.drop(columns=['_id'], inplace=True)

        output = BytesIO()
        df.to_csv(output, index=False)
        output.seek(0)

        return send_file(
            output,
            mimetype='text/csv',
            as_attachment=True,
            download_name='admin_activity_report.csv'
        )
    except errors.PyMongoError as e:
        return jsonify({"error": "Database error. Please try again later."}), 500
    except Exception as e:
        return jsonify({"error": "An unexpected error occurred. Please try again later."}), 500
