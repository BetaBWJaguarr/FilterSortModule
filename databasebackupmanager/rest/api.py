from flask import request, jsonify, Blueprint
from databasebackupmanager.backupmanager import BackupManager
from errorhandling.errormanager import CustomValueError

api = Blueprint('api', __name__)

backup_manager = None

@api.route('/filtermanager/backupmanager/backup', methods=['POST'])
def backup():
    try:
        data = request.get_json()
        if not data:
            raise CustomValueError("Invalid JSON data", "No JSON data received")

        db_name = data.get('db_name')
        connection_string = data.get('connection_string')

        if not db_name or not connection_string:
            raise CustomValueError("Missing required fields", "db_name or connection_string is empty")

        backup_manager = BackupManager(db_name, connection_string)
        backup_file = backup_manager.backup()

        if not backup_file:
            raise CustomValueError("Backup operation failed", "No backup file generated")

        return jsonify({"message": "Backup successful", "backup_file": backup_file}), 200

    except CustomValueError as ve:
        return jsonify({"error": str(ve)}), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@api.route('/filtermanager/backupmanager/restore', methods=['POST'])
def restore_by_date():
    try:
        data = request.get_json()
        if not data:
            raise CustomValueError("Invalid JSON data", "No JSON data received")

        db_name = data.get('db_name')
        connection_string = data.get('connection_string')
        backup_date = data.get('backup_date')

        if not db_name or not connection_string or not backup_date:
            raise CustomValueError("Missing required fields", "db_name, connection_string, or backup_date is empty")

        backup_manager = BackupManager(db_name, connection_string)
        restore_message = backup_manager.restore_from_date(backup_date)

        if not restore_message:
            raise CustomValueError("Restore operation failed", f"No backup found for date: {backup_date}")

        return jsonify({"message": restore_message}), 200

    except CustomValueError as ve:
        return jsonify({"error": str(ve)}), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api.route('/filtermanager/backupmanager/delete', methods=['POST'])
def delete_backup():
    try:
        data = request.get_json()
        if not data:
            raise CustomValueError("Invalid JSON data", "No JSON data received")

        db_name = data.get('db_name')
        connection_string = data.get('connection_string')
        backup_date = data.get('backup_date')

        if not db_name or not connection_string or not backup_date:
            raise CustomValueError("Missing required fields", "db_name, connection_string, or backup_date is empty")

        backup_manager = BackupManager(db_name, connection_string)
        delete_message = backup_manager.delete_backup_by_date(backup_date)

        if not delete_message:
            raise CustomValueError("Delete operation failed", "No backup deleted")

        return jsonify({"message": delete_message}), 200

    except CustomValueError as ve:
        return jsonify({"error": str(ve)}), 400
