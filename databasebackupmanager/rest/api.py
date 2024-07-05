from flask import request, jsonify, Blueprint
from databasebackupmanager.backupmanager import BackupManager

api = Blueprint('api', __name__)

backup_manager = None

@api.route('/filtermanager/backupmanager/backup', methods=['POST'])
def backup():
    try:
        data = request.get_json()
        db_name = data.get('db_name')
        connection_string = data.get('connection_string')

        backup_manager = BackupManager(db_name, connection_string)
        backup_file = backup_manager.backup()
        return jsonify({"message": "Backup successful", "backup_file": backup_file}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api.route('/filtermanager/backupmanager/restore', methods=['POST'])
def restore_by_date():
    try:
        data = request.get_json()
        db_name = data.get('db_name')
        connection_string = data.get('connection_string')
        backup_date = data.get('backup_date')

        backup_manager = BackupManager(db_name, connection_string)
        restore_message = backup_manager.restore_from_date(backup_date)
        return jsonify({"message": restore_message}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api.route('/filtermanager/backupmanager/delete', methods=['POST'])
def delete_backup():
    try:
        data = request.get_json()
        db_name = data.get('db_name')
        connection_string = data.get('connection_string')
        backup_date = data.get('backup_date')

        backup_manager = BackupManager(db_name, connection_string)
        delete_message = backup_manager.delete_backup_by_date(backup_date)
        return jsonify({"message": delete_message}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
