from flask import request, jsonify, Blueprint
from authentication.auth import login_required, limiter, permission_required
from databasebackupmanager.backupmanager import BackupManager
from errorhandling.errormanager import CustomValueError, setup_logging

api = Blueprint('api', __name__)

logger = setup_logging()

@api.route('/filtermanager/backupmanager/backup', methods=['POST'])
@login_required
@permission_required('user_api_use')
@limiter.limit("5 per minute")
def backup():
    data = request.get_json()
    if not data:
        logger.warning("No JSON data received")
        return jsonify({"error": "No JSON data received"}), 400

    db_name = data.get('db_name')
    connection_string = data.get('connection_string')

    if not db_name or not connection_string:
        logger.warning("Missing required fields: db_name or connection_string")
        return jsonify({"error": "db_name or connection_string is empty"}), 400

    try:
        logger.info(f"Initializing BackupManager with db_name: {db_name}")
        backup_manager = BackupManager(db_name, connection_string)
        backup_file = backup_manager.backup()

        if not backup_file:
            raise CustomValueError("Backup operation failed", "No backup file generated")

        logger.info(f"Backup successful: {backup_file}")
        return jsonify({"message": "Backup successful", "backup_file": backup_file}), 200

    except CustomValueError as ve:
        logger.error(f"CustomValueError occurred: {str(ve)}")
        return jsonify({"error": str(ve)}), 400

    except Exception as e:
        logger.exception("Unexpected error occurred")
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500

@api.route('/filtermanager/backupmanager/restore', methods=['POST'])
@login_required
@permission_required('user_api_use')
@limiter.limit("5 per minute")
def restore_by_date():
    data = request.get_json()
    if not data:
        logger.warning("No JSON data received")
        return jsonify({"error": "No JSON data received"}), 400

    db_name = data.get('db_name')
    connection_string = data.get('connection_string')
    backup_date = data.get('backup_date')

    if not db_name or not connection_string or not backup_date:
        logger.warning("Missing required fields: db_name, connection_string, or backup_date")
        return jsonify({"error": "db_name, connection_string, or backup_date is empty"}), 400

    try:
        logger.info(f"Initializing BackupManager with db_name: {db_name} for restore")
        backup_manager = BackupManager(db_name, connection_string)
        restore_message = backup_manager.restore_from_date(backup_date)

        if not restore_message:
            raise CustomValueError("Restore operation failed", f"No backup found for date: {backup_date}")

        logger.info(f"Restore successful: {restore_message}")
        return jsonify({"message": restore_message}), 200

    except CustomValueError as ve:
        logger.error(f"CustomValueError occurred: {str(ve)}")
        return jsonify({"error": str(ve)}), 400

    except Exception as e:
        logger.exception("Unexpected error occurred")
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500

@api.route('/filtermanager/backupmanager/delete', methods=['POST'])
@login_required
@permission_required('user_api_use')
@limiter.limit("5 per minute")
def delete_backup():
    data = request.get_json()
    if not data:
        logger.warning("No JSON data received")
        return jsonify({"error": "No JSON data received"}), 400

    db_name = data.get('db_name')
    connection_string = data.get('connection_string')
    backup_date = data.get('backup_date')

    if not db_name or not connection_string or not backup_date:
        logger.warning("Missing required fields: db_name, connection_string, or backup_date")
        return jsonify({"error": "db_name, connection_string, or backup_date is empty"}), 400

    try:
        logger.info(f"Initializing BackupManager with db_name: {db_name} for deletion")
        backup_manager = BackupManager(db_name, connection_string)
        delete_message = backup_manager.delete_backup_by_date(backup_date)

        if not delete_message:
            raise CustomValueError("Delete operation failed", "No backup deleted")

        logger.info(f"Delete successful: {delete_message}")
        return jsonify({"message": delete_message}), 200

    except CustomValueError as ve:
        logger.error(f"CustomValueError occurred: {str(ve)}")
        return jsonify({"error": str(ve)}), 400

    except Exception as e:
        logger.exception("Unexpected error occurred")
        return jsonify({"error": "An unexpected error occurred", "details": str(e)}), 500
