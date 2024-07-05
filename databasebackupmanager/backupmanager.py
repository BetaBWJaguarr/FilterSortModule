from pymongo import MongoClient
from datetime import datetime
import os
import subprocess

mongodump_path = r'C:\Program Files\MongoDB\Tools\100\bin\mongodump.exe'
mongorestore_path = r'C:\Program Files\MongoDB\Tools\100\bin\mongorestore.exe'

class BackupManager:
    def __init__(self, db_name, connection_string, backup_root_dir='T:\\TunaProjects\\FilterSortModules\\backups'):
        self.client = MongoClient(connection_string)
        self.db_name = db_name
        self.connection_string = connection_string
        self.backup_root_dir = backup_root_dir
        if not os.path.exists(backup_root_dir):
            os.makedirs(backup_root_dir)

    def _generate_backup_filename(self):
        timestamp = datetime.now().strftime('%Y%m%d')
        backup_dir = os.path.join(self.backup_root_dir, timestamp)
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        return os.path.join(backup_dir, f'{self.db_name}_backup.gz')

    def backup(self):
        backup_file = self._generate_backup_filename()
        command = f'"{mongodump_path}" --uri="{self.connection_string}" --db={self.db_name} --archive="{backup_file}" --gzip'
        subprocess.run(command, shell=True)
        return backup_file

    def restore(self, backup_file):
        full_path = os.path.join(self.backup_root_dir, backup_file)
        if not os.path.exists(full_path):
            raise Exception(f'Backup file {full_path} does not exist')
        command = f'"{mongorestore_path}" --uri="{self.connection_string}" --nsInclude={self.db_name}.* --archive="{full_path}" --gzip --drop'
        result = subprocess.run(command, shell=True)
        if result.returncode != 0:
            raise Exception(f'Restore failed with exit code {result.returncode}')
        return f'{self.db_name} restored from {backup_file}'

    def restore_from_date(self, backup_date):
        backup_dir = os.path.join(self.backup_root_dir, backup_date)
        if not os.path.exists(backup_dir):
            raise ValueError(f'No backup available for date {backup_date}')

        latest_backup = max((entry for entry in os.scandir(backup_dir) if entry.is_file()), key=lambda entry: entry.stat().st_ctime)
        backup_file = latest_backup.name
        return self.restore(os.path.join(backup_date, backup_file))

    def delete_backup_by_date(self, backup_date):
        backup_dir = os.path.join(self.backup_root_dir, backup_date)
        if not os.path.exists(backup_dir):
            raise ValueError(f'No backup available for date {backup_date}')

        for entry in os.scandir(backup_dir):
            if entry.is_file():
                os.remove(entry.path)

        os.rmdir(backup_dir)
        return f'Backups for date {backup_date} deleted successfully'
