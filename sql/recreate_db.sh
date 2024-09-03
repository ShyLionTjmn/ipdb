#!/bin/sh

echo "Stop it!"
exit 1

cd /devel/go/src/github.com/ShyLionTjmn/ipdb/sql

DB_USER=`cat .mysql_user`
DB_PASS=`cat .mysql_password`
MYSQL="mysql -u $DB_USER --password=$DB_PASS -D ipdb"

BACKUP_FILE=".backup_"`date +%s`".sql"

on_error() {
  echo "Restoring from backup"
  $MYSQL -B -N -e 'SHOW TABLES' | sed 's/.*/DROP TABLE &;/' | $MYSQL --init-command="SET FOREIGN_KEY_CHECKS=0;" || exit 1
  $MYSQL < $BACKUP_FILE
  exit 1
}

echo "Backing up whole database to $BACKUP_FILE"
mysqldump -u $DB_USER --password=$DB_PASS --skip-extended-insert --order-by-primary ipdb > $BACKUP_FILE || exit 1

echo "Deleting all tables"
$MYSQL -B -N -e 'SHOW TABLES' | sed 's/.*/DROP TABLE &;/' | $MYSQL --init-command="SET FOREIGN_KEY_CHECKS=0;" || on_error

for f in schema.sql local_before_*.sql
do
  if [ -f "$f" ]
  then
    echo "Importing $f"
    $MYSQL < $f || on_error
  fi
done

echo "Importing OLD IPDB"
/devel/go/src/github.com/ShyLionTjmn/import_ipdb/import_ipdb

for f in local_after_*.sql
do
  if [ -f "$f" ]
  then
    echo "Importing $f"
    $MYSQL < $f || on_error
  fi
done

