#!/bin/sh

DB_USER=`cat /devel/ipdb/sql/.mysql_user`
DB_PASS=`cat /devel/ipdb/sql/.mysql_password`
MYSQL="mysql -u $DB_USER --password=$DB_PASS -D ipdb"

BACKUP_FILE="/devel/ipdb/sql/.backup_"`date +%s`".sql"

on_error() {
  echo "Restoring from backup"
  $MYSQL -B -N -e 'SHOW TABLES' | sed 's/.*/DROP TABLE &;/' | $MYSQL --init-command="SET FOREIGN_KEY_CHECKS=0;" || exit 1
  $MYSQL < $BACKUP_FILE
  exit 1
}

echo "backing up whole database to $BACKUP_FILE"
mysqldump -u $DB_USER --password=$DB_PASS --skip-extended-insert --order-by-primary ipdb > $BACKUP_FILE || exit 1

if [ "$1" != "nosave" ]
then
  /devel/ipdb/sql/save_local_data.sh auto
fi

echo "deleting all tables"
$MYSQL -B -N -e 'SHOW TABLES' | sed 's/.*/DROP TABLE &;/' | $MYSQL --init-command="SET FOREIGN_KEY_CHECKS=0;" || on_error

for f in /devel/ipdb/sql/schema.sql /devel/ipdb/sql/schema_populate_ru.sql /devel/ipdb/sql/local_data.sql /devel/ipdb/sql/test_nets.sql /devel/ipdb/sql/test_ranges.sql
do
  echo "Importing $f"
  $MYSQL < $f || on_error
done

if [ "$1" != "nosave" ]
then
  for f in `ls /devel/ipdb/sql/.0*.auto.sql`
  do
    echo "Importing $f"
    $MYSQL < $f || on_error
  done
fi

if [ "$1" != "nosave" ]
then
  find /devel/ipdb/sql -mount -type f -name ".backup_*.sql" -mtime +1 -ls -exec rm {} \;
fi
