#!/bin/sh

DB_USER=`cat /devel/ipdb/sql/.mysql_user`
DB_PASS=`cat /devel/ipdb/sql/.mysql_password`
MYSQL="mysql -u $DB_USER --password=$DB_PASS -D ipdb"

/devel/ipdb/sql/save_local_data.sh auto

echo "deleting all tables"
$MYSQL -B -N -e 'SHOW TABLES' | sed 's/.*/DROP TABLE &;/' | $MYSQL --init-command="SET FOREIGN_KEY_CHECKS=0;"

for f in /devel/ipdb/sql/schema.sql /devel/ipdb/sql/schema_populate_ru.sql /devel/ipdb/sql/local_data.sql
do
  echo "Importing $f"
  $MYSQL < $f || exit 1
done

for f in `ls /devel/ipdb/sql/.0*.auto.sql`
do
  echo "Importing $f"
  $MYSQL < $f || exit 1
done
