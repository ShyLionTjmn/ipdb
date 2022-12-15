#!/bin/sh

DB_USER=`cat .mysql_user`
DB_PASS=`cat .mysql_password`
MYSQL="mysql -u $DB_USER --password=$DB_PASS -D ipdb"

echo "deleting all tables"
$MYSQL -B -N -e 'SHOW TABLES' | sed 's/.*/DROP TABLE &;/' | $MYSQL --init-command="SET FOREIGN_KEY_CHECKS=0;"
