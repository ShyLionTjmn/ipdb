#!/bin/sh

DB_USER=`cat /devel/ipdb/sql/.mysql_user`
DB_PASS=`cat /devel/ipdb/sql/.mysql_password`

DUMP_CMD="mysqldump -u $DB_USER --password=$DB_PASS --skip-extended-insert --order-by-primary --skip-add-drop-table --skip-comments --skip-set-charset --skip-add-locks --no-create-info --skip-triggers"

PREFIX=""

if [ ! -z "$1" ]
then
  PREFIX=".$1"
fi

TABLE="users"
FILE="/devel/ipdb/sql/.00100_${TABLE}${PREFIX}.sql"
echo "save $TABLE to $FILE"
$DUMP_CMD ipdb $TABLE                      > $FILE || exit 1

TABLE="groups"
FILE="/devel/ipdb/sql/.00110_${TABLE}${PREFIX}.sql"
echo "save $TABLE to $FILE"
$DUMP_CMD --where="group_id>2" ipdb $TABLE > $FILE || exit 1

TABLE="ugs"
FILE="/devel/ipdb/sql/.00120_${TABLE}${PREFIX}.sql"
echo "save $TABLE to $FILE"
$DUMP_CMD ipdb $TABLE                      > $FILE || exit 1

