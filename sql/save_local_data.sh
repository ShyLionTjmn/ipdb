#!/bin/sh

DB_USER=`cat .mysql_user`
DB_PASS=`cat .mysql_password`

DUMP_CMD="mysqldump -u $DB_USER --password=$DB_PASS --skip-extended-insert --complete-insert --order-by-primary --skip-add-drop-table --skip-comments --skip-set-charset --skip-add-locks --no-create-info --skip-triggers"

PREFIX=""

if [ ! -z "$1" ]
then
  PREFIX=".$1"
fi

TABLE="us"
FILE=".00100_${TABLE}${PREFIX}.sql"
echo "save $TABLE to $FILE"
$DUMP_CMD ipdb $TABLE                      > $FILE || exit 1

TABLE="gs"
FILE=".00110_${TABLE}${PREFIX}.sql"
echo "save $TABLE to $FILE"
$DUMP_CMD ipdb $TABLE > $FILE || exit 1

