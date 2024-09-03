#!/bin/sh

cd /devel/go/src/github.com/ShyLionTjmn/ipdb/www
cp ipdb.js local_ipdb.js.`date +%Y-%m-%d.%H:%M:%S`
cp ipdb_dev.js ipdb.js

DELLIST=`ls -t local_ipdb.js.* | tail -n +7`
if [ ! -z "$DELLIST" ]
then
  rm $DELLIST
fi
