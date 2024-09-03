#!/bin/sh
go build && sudo install ipdb /usr/local/sbin/ && sudo systemctl restart ipdb && sleep 1 && sudo systemctl --no-pager status ipdb
