#!/bin/sh

GAME=$1
if [ -z "$GAME" ]; then
	echo "Please pass game ID as argv[1]"
	exit 1
fi

sed -e "s/\$GAME/$GAME/g" orga.yaml
