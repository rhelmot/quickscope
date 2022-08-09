#!/bin/bash

GAME=$1
if [ -z "$GAME" ]; then
	echo "Please specify the game to connect to in argv[1]"
	exit 1
fi

NUM_SERVICES=5
PORT_BASE=5000
ORGA_IP=127.0.1.1

for PODSPEC in $(./teams/get_pods.sh); do
	POD=$(cut -d':' -f 1 <<<"$PODSPEC")
	IP=$(cut -d':' -f 3 <<<"$PODSPEC")
	kubectl port-forward $POD --address=$IP $(($PORT_BASE + 1)) $(($PORT_BASE + 2)) $(($PORT_BASE + 3)) $(($PORT_BASE + 4)) $(($PORT_BASE + 5)) &
done

kubectl port-forward deploy/orga-$GAME --address=$ORGA_IP 1337 1338 &
sleep 5
echo "Port forwarding complete"
echo " - Kill the connection with ctrl-c"
echo " - Flag submission at $ORGA_IP:1337"
echo " - Game status at $ORGA_IP:1338"

trap 'kill -INT $(jobs -p)' INT
wait
