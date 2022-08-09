#!/bin/bash

NUM_SERVICES=5
PORT_BASE=5000

IDX=1
for POD in $(./get_pods.sh); do
	kubectl port-forward $POD --address=127.0.0.$IDX $(($PORT_BASE + 1)) $(($PORT_BASE + 2)) $(($PORT_BASE + 3)) $(($PORT_BASE + 4)) $(($PORT_BASE + 5)) &
	IDX=$(($IDX + 1))
done

trap 'kill -INT $(jobs -p)' INT
wait
