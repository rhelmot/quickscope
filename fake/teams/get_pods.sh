#!/bin/sh
kubectl get pods -l app=team -o custom-columns='NAME:.metadata.name,IP:.status.podIP' | tail -n +2 | awk '{ print $1 ":" $2 ":127.0.0." ++i }'
