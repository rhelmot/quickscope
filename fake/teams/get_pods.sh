#!/bin/sh
kubectl get pods | grep -o 'team-\w*-\w*-\w*'
