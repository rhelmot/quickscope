#!/usr/bin/zsh

NUM_TEAMS=200
for i in $(seq $NUM_TEAMS); do
	D1=0
	D2=$((0.2 * $i / $NUM_TEAMS))
	D3=$((0.5 * $i / $NUM_TEAMS))
	D4=$((0.8 * $i / $NUM_TEAMS))
	D5=1
	sed -e "s/\$TEAM_ID/$i/g" -e "s/\$D1/$D1/g" -e "s/\$D2/$D2/g" -e "s/\$D3/$D3/g" -e "s/\$D4/$D4/g" -e "s/\$D5/$D5/g" team.yaml
done
