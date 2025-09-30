#!/bin/bash

cnt=$1
for ((i = 1; i < $cnt+1; i+=1))
do
	java -cp "build/libs/task_J1_client-1.0-SNAPSHOT.jar" ru.nsu.romankin.hoi.Client localhost 8080 "client_$i" 0 false &
done
