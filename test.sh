#!/bin/bash

echo "Starting run.sh..."
bash run.sh > run.log 2>&1 &
run_pid=$!
sleep 10

echo "Starting tshark..."
sudo tshark -i utun7 > tshark.log 2>&1 &
tshark_pid=$!

sleep 10
echo "Sending data using netcat..."
echo "Hello from GK" | nc 192.168.0.2 443

echo "Wait for background task to complete..."
wait $run_pid
wait $tshark_pid

echo "---------tcp server log start---------"
cat run.log
echo "----------tcp server log end----------"
echo ""

echo "---------tshark log start---------"
cat tshark.log
echo "----------tshark log end----------"