#!/bin/bash

export GWC_SERVER_ADDR=45.83.104.102;
export GWC_SERVER_PORT=60443;
# export GWC_BIND_IFACE_000=enx00e04c680cac;
# export GWC_BIND_IP_000=10.20.0.2;
export GWC_BIND_IFACE_001=wlo1;
export GWC_BIND_IP_001=192.168.240.80;
./gwstms client;

