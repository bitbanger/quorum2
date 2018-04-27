#!/bin/bash

for pid in $(ps -A | grep ' server$' | awk '{print $1}'); do kill ${pid}; done
