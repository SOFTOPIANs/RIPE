#!/bin/bash
rm -rf /tmp/rip-eval/*
ls -al /tmp/rip-eval
make
./build/ripe_simple
ls -al /tmp/rip-eval