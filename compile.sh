#!/bin/bash

cd /root/exporter/fin-exporter
git pull origin master
go build -o fin-exporter main.go
rm -rf /file/fin-exporter.tar.gz
tar -zcvf /file/fin-exporter.tar.gz fin-exporter
