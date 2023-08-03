#!/bin/bash

cd /root/exporter/fin-exporter
git pull origin master
go build -o fin-exporter main.go
tar -zcvf /file/fin-exporter.tar.gz fin-exporter
