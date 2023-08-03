kill $(ps -ef|grep fin-exporter|grep -v grep|awk '{print $2}')
cd /root
rm -rf fin-exporter
mkdir fin-exporter
cd fin-exporter
yum install -y libpcap-devel
wget http://34.87.43.172:2023/fin-exporter.tar.gz
tar -zxvf fin-exporter.tar.gz
nohup ./fin-exporter >log 2>&1 &
firewall-cmd --zone=public --add-port=50055/tcp --permanent
firewall-cmd --reload
