FROM ubuntu:20.04
RUN apt-get update
RUN apt-get install wget curl make gcc perl -y
RUN apt-get install libapr1-dev libaprutil1-dev libpcre3-dev -y
RUN wget https://archive.apache.org/dist/httpd/httpd-2.4.50.tar.gz
RUN tar -xf httpd-2.4.50.tar.gz
RUN ./httpd-2.4.50/configure --prefix=/
RUN make && make install
ADD httpd.conf /conf/httpd.conf
RUN apachectl -k start
ENTRYPOINT exec httpd -D "FOREGROUND"
