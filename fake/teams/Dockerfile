FROM python:3.8

WORKDIR /root
RUN pip install nclib supervisor
ADD supervisord.conf /root/supervisord.conf
ADD service.py /root/service.py
ENTRYPOINT supervisord -sn
