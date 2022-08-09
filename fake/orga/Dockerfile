# rhelmot/fake_orga
FROM python:3.8

WORKDIR /root
RUN pip install nclib
ADD orga.py /root/orga.py
ADD teams.txt /root/teams.txt
ADD services.txt /root/services.txt
ENTRYPOINT python orga.py /root/teams.txt /root/services.txt
# serves port 1337 and 1338
