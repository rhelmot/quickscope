import os

# x-service-name: test_svc

host = os.environ['HOST']
port = os.environ['PORT']
flag_id = os.environ['FLAG_ID']

print(host, port, flag_id)
