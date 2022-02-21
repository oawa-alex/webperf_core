# Container image that runs your code
FROM python:latest

# Copies your code file from your action repository to the filesystem path `/` of the container
#COPY entrypoint.sh /entrypoint.sh
COPY . /webperf-core

RUN python -m pip install --upgrade pip
RUN pip install -r /webperf-core/requirements.txt
RUN python /webperf-core/.github/workflows/verify_result.py -c false

# Executes `entrypoint.sh` when the Docker container starts up
ENTRYPOINT ["/webperf-core/entrypoint.sh"]