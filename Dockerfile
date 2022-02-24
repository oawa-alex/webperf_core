# Container image that runs your code
#FROM ubuntu:latest
FROM python:latest

# Copies your code file from your action repository to the filesystem path `/` of the container
#COPY entrypoint.sh /entrypoint.sh
COPY . /webperf-core

RUN apt-get update -y
#RUN apt-get install -y python3.x --no-install-recommends
#RUN apt install python3-pip

RUN python -m pip install --upgrade pip
RUN pip install -r /webperf-core/requirements.txt
RUN python /webperf-core/.github/workflows/verify_result.py -c false
RUN python /webperf-core/.github/workflows/verify_result.py -d

RUN chmod +x /webperf-core/entrypoint.sh
RUN chmod +x /webperf-core/docker-cmd.sh

RUN curl -fsSL https://deb.nodesource.com/setup_14.x | bash -
RUN apt-get install -y nodejs

RUN wget -q -O vnu.jar https://github.com/validator/validator/releases/download/latest/vnu.jar

RUN npm install -g lighthouse
RUN npm install -g node-gyp
RUN apt-get install libjpeg-dev libfontconfig
RUN npm install -g yellowlabtools

#RUN /webperf-core/docker-cmd.sh

# Give us a updated list of project that want funding so we can update it on our page
RUN npm fund

# Executes `entrypoint.sh` when the Docker container starts up
ENTRYPOINT ["/webperf-core/entrypoint.sh"]