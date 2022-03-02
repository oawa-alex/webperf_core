# Container image that runs your code
#FROM ubuntu:latest
FROM python:latest
LABEL name="webperf-core" \
  maintainer="Mattias <mattias@webperf.se>" \
  description="The project goal is to help identify and improve the web over time, one improvment at a time. It tries to do this by giving you a weighted list of improvment you can (and probably should do) to your website."
# Copies your code file from your action repository to the filesystem path `/` of the container
#COPY entrypoint.sh /entrypoint.sh
COPY . /webperf-core

# RUN export DEBIAN_FRONTEND="noninteractive"

RUN apt-get update -y


RUN wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | gpg --no-default-keyring --keyring gnupg-ring:/etc/apt/trusted.gpg.d/NAME.gpg --import
RUN chown _apt /etc/apt/trusted.gpg.d/NAME.gpg
#RUN wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - 
RUN sh -c 'echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list'
RUN apt-get update -y
RUN apt-get --only-upgrade install google-chrome-stable -y
RUN apt-get install -y google-chrome-stable
RUN google-chrome --version

#RUN dpkg --configure -a
#RUN apt-get install apt-utils -y

# Install deps + add Chrome Stable + purge all the things
# RUN apt-get update && apt-get install -y \
#   apt-transport-https \
#   ca-certificates \
#   curl \
#   gnupg \
#   --no-install-recommends \
#   && curl -sSL https://deb.nodesource.com/setup_12.x | bash - \
#   && curl -sSL https://dl.google.com/linux/linux_signing_key.pub | apt-key add - \
#   && echo "deb https://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list \
#   && apt-get update && apt-get install -y \
#   google-chrome-stable \
#   fontconfig \
#   fonts-ipafont-gothic \
#   fonts-wqy-zenhei \
#   fonts-thai-tlwg \
#   fonts-kacst \
#   fonts-symbola \
#   fonts-noto \
#   fonts-freefont-ttf \
#   nodejs \
#   --no-install-recommends \
#   && apt-get purge --auto-remove -y curl gnupg \
#   && rm -rf /var/lib/apt/lists/*


RUN apt-get install default-jre -y
#RUN apt-get install -y python3.x --no-install-recommends
#RUN apt install python3-pip

RUN chmod +x /webperf-core/entrypoint.sh

RUN apt-get install libjpeg-dev libfontconfig -y


RUN groupadd -r webperf
RUN useradd -r -g webperf -G audio,video webperf
RUN mkdir -p /home/webperf/reports
RUN chown -R webperf:webperf /home/webperf
RUN chown -R webperf:webperf /webperf-core/
USER webperf


RUN python -m pip install --upgrade pip
RUN pip install -r /webperf-core/requirements.txt
RUN python /webperf-core/.github/workflows/verify_result.py -c false
#RUN python /webperf-core/.github/workflows/verify_result.py -d
#RUN chmod +x /webperf-core/docker-cmd.sh

RUN curl -fsSL https://deb.nodesource.com/setup_14.x | bash -
RUN apt-get install -y nodejs

RUN wget -q -O vnu.jar https://github.com/validator/validator/releases/download/latest/vnu.jar

# Add Chrome as a user
#RUN groupadd -r webperf-user && useradd -r -g webperf-user -G audio,video webperf-user \
#  && mkdir -p /home/webperf-user/reports && chown -R webperf-user:webperf-user /home/webperf-user

RUN npm install -g lighthouse
RUN npm install -g node-gyp
# RUN apt-get install libjpeg-dev libfontconfig -y
#RUN npm install -g yellowlabtools

#RUN /webperf-core/docker-cmd.sh

# Give us a updated list of project that want funding so we can update it on our page
RUN npm fund

# Run Chrome non-privileged
#USER webperf

#RUN lighthouse https://webperf.se/ --output json --output-path stdout --locale en --only-categories performance --form-factor mobile --chrome-flags="--headless --disable-gpu --no-sandbox"
RUN lighthouse https://webperf.se/ --output json --output-path stdout --locale en --only-categories performance --form-factor mobile --chrome-flags="--headless --disable-gpu" --quiet

# Executes `entrypoint.sh` when the Docker container starts up
ENTRYPOINT ["/webperf-core/entrypoint.sh"]