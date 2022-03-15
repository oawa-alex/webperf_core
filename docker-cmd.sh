cd /webperf-core
pip install -r requirements.txt
wget -q -O vnu.jar https://github.com/validator/validator/releases/download/latest/vnu.jar
npm install -g lighthouse
apt-get update -y
apt-get install -y imagemagick libjpeg-dev xz-utils --no-install-recommends --force-yes
python -m pip install --upgrade pip
python -m pip install --upgrade setuptools
python -m pip install pyssim Pillow image
apt install ffmpeg
google-chrome --version
wget -q -O data/blocklistproject-ads-nl.txt https://blocklistproject.github.io/Lists/alt-version/ads-nl.txt
wget -q -O data/blocklistproject-tracking-nl.txt https://blocklistproject.github.io/Lists/alt-version/tracking-nl.txt
wget -q -O data/disconnect-services.json https://raw.githubusercontent.com/disconnectme/disconnect-tracking-protection/master/services.json
wget -q -O - https://github.com/mozilla/geckodriver/releases/download/v0.30.0/geckodriver-v0.30.0-linux64.tar.gz | tar -xvzf -
npm install -g node-gyp
apt-get install libjpeg-dev libfontconfig
npm install -g yellowlabtools
