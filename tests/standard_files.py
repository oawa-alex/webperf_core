#-*- coding: utf-8 -*-
import sys
import socket
import ssl
import json
import requests
import urllib # https://docs.python.org/3/library/urllib.parse.html
import uuid
import re
from bs4 import BeautifulSoup
import config
from tests.utils import *

### DEFAULTS
request_timeout = config.http_request_timeout
googlePageSpeedApiKey = config.googlePageSpeedApiKey

def run_test(url):
	"""
	Looking for:
	* robots.txt
	* at least one sitemap/siteindex mentioned in robots.txt
	* a RSS feed mentioned in the page's meta
	"""
	o = urllib.parse.urlparse(url)
	parsed_url = '{0}://{1}/'.format(o.scheme, o.netloc)
	robots_content = httpRequestGetContent(parsed_url + 'robots.txt')

	review = ''
	return_dict = dict()
	return_dict["num_sitemaps"] = 0
	points = 5.0

	if robots_content == None or ('user-agent' not in robots_content.lower() and 'disallow' not in robots_content.lower() and 'allow' not in robots_content.lower()):
		points -= 3
		review += '* robots.txt saknas, får inte lov att hämtas eller har inte förväntat innehåll.\n'
		return_dict['robots.txt'] = 'missing content'
	else:
		review += '* robots.txt verkar ok.\n'
		return_dict['robots.txt'] = 'ok'

		if 'sitemap:' not in robots_content.lower():
			points -= 2
			review += '* Sitemap anges inte i robots.txt\n'
			return_dict['sitemap'] = 'not in robots.txt'
		else:
			review += '* Sitemap finns omnämnd i robots.txt\n'
			return_dict['sitemap'] = 'ok'

		smap_pos = robots_content.lower().find('sitemap')
		smaps = robots_content[smap_pos:].split('\n')
		found_smaps = []
		for line in smaps:
			if 'sitemap:' in line.lower():
				found_smaps.append(line.lower().replace('sitemap:', '').strip())
		
		return_dict["num_sitemaps"] = len(found_smaps)
		
		if len(found_smaps) > 0:
			return_dict["sitemaps"] = found_smaps
			smap_content = httpRequestGetContent(found_smaps[0])

			if not is_sitemap(smap_content):
				points -= 1
				review += '* Sitemap verkar vara trasig.\n'
				return_dict['sitemap_check'] = '\'{0}\' seem to be broken'.format(found_smaps[0])
			else:
				review += '* Sitemap verkar fungera.\n'
				return_dict['sitemap_check'] = '\'{0}\' seem ok'.format(found_smaps[0])
		
	# TODO: validate first feed
	headers = {'user-agent': config.useragent}
	request = requests.get(url, allow_redirects=True, headers=headers, timeout=request_timeout)

	soup = BeautifulSoup(request.text, 'lxml')
	#feed = soup.find_all(rel='alternate')
	feed = soup.find_all("link", {"type" : "application/rss+xml"})

	if len(feed) == 0:
		points -= 0.5
		review += '* RSS-prenumeration saknas i meta.\n'
		return_dict['feed'] = 'not in meta'
		return_dict['num_feeds'] = len(feed)
	elif len(feed) > 0:
		review += '* RSS-prenumeration hittad.\n'
		return_dict['feed'] = 'found in meta'
		return_dict['num_feeds'] = len(feed)
		tmp_feed = []
		for single_feed in feed:
			tmp_feed.append(single_feed.get('href'))

		return_dict['feeds'] = tmp_feed
	
	if points < 1:
		points = 1

	return (points, review, return_dict)
