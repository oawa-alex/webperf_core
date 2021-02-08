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
from decimal import Decimal

import config
from tests.utils import *
import gettext
_ = gettext.gettext

def run_test(langCode, url):
	"""
	Analyzes URL with Website Carbon Calculator API.
	API documentation: https://api.websitecarbon.com
	https://gitlab.com/wholegrain/carbon-api-2-0
	"""

	language = gettext.translation('energy_efficiency_websitecarbon', localedir='locales', languages=[langCode])
	language.install()
	_ = language.gettext

	print(_("TEXT_RUNNING_TEST"))

	result_json = httpRequestGetContent('https://api.websitecarbon.com/site?url={0}'.format(url))
	result_dict = json.loads(result_json)

	#print(result_json)

	green = str(result_dict['green'])
	#print("Grön?", green)

	co2 = Decimal(result_dict['statistics']['co2']['grid']['grams'])
	#print('Co2', round(co2, 2), 'gram')

	cleaner_than = int(Decimal(result_dict['cleanerThan']) * 100)
	#print("Renare än:", cleaner_than, "%")
	
	review = ''
	rating = -1

	if co2 < 0.8:
		rating = 5
	elif co2 < 1.2:
		rating = 4
	elif co2 < 2:
		rating = 3
	elif co2 <= 4:
		rating = 2
	elif co2 > 4:
		rating = 1

	#print(rating)

	if rating == 5:
		review = _("TEXT_WEBSITE_IS_VERY_GOOD")
	elif rating >= 4:
		review = _("TEXT_WEBSITE_IS_GOOD")
	elif rating >= 3:
		review = _("TEXT_WEBSITE_IS_OK")
	elif rating >= 2:
		review = _("TEXT_WEBSITE_IS_BAD")
	elif rating <= 1:
		review = _("TEXT_WEBSITE_IS_VERY_BAD")

	review += _("TEXT_GRAMS_OF_CO2").format(round(co2, 2))
	review += _("TEXT_BETTER_THAN").format(cleaner_than)
	if 'false' in green.lower():
		review += _("TEXT_GREEN_ENERGY_FALSE")
	elif 'true' in green.lower():
		review += _("TEXT_GREEN_ENERGY_TRUE")
	

	return (rating, review, result_dict)