import xmltodict
import requests
import urllib3
import argparse
import sys

# Copyright (c) 2020
# Author: Matt Smith <https://github.com/Mediab0t/>

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


__author__ = "Matt Smith <https://github.com/Mediab0t/>"
__copyright__ = "Copyright 2020, Palo Alto Networks, Inc."
__license__ = "GPLv3"
__version__ = "0.9.0"
__status__ = "Development"
__repository__ = "https://github.com/Mediab0t/panos-pandb-query"


class PanOSXMLAPI():

	def __init__(self, host, port, api_key, tls_verify, timeout, verbose):

		self.params = {
			'ngfw_host': str(host),
			'ngfw_port': int(port),
			'ngfw_api_key': str(api_key),
			'ngfw_tls_verify': bool(tls_verify),
			'ngfw_timeout': int(timeout),
			'verbose': bool(verbose)
		}

		if self.params.get('ngfw_tls_verify') is False:
			urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

		# If using a custom port (e.g. when GlobalProtect Clientless and management are enabled on the same interface)
		if port == 443:
			self.params['ngfw_base_url'] = 'https://' + self.params['ngfw_host'] + '/api/'
		else:
			self.params['ngfw_base_url'] = 'https://' + self.params['ngfw_host'].rstrip('/:') + ':' + str(
				self.params['ngfw_port']) + '/api/'

	def test_url(self, url):
		if url is None:
			raise Exception('[PanOSXMLAPI -> test_url()] URL parameter cannot be None!')
		else:
			request = self.xmlapi_request(
				'<test><url>' + requests.utils.requote_uri(str(url.strip())) + '</url></test>')
			result = xmltodict.parse(request.content)
			results = result['response']['result'].split('\n')
			return results

	def test_url_cloud(self, url):
		if url is None:
			raise Exception('[PanOSXMLAPI -> test_url_cloud()] URL parameter cannot be None!')
		else:
			request = self.xmlapi_request(
				'<test><url-info-cloud>' + requests.utils.requote_uri(str(url.strip())) + '</url-info-cloud></test>')
			result = xmltodict.parse(request.content)
			results = result['response']['result'].split('\n')
			results.pop(0)
			return results

	def xmlapi_request(self, command, validate=True):

		request_parameters = {
			'type': 'op',
			'key': self.params.get('ngfw_api_key'),
			'cmd': command
		}

		if self.params.get('verbose', False) is True:
			print('--------------------------------------------------------------------------------')
			print('Attempting to execute API query against: ' + str(
				self.params.get('ngfw_base_url')) + ' using parameters:')
			print(request_parameters)
			print('--------------------------------------------------------------------------------')

		request = requests.get(self.params.get('ngfw_base_url'), params=request_parameters,
		                       verify=self.params.get('ngfw_tls_verify', True))

		if self.params.get('verbose', False) is True:
			print('Got response from API: ')
			print(str(request.text))
			print('--------------------------------------------------------------------------------')

		if validate is False:
			return request
		else:
			# Load XML response into Python dict's
			result = xmltodict.parse(request.content)

			# Get API response status
			status = result['response']['@status']

			if "success" in status:
				return request
			else:
				code = result['response']['@code']
				message = result['response']['result']['msg']
				raise Exception('API call encountered an error, received ' + str(
					code).strip() + ' as status code with error message: ' + str(message))


def main(args):
	hostname = args.firewall
	port = args.port
	api_key = args.api_key
	file_input = args.input
	file_output = args.output
	tls_verify = args.no_verify
	timeout = args.timeout
	verbose = args.verbose

	firewall = PanOSXMLAPI(hostname, port, api_key, tls_verify, timeout, verbose)

	response_output = open(file_output, 'a')
	with open(file_input, 'r') as urls:
		for url in urls:
			test_url = firewall.test_url(url)
			print('--------------------------------------------------------------------------------')
			print('Querying: ' + str(url).strip())
			print('--------------------------------------------------------------------------------')
			data = test_url[0] + ' | ' + test_url[1]
			print(data)
			response_output.write('--------------------------------------------------------------------------------\n')
			response_output.write(str(data) + '\n')

			test_cloud = firewall.test_url_cloud(url)
			for entry in test_cloud:
				print(entry)
				response_output.write(str(entry) + '\n')

	print('--------------------------------------------------------------------------------')
	print('Finished!')
	print('--------------------------------------------------------------------------------')
	sys.exit(1)


if __name__ in ['__main__', 'builtin', 'builtins']:
	parser = argparse.ArgumentParser(
		description='This script will query the target firewall for URL information, same output as "test url <url>"')
	parser.add_argument('-f', '--firewall', type=str, help='FQDN of the target firewall for querying', required=True)
	parser.add_argument('-p', '--port', type=int, default=443,
	                    help='TCP port used by the management interface (default: 443)')
	parser.add_argument('-k', '--api_key', type=str, help='The firewall API key', required=True)
	parser.add_argument('-i', '--input', type=str,
	                    help='Input file with list of URLs, must be text with 1 URL per line', required=True)
	parser.add_argument('-o', '--output', type=str, help='Output file where the URL data will be stored', required=True)
	parser.add_argument('-n', '--no_verify', help='Disable TLS Verification', action="store_false")
	parser.add_argument('-t', '--timeout', type=int, default=30,
	                    help='Timeout (in seconds) value for the firewall API (default: 30)', required=True)
	parser.add_argument('-V', '--verbose', help='Enable verbose outputs', action="store_true")
	args = parser.parse_args()
	main(args)
