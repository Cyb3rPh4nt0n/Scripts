from burp import IBurpExtender
from burp import IcontextMenuFactory

from java.net import URL
from java.util import ArrayList
from java.swing import JmenuItem
from thread import start_new_thread

import json
import socket
import urllib
API_KEY = "YOURKEY"
API_HOST = 'api.cognitive.microsoft.com'

class BurpExtender(IBurpExtender, IcontextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self.context = None

        # we set up our extension
        callbacks.setExtensionName("BHP Bing")
        callbacks.registerContextMenuFactory(self)

        return
    
    def createMenuItems(self, context_menu):
        self.context = context_menu
        menu_list = ArrayList()
        menu_list.add(JMenuItem(
            "Send to Bing", actionPerformed=self.bing_menu))
        return menu_list
    
    def bing_menu(self, event):

        # grab the details of what the user clicked
        http_traffic = self.context.getSelecteddMessages()

        print("%d requests highlighted" % len(http_traffic))

        for traffic in http_traffic:
            http_service = traffic.getHttpService()
            host = http_service.getHost()

            print("User selected host: %s" % host)
            self.bing_search(host)

        return
    
    def bing_search(self, host):
        # check if we have an IP or hostname
        try:
            is_ip = bool(socket.inet_aton(host))
        except socket.error:
            is_ip = False

        if is_ip:
            ip_address = host
            domain = False
        else:
            ip_address = socket.gethostbyname(host)
            domain = True

        start_new_thread(self.bing_query, ('ip:%s' % ip_address,))

        if domain:
            start_new_thread(self.bing_query, ('domain_:%s' % host,))

    def bing_query(self, bing_query_string):
        print('Performing Bing search: %s' % bing_query_string)
        http_request = 'GET https://%s/bing/v7.0/search?' % API_HOST
        # encode our query
        http_request += 'q=%s HTTP/1.1\r\n' % urllib.quote(bing_query_string)
        http_request += 'Host: %s\r\n' % API_HOST
        http_request += 'Connection:close\r\n'
        http_request += 'Ocp-Apim-Subscription-Key: %s\r\n' % API_KEY
        http_request += 'User-Agent: Black Hat Python\r\n\r\n'

        json_body = self._callbacks.makeHttpRequest(
            API_HOST, 443, True, http_request).tostring()
        json_body = json_body.split('\r\n\r\n', 1)[1]

        try:
            response = json.loads(json_body)
        except (TypeError, ValueError) as err:
            print('No results from Bing: %s' % err)
        else:
            sites = list()
            if response.get('webPages'):
                sites = response['webPages']['value']
            if len(sites):
                for site in sites:
                    print('*'*100)
                    print('Name: %s' % site['name'])
                    print('URL %s' % site['url'])
                    print('Description: %r' % site['snippet'])
                    print('*'*100)

                    java_url = URL(site['url'])
                    if not self._callbacks.isInScope(java_url):
                        print('Adding %s to Burp scope' % site['url'])
                        self._callbacks.includeInScope(java_url)
                    else:
                        print('Empty response from Bing.: %s' % bing_query_string)
        return
    