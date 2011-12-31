#coding=utf8
import tornado.web
import tornado.httpserver
import tornado.httpclient

import os
import re
import urllib2

from weibopy.api import API
from urlparse import urljoin
from weibopy import OAuthHandler
from tornado.options import options
from common.decorator import login_required
#from config.web_config import PLATFORM


import session
from httputil import iri_to_uri

#from config.web_config import PLATFORM

absolute_http_url_re = re.compile(r"^https?://", re.I)
INTERNAL_IP_PATTERN = re.compile('127.0.0.1|192.168.*.*')

class BaseHandler(tornado.web.RequestHandler):
    @property
    def db(self):
        return self.application.db


    def __init__(self, *argc, **argkw):
        super(BaseHandler, self).__init__(*argc, **argkw)
        self.path = ''
        self.session = session.TornadoSession(self.application.session_manager, self)

        if self.session.get('platform') == 'weibo':
            self.sina_access_token = self.session.get('oauth_access_token')
            auth = OAuthHandler(options.SINA_APP_KEY, options.SINA_APP_SECRET)
            auth.set_access_token(self.sina_access_token.key, self.sina_access_token.secret)
            self.sina_api = API(auth)
        elif self.session.get('platform') == 'renren':
            self._userid = int(self.get_user_id())
            print "renren ok"
        elif self.session.get('platform') == 'douban':
            self._userid = int(self.get_user_id())
            print "douban ok"


    # platform apis, support sina, renren, douban
    def get_current_user(self):
        return self.session.get('username')

    def get_account_id(self):
        return self.session.get('me').id

    def get_user_id(self):
        if INTERNAL_IP_PATTERN.match(self.request.remote_ip):
            userid = self.get_argument('userid', None)
            if userid:
                return userid
        if not self.session.get('userid'):
            raise tornado.web.HTTPError(500, 'choose player first')
        return self.session.get('userid')

    def get_user_image(self):
        return self.session.get('me').profile_image_url

    def get_user_url(self):
        return self.session.get('me').url

    def get_host(self):
        """Returns the HTTP host using the environment or request headers."""
        return self.request.headers.get('Host')

    def build_absolute_uri(self, location=None):
        """
        Builds an absolute URI from the location and the variables available in
        this request. If no location is specified, the absolute URI is built on
        ``request.get_full_path()``.
        """
        if not location:
            location = ''
        if not absolute_http_url_re.match(location):
            current_uri = '%s://%s%s' % (self.is_secure() and 'https' or 'http',
                                         self.get_host(), self.path)
            location = urljoin(current_uri, location)
        return iri_to_uri(location)

    def is_secure(self):
        return os.environ.get("HTTPS") == "on"

    def get_error_html(self, status_code, exception=None, **kwargs):
        return self.render_string('_error.htm', status_code=status_code, exception=exception, **kwargs)


class ReqMixin(object):
    user_callback = {}

    def wait_for_request(self, callback):
        cls = ReqMixin
        cls.user_callback.update({self.get_user_id():callback})

    def new_req(self, req):
        cls = ReqMixin
        callback = cls.user_callback[self.get_user_id()]
        callback(req)

class ProxyHandler(BaseHandler, ReqMixin):
    @login_required
    @tornado.web.asynchronous
    def get(self, action):
        if action == 'update':
            self.wait_for_request(self.async_callback(self.send))

        elif action == 'request':
            http = tornado.httpclient.AsyncHTTPClient()
            http.fetch(self.get_argument('url'), callback=self.new_req)
            self.finish()


    def send(self, response):
        # Closed client connection
        if response.error:
            raise tornado.web.HTTPError(500)
        self.write(response.body)
        self.flush()

