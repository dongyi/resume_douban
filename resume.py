#!/usr/bin/env python
#
# Copyright 2009 Facebook
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
import session
import os

from tornado.options import define, options

define('douban_api_key', default='083d72c75bee281018b8585613ca7830')
define('douban_api_secret', default='3aa03c5f7a1cc965')

PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))

settings = dict(
            cookie_secret="43oETzKXQAGaYdkL5gEmGeJJFuYh7EQnp2XdTP1o/Vo=",
            debug=True,
            session_secret='some secret password!!',
            session_dir='sessions',
            template_path=os.path.join(PROJECT_ROOT, "templates"),
            static_path=os.path.join(PROJECT_ROOT, "static"),
            xsrf_cookies=False,
        )

define("port", default=8888, help="run on the given port", type=int)

from douban_auth import LoginCheckHandler, LogoutHandler, LoginHandler

class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.render('/index.html')

    def post(self):
        return self.finish('ok')

class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
        (r"/", MainHandler),
        (r"/dblogin", DBLoginHandler),
        (r"/dblogout", DBLogoutHandler),
        (r'/dblogincheck', DBLoginCheckHandler),
    ]
    tornado.web.Application.__init__(self, handlers, **settings)
    self.session_manager = session.TornadoSessionManager(settings["session_secret"], settings["session_dir"])


def main(port):
    tornado.options.parse_command_line()
    print "start on port %s..."%port

    app = Application()
    app.listen(port)
    #if port == 9999 or tornado.options.options.debug:
    if True:
        application = tornado.ioloop.IOLoop.instance()
        tornado.autoreload.start(application)
        application.start()
    else:
        tornado.ioloop.IOLoop.instance().start()


if __name__ == "__main__":
    main()
