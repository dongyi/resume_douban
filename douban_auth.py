#!/usr/bin/env python
#coding:utf-8
import sys
reload(sys)
sys.setdefaultencoding("utf-8")
import urllib
import hashlib
import time
import re
import httplib
import random
import base64
import hmac
import pylibmc as memcache
from tornado.options import options
from base_httphandler import BaseHandler


session_mc_client = memcache.Client(session_mc)

def _get_referer_url(request_handle):
    headers = request_handle.request.headers
    referer_url = headers.get('HTTP_REFERER', '/')
    host = headers.get('Host')
    if referer_url.startswith('http') and host not in referer_url:
        referer_url = '/' # 避免外站直接跳到登录页而发生跳转错误
        return referer_url

class LoginCheckHandler(BaseHandler):
    def get(self):
        d = douban()
        login_backurl = self.build_absolute_uri('/dblogincheck')
        print self.session.session_id
        self.request_token = self.session.get('request_token')

        access_token = d.steptwo(self.request_token['oauth_token'], self.request_token['oauth_token_secret'],)

        item = d.stepthree(token=access_token['oauth_token'], secret=access_token['oauth_token_secret'])
        self.session['username'] = item.username
        self.session['me'] = item
        self.session['oauth_access_token'] = access_token
        self.session.save()
        self.session['accountid'] = item.id
        session_mc_client.set(str(item.id), self.session.session_id)
        return self.redirect('/')

class LoginHandler(BaseHandler):
    def get(self):
        login_backurl = self.build_absolute_uri('/dblogincheck')
        d = douban()
        back_to_url, request_token = d.stepone(login_backurl)

        self.session['request_token'] = request_token
        print self.session.session_id
        self.session.save()
        self.redirect(back_to_url)

class LogoutHandler(BaseHandler):
    def get(self):
        self.session.clear()
        self.session.save()
        back_to_url = _get_referer_url(self)
        self.redirect('/')


def to_signature_key(method, url, data):
    keys = list(data.keys())
    keys.sort()
    encoded = urllib.quote("&".join([key+"="+data[key] for key in keys]))
    return "&".join([method, urllib.quote(url, safe="~"), encoded])



def request_token_params(consumer_key, consumer_secret, path, method='GET'):
    data={}
    data['oauth_consumer_key']=consumer_key
    data['oauth_signature_method']='HMAC-SHA1'
    data['oauth_timestamp']=str(int(time.time()))
    data['oauth_nonce']=''.join([str(random.randint(0,9)) for i in range(10)])
    print data

    msg = to_signature_key(method, path, data)
    print msg

    signed = base64.b64encode(hmac.new(consumer_secret+"&", msg, hashlib.sha1).digest())
    print signed
    data['oauth_signature']=signed
    return data

def result2dict(res):
    d = {}
    params = res.split('&')
    for p in params:
        d[p.split('=')[0]] = p.split('=')[1]
    return d

def access_token_params(consumer_key, consumer_secret, oauth_token, oauth_secret, path, method='GET'):
    data={}
    data['oauth_consumer_key']=consumer_key
    data['oauth_signature_method']='HMAC-SHA1'
    data['oauth_timestamp']=str(int(time.time()))
    data['oauth_nonce']=''.join([str(random.randint(0,9)) for i in range(10)])
    data['oauth_token'] = oauth_token

    msg = to_signature_key(method, path, data)
 #   print msg

    signed = base64.b64encode(hmac.new(consumer_secret+"&"+oauth_secret, msg, hashlib.sha1).digest())
  #  print signed
    data['oauth_signature']=signed
    return data

def access_params(consumer_key, consumer_secret, access_token,access_token_secret, path, method='GET'):
    data={}
    data['oauth_consumer_key'] = consumer_key
    data['oauth_token'] = access_token
    data['oauth_signature_method'] = 'HMAC-SHA1'
    data['oauth_timestamp'] = str(int(time.time()))
    data['oauth_nonce']=''.join([str(random.randint(0,9)) for i in range(10)])
    msg = to_signature_key(method, path, data)
    signed = base64.b64encode(hmac.new(consumer_secret+"&"+access_token_secret, msg, hashlib.sha1).digest())
    data['oauth_signature'] = signed
    return data


class douban:
    def __init__(self):
        self.consumer_key = options.douban_api_key
        self.consumer_secret = options.douban_api_secret

    access_token_path = "http://www.douban.com/service/auth/access_token"
    request_token = {}
    conn = httplib.HTTPConnection("www.douban.com", 80)
    def stepone(self, callback):
        # step-one
        request_token_path = "http://www.douban.com/service/auth/request_token"
        params = request_token_params(consumer_key=options.douban_api_key, consumer_secret=options.douban_api_secret, path="http://www.douban.com/service/auth/request_token")
        self.conn.request('GET', request_token_path+"?"+urllib.urlencode(params))
        res = self.conn.getresponse().read()
        self.request_token = result2dict(res)
        #return request_token
        return 'http://www.douban.com/service/auth/authorize?oauth_token=%s&oauth_callback=%s'%(self.request_token['oauth_token'], callback), self.request_token

    def steptwo(self, token, secret):
        params = access_token_params(self.consumer_key,
                             self.consumer_secret,
                             token,
                             secret,
                             self.access_token_path)
        self.conn.request('GET', self.access_token_path+"?"+urllib.urlencode(params))
        res = self.conn.getresponse().read()
        access_token = result2dict(res)
        return access_token

    def oauth_header(self,consumer_key, consumer_secret, oauth_token, oauth_secret, path, realm):
        data = access_token_params(consumer_key, consumer_secret, oauth_token, oauth_secret, path, method="GET")
        header_string = ','.join([key+'="'+data[key]+'"' for key in data.keys()])
        return 'OAuth realm="'+realm+'",'+header_string

    def stepthree(self, token, secret):
        posturl = 'http://api.douban.com/people/%40me'
        header = {}
        header['Authorization'] = self.oauth_header(self.consumer_key, self.consumer_secret,token, secret,posturl, "http://api.douban.com")
        self.conn.request('GET', posturl, None, header)
        res = self.conn.getresponse().read()
        self.conn.close()
        url = re.findall(re.compile("(?<=<link href=\").*(?=/\" rel=\"alternate\"/>)"), res)[0]
        me = txt_wrap_by('<title>','</title>', res)
        image_url = re.findall(re.compile("http://img.*.jpg"), res)[0]
        #<id>http://api.douban.com/people/1869286</id>
        id = re.findall(re.compile("(?<=<id>http://api.douban.com/people/)\d*(?=</id>)"), res)[0]
        item = douban_iterm(id, me, url, image_url)
        return item

class douban_iterm:
    def __init__(self, id, me, url, profile_image_url):
        self.id = int(id)
        self.username = me
        self.url = url
        self.profile_image_url = profile_image_url

def txt_wrap_by(start_str, end, html):
    start = html.find(start_str)
    if start >= 0:
        start += len(start_str)
        end = html.find(end, start)
        if end >= 0:
            return html[start:end].strip()



def main():
    consumer_key = "0f0b1d1ab36508da2d2157501a2f1a8e"
    consumer_secret = "1bd0072da311382e"
    access_token_path = "http://www.douban.com/service/auth/access_token"
    # step-one
    conn = httplib.HTTPConnection("www.douban.com", 80)
    request_token_path = "http://www.douban.com/service/auth/request_token"
    params = request_token_params(consumer_key="0f0b1d1ab36508da2d2157501a2f1a8e", consumer_secret="1bd0072da311382e", path="http://www.douban.com/service/auth/request_token")
    conn.request('GET', request_token_path+"?"+urllib.urlencode(params))
    res = conn.getresponse().read()
    request_token = result2dict(res)
    print 'http://www.douban.com/service/auth/authorize?oauth_token=%s'%request_token['oauth_token']

    # step-two
    params = access_token_params(consumer_key,
                             consumer_secret,
                             request_token['oauth_token'],
                             request_token['oauth_token_secret'],
                             access_token_path)
    conn.request('GET', access_token_path+"?"+urllib.urlencode(params))
    res = conn.getresponse().read()
    print res
    access_token = result2dict(res)
    print access_token
    access_path = raw_input("input url!!!")
    params_access = access_params(consumer_key, consumer_secret, access_token['oauth_token'],access_token['oauth_token_secret'], access_path, method='GET')
    conn.request('GET', access_path+"?"+urllib.urlencode(params_access))
    res_access = conn.getresponse().read()
    print res_access





if "__main__" == __name__:
    main()

