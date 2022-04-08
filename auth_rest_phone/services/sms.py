# -*- coding: utf-8 -*-

from auth_rest_phone.conf import settings
"""
	ghasedak.py
	~~~~~~~~~
	:copyright: (c) 2019 by Ghasedak ICT
	:license: MIT, see LICENSE for more details.
"""
import requests
import json


class Ghasedak:
    """docstring for Ghasedak."""

    def __init__(self, apikey):
        self.apikey = apikey

    # send request to api
    def request_api(self, opts):
        headers = {
            'Accept': "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            'charset': "utf-8",
            'apikey': self.apikey
        }

        url = 'https://api.ghasedak.io/v2/' + opts['path']

        data = opts['data']

        r = requests.post(url, data=data, headers=headers)

        return r

    def send(self, opts):
        data = {}
        data['path'] = "sms/send/simple"
        data['data'] = {
            'message': opts['message'],
            'receptor': opts['receptor'],
            'linenumber': opts['linenumber'] if 'linenumber' in opts.keys() else "",
            'senddate': opts['senddate'] if 'senddate' in opts.keys() else "",
            'checkid': opts['checkid'] if 'checkid' in opts.keys() else ""
        }

        r = self.request_api(data)
        if r.status_code == 200:
            return True

        return False

    def bulk1(self, opts):
        data = {}
        data['path'] = "sms/send/bulk"
        data['data'] = {
            'message': opts['message'],
            'receptor': opts['receptor'],
            'linenumber': opts['linenumber'] if 'linenumber' in opts.keys() else "",
            'senddate': opts['senddate'] if 'senddate' in opts.keys() else "",
            'checkid': opts['checkid'] if 'checkid' in opts.keys() else ""
        }

        r = self.request_api(data)
        if r.status_code == 200:
            return True

        return False

    def bulk2(self, opts):
        data = {}
        data['path'] = "sms/send/pair"
        data['data'] = {
            'message': opts['message'],
            'receptor': opts['receptor'],
            'linenumber': opts['linenumber'] if 'linenumber' in opts.keys() else "",
            'senddate': opts['senddate'] if 'senddate' in opts.keys() else "",
            'checkid': opts['checkid'] if 'checkid' in opts.keys() else ""
        }

        r = self.request_api(data)
        if r.status_code == 200:
            return True

        return False

    def pair(self, opts):
        data = {}
        data['path'] = "sms/send/pair"
        data['data'] = {
            'message': opts['message'],
            'receptor': opts['receptor'],
            'linenumber': opts['linenumber'] if 'linenumber' in opts.keys() else "",
            'senddate': opts['senddate'] if 'senddate' in opts.keys() else "",
            'checkid': opts['checkid'] if 'checkid' in opts.keys() else ""
        }

        r = self.request_api(data)
        if r.status_code == 200:
            return True

        return False

    def voicecall(self, opts):
        data = {}
        data['path'] = "voice/send"
        data['data'] = {
            'message': opts['message'],
            'receptor': opts['receptor'],
            'senddate': opts['senddate'] if 'senddate' in opts.keys() else ""
        }

        r = self.request_api(data)
        if r.status_code == 200:
            return True

        return False

    def template(self, opts):
        data = {}
        data['path'] = "sms/verify"
        data['data'] = {
            'receptor': opts['receptor'],
            'type': opts['type'] if 'type' in opts.keys() else "",
            'template': opts['template'],
            'param1': opts['param1'],
            'param2': opts['param2'] if 'param2' in opts.keys() else "",
            'param3': opts['param3'] if 'param3' in opts.keys() else ""
        }

        r = self.request_api(data)
        if r.status_code == 200:
            return True

        return False

    def verification(self, opts):
        data = {}
        data['path'] = "sms/send/verification"
        data['data'] = {
            'receptor': opts['receptor'],
            'type': opts['type'] if 'type' in opts.keys() else "",
            'template': opts['template'],
            'ip': opts['ip'] if 'ip' in opts.keys() else "",
            'param1': opts['param1'],
            'param2': opts['param2'] if 'param2' in opts.keys() else "",
            'param3': opts['param3'] if 'param3' in opts.keys() else ""
        }

        r = self.request_api(data)
        if r.status_code == 200:
            return True

        return False

    def check_verification(self, opts):
        data = {}
        data['path'] = "sms/check/verification"
        data['data'] = {
            'receptor': opts['receptor'],
            'token': opts['token'],
            'ip': opts['ip'] if 'ip' in opts.keys() else ""
        }

        r = self.request_api(data)
        if r.status_code == 200:
            return True

        return False


sms = ""
linenumber = ""
if settings.GHASEDAK_APIKEY:
    sms = Ghasedak(settings.GHASEDAK_APIKEY)
else:
    raise Exception("set ghasedak api key in setting file.")
if settings.LINE_NUMBER:
    linenumber = settings.LINE_NUMBER
else:
    raise Exception("set ghasedak line number in setting file.")
