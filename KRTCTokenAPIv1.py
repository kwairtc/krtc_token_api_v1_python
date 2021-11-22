#! /usr/bin/python
# coding:utf-8


import hmac
import hashlib
import base64
import zlib
import json
import time


def base64_encode_url(data):
    """ base url encode 实现"""
    base64_data = base64.b64encode(data)
    base64_data_str = bytes.decode(base64_data)
    base64_data_str = base64_data_str.replace('+', '*')
    base64_data_str = base64_data_str.replace('/', '-')
    base64_data_str = base64_data_str.replace('=', '_')
    return base64_data_str


def base64_decode_url(base64_data):
    """ base url decode 实现"""
    base64_data_str = bytes.decode(base64_data)
    base64_data_str = base64_data_str.replace('*', '+')
    base64_data_str = base64_data_str.replace('-', '/')
    base64_data_str = base64_data_str.replace('_', '=')
    raw_data = base64.b64decode(base64_data_str)
    return raw_data

class KRTCTokenAPIv1:
    __sdkappid = 0
    __version = '1.0'
    __key = ""

    def __init__(self, sdkappid, key):
        self.__sdkappid = sdkappid
        self.__key = key

    def __hmacsha256(self, identifier, curr_time, expire, base64_userbuf=None):
        """ 通过固定串进行 hmac 然后 base64 得的 token 字段的值"""
        raw_content_to_be_signed = "TLS.identifier:" + str(identifier) + "\n"\
                                   + "TLS.sdkappid:" + str(self.__sdkappid) + "\n"\
                                   + "TLS.time:" + str(curr_time) + "\n"\
                                   + "TLS.expire:" + str(expire) + "\n"
        if None != base64_userbuf:
            raw_content_to_be_signed += "TLS.userbuf:" + base64_userbuf + "\n"
        return base64.b64encode(hmac.new(self.__key.encode('utf-8'),
                                         raw_content_to_be_signed.encode('utf-8'),
                                         hashlib.sha256).digest())

    def __gen_token(self, identifier, expire=180*86400, userbuf=None):
        """ 用户可以采用默认的有效期生成 token """
        curr_time = int(time.time())
        m = dict()
        m["TLS.ver"] = self.__version
        m["TLS.identifier"] = str(identifier)
        m["TLS.sdkappid"] = int(self.__sdkappid)
        m["TLS.expire"] = int(expire)
        m["TLS.time"] = int(curr_time)
        base64_userbuf = None
        if None != userbuf:
            base64_userbuf = bytes.decode(base64.b64encode(userbuf))
            m["TLS.userbuf"] = base64_userbuf

        m["TLS.token"] = bytes.decode(self.__hmacsha256(
            identifier, curr_time, expire, base64_userbuf))

        raw_token = json.dumps(m)
        token_cmpressed = zlib.compress(raw_token.encode('utf-8'))
        base64_token = base64_encode_url(token_cmpressed)
        return base64_token

    ##
    #【功能说明】用于签发 KRTC 服务中必须要使用的 Token 鉴权票据
    #
    #【参数说明】
    # userid - 用户id，限制长度为32字节，只允许包含大小写英文字母（a-zA-Z）、数字（0-9）及下划线和连词符。
    # expire - Token 票据的过期时间，单位是秒，比如 86400 代表生成的 Token 票据在一天后就无法再使用了。
    #/
    def genUserToken(self, userid, expire=180*86400):
        """ 用户可以采用默认的有效期生成 token """
        return self.__gen_token(userid, expire, None)

def main():
    api = KRTCTokenAPIv1(9726578939, 'a173af0fa8c1008bc269e0064f32c2e408292279')
    token = api.genUserToken("12345678")
    print(token)

if __name__ == "__main__":
    main()
