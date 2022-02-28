# -*- coding: utf-8 -*-
import hashlib, hmac, json, os, sys, time
from datetime import datetime

# 密钥参数
secret_id = "9098061829929******"
secret_key = "8ad56548-29b8-42b9-87e7-c361******"

#URL
host = "openapiserver.kwairtc.com"
url = "https://" + host

#公共参数：X-KC-Action
action = "stopMCUMixTranscode"

#公共参数：X-KC-Version
version = "1"

#公共参数：X-KC-Tms
#timestamp = int(time.time())
timestamp = 1551113065

algorithm = "KC1-HMAC-SHA256"

date = datetime.utcfromtimestamp(timestamp).strftime("%Y-%m-%d")
params = {"TaskId":"123456", "RoomId":"423424", "SdkAppId":"3004193698"}

# ************* 步骤 1：拼接规范请求串 *************
http_request_method = "POST"
canonical_uri = "/"
canonical_querystring = ""
ct = "application/json; charset=utf-8"
payload = json.dumps(params)
print(payload)
canonical_headers = "content-type:%s\nhost:%s\n" % (ct, host)
signed_headers = "content-type;host"
hashed_request_payload = hashlib.sha256(payload.encode("utf-8")).hexdigest()
canonical_request = (http_request_method + "\n" +
                     canonical_uri + "\n" +
                     canonical_querystring + "\n" +
                     canonical_headers + "\n" +
                     signed_headers + "\n" +
                     hashed_request_payload)
print(canonical_request)

# ************* 步骤 2：拼接待签名字符串 *************
credential_scope = date + "/rtc"
hashed_canonical_request = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
string_to_sign = (algorithm + "\n" +
                  str(timestamp) + "\n" +
                  credential_scope + "\n" +
                  hashed_canonical_request)
print(string_to_sign)


# ************* 步骤 3：计算签名 *************
# 计算签名摘要函数
def sign(key, msg):
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

secret_date = sign(("KC1" + secret_key).encode("utf-8"), date)
secret_service = sign(secret_date, "rtc")
signature = hmac.new(secret_service, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
print(signature)

# ************* 步骤 4：拼接 Authorization *************
authorization = (algorithm + " " +
                 "Credential=" + secret_id + "/" + credential_scope + ", " +
                 "SignedHeaders=" + signed_headers + ", " +
                 "Signature=" + signature)
print(authorization)

print('curl -X POST ' + url
      + ' -H "Authorization: ' + authorization + '"'
      + ' -H "Content-Type: application/json; charset=utf-8"'
      + ' -H "Host: ' + host + '"'
      + ' -H "X-KC-Action: ' + action + '"'
      + ' -H "X-KC-Tms: ' + str(timestamp) + '"'
      + ' -H "X-TC-Version: ' + version + '"'
      + " -d '" + payload + "'")
      