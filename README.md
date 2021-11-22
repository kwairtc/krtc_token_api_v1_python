## 说明
此项目为 krtc_token_api_v1 版本的 python 实现。

### 源码
直接将文件 `KRTCTokenAPIv1.py` 下载到本地即可。

## 使用

``` python
import KRTCTokenAPIv1

api = KRTCTokenAPIv1.KRTCTokenAPIv1(9110123132, 'a173af0fa8c1008bc269e0064f32c2e408292279')
token = api.gen_token("321123")
print(token)
```
