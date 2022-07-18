使用方法:


按照加密类型，和key，pass。初始化类。然后输入字节流形式的请求/响应体。调用相应的加/解密函数即可。


如下例子:


```python
decrypter = PHP_XOR_BASE64(pass_='pass', key='3c6e0b8a9c15224a')
    data = decrypter.decrypt_req_payload(b'pass=DlMRWA1cL1gOVDc2MjRhRwZFEQ==')
    print(data)
    data = decrypter.decrypt_res_payload(b'72a9c691ccdaab98fL1tMGI4YTljO/79NDQm7r9PZzBiOA==b4c4e1f6ddd2a488')
    print(data)
```

