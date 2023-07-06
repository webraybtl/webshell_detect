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

## 免责声明:

本篇文章仅用于技术交流学习和研究的目的，严禁使用文章中的技术用于非法目的和破坏，否则造成一切后果与发表本文章的作者无关。

### 中文版本:

本免责声明旨在明确指出，本文仅为技术交流、学习和研究之用，不得将文章中的技术用于任何非法目的或破坏行为。发表本文章的作者对于任何非法使用技术或对他人或系统造成的损害概不负责。

阅读和参考本文章时，您必须明确并承诺，不会利用文章中提供的技术来实施非法活动、侵犯他人的权益或对系统进行攻击。任何使用本文中的技术所导致的任何意外、损失或损害，包括但不限于数据损失、财产损失、法律责任等问题，都与发表本文章的作者无关。

本文提供的技术信息仅供学习和参考之用，不构成任何形式的担保或保证。发表本文章的作者不对技术的准确性、有效性或适用性做任何声明或保证。

### 英文版本:

This disclaimer is intended to clearly state that this article is solely for the purpose of technical exchange, learning, and research, and the use of the techniques mentioned in the article for any illegal purposes or destructive actions is strictly prohibited. The author of this article shall not be held responsible for any consequences resulting from the misuse of the techniques mentioned.

By reading and referring to this article, you must acknowledge and commit that you will not exploit the techniques provided in the article for any illegal activities, infringement of rights of others, or attacks on systems. The author of this article bears no responsibility for any accidents, losses, or damages caused by the use of the techniques mentioned in this article, including but not limited to data loss, property damage, legal liabilities, etc.

The technical information provided in this article is for learning and reference purposes only and does not constitute any form of warranty or guarantee. The author of this article makes no representations or warranties regarding the accuracy, effectiveness, or applicability of the techniques mentioned.
