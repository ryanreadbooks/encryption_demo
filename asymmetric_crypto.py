"""
演示非对称加密, 公钥加密　私钥解密
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP


# 需要加密的内容
data = b'this is my password'
print(f'原始数据为: \n{data}')

# 生成密钥对, 这里包含了公钥和私钥
key = RSA.generate(2048)
# 得到私钥
private_key = key
# 得到公钥
public_key = key.public_key()

# 初始化加密套件
encrypt_cipher = PKCS1_OAEP.new(key=public_key)
# 加密
encrypted_data = encrypt_cipher.encrypt(data)
print(f'公钥加密后的内容是: \n{encrypted_data}')

################ 使用私钥进行解密 #######################
decrypt_cipher = PKCS1_OAEP.new(key=private_key)
decrypted_data = decrypt_cipher.decrypt(encrypted_data)
print(f'私钥解密后的内容是: \n{decrypted_data}')
