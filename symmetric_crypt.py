""" 
演示对称加密
"""
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# 要加密的内容
data = b'this is my password'
print(f'原始数据为: \n{data}')
# 随机生成一个加密密钥, 这个key用来进行对称的加密和解密
key = get_random_bytes(16)
print(f'对称加密的密钥是: \n{key}')

############## 用加密套件加密, 加密的密钥是key ######################
cipher = AES.new(key, AES.MODE_CBC)
encrypted_data = cipher.encrypt(pad(data, AES.block_size))
print(f'加密后的内容是: \n{encrypted_data}, len = {len(encrypted_data)}')

############## 对称加密使用同样的key进行解密 #########################
decrypt_cipher = AES.new(key, AES.MODE_CBC, cipher.iv)
decrypted_data = unpad(decrypt_cipher.decrypt(encrypted_data), AES.block_size)

print(f'解密后的内容是: \n{decrypted_data}') # 恢复出原来data的数据