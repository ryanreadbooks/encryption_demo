"""
模拟HTTPS中TLS的握手情况
"""
import time

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import MD5

# 客户端生成的第1随机数, 这个随机数会在TLS握手时发送给服务器，所以服务器是知道这个随机数的
client_random_num1 = get_random_bytes(16)
print(f'客户端第1随机数为  {client_random_num1}') # client hello

# 客户端的密钥对
client_key = RSA.generate(2048)

# 服务器的密钥对, 其中的公钥要让客户端知道，私钥保存在服务器端，不让任何人知道
server_key = RSA.generate(2048)

# 服务器生成的第2随机数，这个随机数会在TLS握手时发送个客户端，所以客户端是知道这个随机数的
server_random_num2 = get_random_bytes(16)
print(f'服务器第2随机数为  {server_random_num2}') # server hello

# 客户端生成的第3随机数
client_random_num3 = get_random_bytes(16)
# 用服务器的公钥加密这个第3随机数
client_encrypt_cipher1 = PKCS1_OAEP.new(key=server_key.public_key())
encrypted_client_random_num3 = client_encrypt_cipher1.encrypt(client_random_num3)

# 服务器用自己的私钥解密获得客户端生成的第3随机数
server_decrypt_cipher1 = PKCS1_OAEP.new(key=server_key)
server_decrypted_random_num3 = server_decrypt_cipher1.decrypt(encrypted_client_random_num3)

print(f'客户端生成的第3随机数为      {client_random_num3}, len = {len(client_random_num3)}')
print(f'服务器解密得到的第3随机数为  {server_decrypted_random_num3}, len = {(len(server_decrypted_random_num3))}')

# 将第1，第2，第3随机数相融合，得到一个会话密钥，这个密钥用来进行对称加密
# 往后的客户端和服务器通信都是用这个密钥进行加密和解密
# 由于客户端和服务器都知道第1，第2，第3随机数，所以这个会话密钥双方都知道
client_session_key = client_random_num1 + server_random_num2 + client_random_num3
server_session_key = client_random_num1 + server_random_num2 + server_decrypted_random_num3
md5_calculator_client = MD5.new()
md5_calculator_client.update(client_session_key)
client_session_key = md5_calculator_client.digest()

md5_calculator_server = MD5.new()
md5_calculator_server.update(server_session_key)
server_session_key = md5_calculator_server.digest()
# 由于双方的计算规则都是相同的，所以两者的计算结果是相等的
print(f'客户端计算得到的会话密钥为 {client_session_key} len = {len(client_session_key)}')
print(f'服务器计算得到的会话密钥为 {server_session_key} len = {len(server_session_key)}\n')

# 开始正常收发应用数据，并且都使用会话密钥进行加密和解密
client_msg_encrypt_cipher = AES.new(key=client_session_key, mode=AES.MODE_CBC, iv=client_session_key)
client_msg_decrypt_cipher = AES.new(key=client_session_key, mode=AES.MODE_CBC, iv=client_session_key)

server_msg_encrypt_cipher = AES.new(key=server_session_key, mode=AES.MODE_CBC, iv=server_session_key)
server_msg_decrypt_cipher = AES.new(key=server_session_key, mode=AES.MODE_CBC, iv=server_session_key)

# 模拟数据的收发
for i in range(3):
  print(f'===========Begin of Round-{i}===========')
  # client -> server (request)
  req_msg = bytes('request-' + str(i), encoding='utf8')
  encrypted_msg_4_server = client_msg_encrypt_cipher.encrypt(pad(req_msg, AES.block_size)) # 客户端加密后发送个服务器的数据
  print(f'客户端发起的响应为 => {req_msg}')
  
  # server -> client (response)
  # 服务器将接受到的数据解密
  print(f'服务器收到的加密数据为 => {encrypted_msg_4_server}, len = {len(encrypted_msg_4_server)}')
  decrypted_msg_from_client = unpad(server_msg_decrypt_cipher.decrypt(encrypted_msg_4_server), AES.block_size)
  print(f'服务器解密收到客户端的请求为 => {decrypted_msg_from_client}')
  response_msg = bytes('response-' + str(i), encoding='utf8')
  print(f'服务器的响应为 => {response_msg}')
  encrypted_msg_4_client = server_msg_encrypt_cipher.encrypt(pad(response_msg, AES.block_size))  # 服务器加密发送个客户端的内容

  # 客户端收到加密的内容后解密
  print(f'客户端收到的加密的响应为 => {encrypted_msg_4_client}')
  decrypted_msg_from_server = unpad(client_msg_decrypt_cipher.decrypt(encrypted_msg_4_client), AES.block_size)
  print(f'客户端收到解密后服务器的响应为 => {decrypted_msg_from_server}')
  print(f'===========End of Round-{i}===========\n')
  time.sleep(1)