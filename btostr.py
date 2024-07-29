import base64
#encode with base64
def b_str(bytes_data):
    bast64_data = base64.b64encode(bytes_data)
    #字符串化，使用utf-8的方式解析二进制
    bast64_str = str(bast64_data,'utf-8')
    return bast64_str

def str_b(bast64_str):
    bast64_data = bast64_str.encode(encoding='utf-8')
    #b64解码,获得原二进制序列
    bytes_data = base64.b64decode(bast64_data)
    return bytes_data

