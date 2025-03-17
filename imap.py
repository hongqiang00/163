# 导入必要的库
import os,re
import imaplib
import ssl
import email
from email.header import decode_header
from email.utils import parseaddr
import time
from datetime import datetime

client = None

# 创建一个默认的SSL上下文对象，用于服务器认证
# 参数设置为None，表示使用默认值，后续将通过代码明确指定SSL/TLS版本范围
ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=None, capath=None, cadata=None)

# 指定SSL/TLS的最小版本为TLS 1.2，以确保连接使用的协议不低于此版本
# 这是为了提高安全性，因为较老的版本可能有已知的漏洞
ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2

# 指定SSL/TLS的最大版本为TLS 1.3，以确保连接不会使用超出此版本的协议
# TLS 1.3是最新的TLS版本，提供了更强的安全性和加密方法
ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3

# 解码 UTF-7 编码的文件夹名称
def decode_utf7_folder_name(encoded_name):
    try:
        # 将 IMAP UTF-7 转换为标准 UTF-8
        encoded_name = encoded_name.replace('&', '+').replace(',', '/')
        return encoded_name.encode('utf-8').decode('utf-7')
    except Exception as e:
        print(f"解码失败: {e}")
        return encoded_name  # 如果解码失败，返回原始值

def login163(user=None, pwd=None, host="imap.163.com" ):
    # 使用环境变量作为默认值，如果用户没有提供邮箱用户名和密码
    # 使用配置文件或环境变量代替硬编码的值
    if not user:
        user = os.getenv('EMAIL_USER', 'ustsszedu@163.com')
    if not pwd:
        pwd = os.getenv('EMAIL_PWD', 'KOXFORXDBFXYKSEK')

    # 尝试建立SSL加密的IMAP连接并登录
    # 异常处理增强
    try:
        imap_client = imaplib.IMAP4_SSL(host, ssl_context=ssl_context)  # 确保使用TLS 1.2
        imap_client.login(user, pwd)
    except imaplib.IMAP4.error as e:
        print(f"登录失败: {e}")
        return None

    # 获取邮箱文件夹列表
    status, folders = imap_client.list()
    if status == "OK":
        print("邮箱文件夹列表：")
        for folder in folders:
            # 解码文件夹信息
            folder_info = folder.decode('utf-8')
            # 提取文件夹名称
            match = re.search(r'"([^"]+)"$', folder_info)
            if match:
                folder_name_encoded = match.group(1)
                folder_name_decoded = decode_utf7_folder_name(folder_name_encoded)
                print(folder_name_decoded)
    else:
        print("无法获取邮箱文件夹列表。")
    return imap_client

    # # 关闭连接，退出
    # imap_client.close()
    # imap_client.logout()
def imap_client_close(imap_client):
    imap_client.close()
    imap_client.logout()

def decode_email_header(header):
    """
    解码电子邮件头信息。

    电子邮件头信息可能包含多种编码，这个函数旨在解析头信息并返回解码后的字符串。
    如果头信息是ASCII码，则直接返回；如果是非ASCII码，会根据编码类型进行解码。

    参数:
    header (str): 需要解码的电子邮件头信息。

    返回:
    str: 解码后的字符串。如果解码过程中包含多种编码，会返回一个元组，包含解码后的字符串和对应的编码类型。
    """
    # 解码头信息，返回一个包含解码结果和编码类型的元组
    # 列表
    decoded_header = decode_header(header)[0]
    # print(decoded_header)
    # 判断解码结果是否为元组，如果是，说明存在多种编码，需要进一步解码
    if isinstance(decoded_header, tuple):
        # 对元组中的字符串进行解码，并返回解码后的结果
        part, charset = decoded_header
        if isinstance(part, bytes):  # 检查是否为字节串
            if charset:  # 如果有字符集，按指定字符集解码
                decoded_part = part.decode(charset)
            else:  # 没有指定字符集时尝试UTF-8解码，或选择其他策略
                decoded_part = part.decode('utf-8', errors='replace')
        else:  # 如果已经是字符串，直接使用
            decoded_part = part
        return decoded_part
    else:
        # 如果解码结果不是元组，直接返回解码后的字符串
        return None

def extract_text_body(email_message):
    """
    从电子邮件消息中提取纯文本正文。
    
    参数:
    email_message: 一个电子邮件消息对象，可以是使用Python email库构建的或从文件中读取的。
    
    返回:
    一个字符串，包含电子邮件的纯文本正文。如果没有找到纯文本正文或邮件为空，则返回空字符串。
    """
    # 初始化一个字符串，用于存储提取的文本正文
    all_text_body = ""
    
    # 遍历电子邮件的每一个部分
    for part in email_message.walk():
        # 获取当前部分的Content-Type
        ctype = part.get_content_type()
        # 获取当前部分的Content-Disposition
        cdispo = str(part.get('Content-Disposition'))
        
        # 检查当前部分是否为纯文本且不是附件
        if ctype == 'text/plain' and 'attachment' not in cdispo:
            # 获取当前部分的payload（实际内容），并解码
            body = part.get_payload(decode=True)
            # 获取当前部分的内容字符集
            charset = part.get_content_charset()
            # 将解码后的文本添加到存储所有文本正文的字符串中
            all_text_body += body.decode(charset, errors='replace')
            # 找到纯文本正文后立即终止循环，以提高效率
            break  # 如果找到文本部分，即停止搜索，提高效率
    
    # 返回收集到的所有文本正文
    return all_text_body
    
def main():
    retry_limit = 5
    retry_wait = 3  # 秒
    client=None
    while True:
        try:
            if client is None:
                client = login163("qu_personal@163.com","VQpvEwCFdmqBa2tK")
            # 对两个邮箱进行操作
            time.sleep(10)
        except Exception as e:
             if retry_limit > 0:
                print(f"邮件读取失败,错误：{e}--尝试重新登陆imap")
                # imap_client_close(client)
                client=login163("qu_personal@163.com","VQpvEwCFdmqBa2tK")
                retry_limit -= 1
                time.sleep(retry_wait)  # 等待一段时间后重试
             else:
                print("重试次数耗尽，退出程序")
                # imap_client_close(client)
                break


if __name__ == "__main__":
    main()