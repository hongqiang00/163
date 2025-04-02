# 导入必要的库
import os,re
import imaplib
import ssl
import email
from email.header import decode_header
from email.utils import parseaddr
import time
from datetime import datetime
from email.message import Message

class ImailReceiver:
    def __init__(self, subject: str, sender: str, mail_address, body:dict):
        """
        初始化邮件对象。
        
        :param subject: 邮件主题（字符串类型）
        :param sender: 发件人邮箱地址（字符串类型）
        :param receiver: 收件人邮箱地址（字符串类型）
        :param body["attachments"] body["plain_text"] body["html"]: 邮件正文：附件，纯文本，html
        """
        self.mail_subject = subject
        self.mail_from = sender
        self.sender_email = mail_address
        self.mail_content = body  # 邮件正文

class Person:
    def __init__(self,name:str,phone:str,intention,wechat=None,others:str=None,area:str=None):
        self.name=name
        self.phone=phone
        self.area=area
        self.others=others
        self.intention=intention
        self.wechat=wechat


class IMAIL_163:
    def __init__(self, email_account: str, email_password: str=os.getenv("IMAP_PWD_163")):
        self.email_account=email_account
        self.email_password=email_password
        self.client=self._login()
        self.email_flodernamelist=self.fetch_floders()
        self.selected_floders=['edu66']
        
    def _login(self,host="imap.163.com" ):
        # 尝试建立SSL加密的IMAP连接并登录
        # 异常处理增强
        try:
            imap_client = imaplib.IMAP4_SSL(host, 993)  # 确保使用TLS 1.2
            response, data =imap_client.login(self.email_account, self.email_password)
            if response == "OK":
                print(f"登录成功")
                return imap_client  # 返回 IMAP 客户端对象
            else:
                print(f"登录失败：{data}")
                return None
        except imaplib.IMAP4.error as e:
            # 捕获登录失败的异常
            print(f"登录失败: {e}")
            return None
        
    def fetch_floders(self):
        try:
            # 发送ID命令给服务器，提供客户端信息
            imaplib.Commands["ID"] = ('AUTH',)
            args = ("name", self.email_account, "contact", self.email_account, "version", "1.0.0", "vendor", "myclient")
            self.client._simple_command("ID", str(args).replace(",", "").replace("'", "\""))
            # 获取邮箱文件夹列表
            status, folders = self.client.list()
            folder_list=[]
            if status == "OK":
                for folder in folders:
                    # 解码文件夹信息
                    folder_info = folder.decode('utf-8')
                    # 提取文件夹名称
                    match = re.search(r'"([^"]+)"$', folder_info)
                    if match:
                        folder_name_encoded = match.group(1)
                        folder_name_decoded = decode_utf7_folder_name(folder_name_encoded)
                        folder_list.append(folder_name_decoded)
            else:
                print("无法获取邮箱文件夹列表。")
            return folder_list
        except Exception as e:
            print("获取文件夹错误")
            return None

    def email_folders_info(self):
        print("邮箱文件夹如下：")
        for folder in self.email_flodernamelist:
            print(folder,end=" ",flush=True)
        print()

    def imap_client_close(self):
        """安全地关闭 IMAP 连接"""
        try:
            if self.client:  # 确保 IMAP 客户端存在
                if self.client.state == "SELECTED":  # 如果当前状态是 SELECTED
                    self.client.close()  # 调用 CLOSE 命令
                self.client.logout()  # 调用 LOGOUT 命令
                print("IMAP 连接已安全关闭。")
        except Exception as e:
            print(f"关闭 IMAP 连接时发生错误: {e}")

    def read_emailfolder(self, mailbox_folder):
        encode_mailbox_folder=encode_utf7_folder_name(mailbox_folder)
        email_info_list=[]
        try:
            # 选择邮箱文件夹
            typ, data = self.client.select(encode_mailbox_folder)
            if typ != "OK":
                print(f"选择邮箱失败: {data}")
                return

            print(f"已选中邮箱: {mailbox_folder}")

            # 搜索未读邮件
            typ, data = self.client.search(None, "UNSEEN")
            if typ != "OK":
                print(f"搜索未读邮件失败: {data}")
                return

            # 打印搜索结果
            print(f"搜索结果类型: {typ}, 数据: {data}")
            unseen_emails = data[0].decode('utf-8').split() if data[0] else []
            print(f"未读邮件数量: {len(unseen_emails)}")

            for unseen_email in unseen_emails:
                _, data = self.client.fetch(unseen_email, '(RFC822)')
                raw_email = data[0][1]
                email_message = email.message_from_bytes(raw_email)
                subject = decode_email_header(email_message['Subject'])
                from_info = decode_header(email_message['From'])
                sender_name,sender_email=decode_email_senderinfo(from_info)
                email_body=extract_all_parts(email_message)
                email_info_list.append(ImailReceiver(subject,sender_name,sender_email,email_body))

        except Exception as e:
            print(f"读取邮箱时发生错误: {e}")
        
        return email_info_list

# 解码 UTF-7 编码的文件夹名称
def decode_utf7_folder_name(encoded_name):
    try:
        # 将 IMAP UTF-7 转换为标准 UTF-8
        encoded_name = encoded_name.replace('&', '+').replace(',', '/')
        return encoded_name.encode('utf-8').decode('utf-7')
    except Exception as e:
        print(f"解码失败: {e}")
        return encoded_name  # 如果解码失败，返回原始值

# 编码函数：从 UTF-8 转换为 Modified UTF-7
def encode_utf7_folder_name(folder_name):
    try:
        # 检查字符串是否仅包含 ASCII 字符
        if all(ord(c) < 128 for c in folder_name):
            return folder_name  # 如果是纯 ASCII，直接返回

        # 将字符串转换为 UTF-16BE 编码
        utf16_bytes = folder_name.encode("utf-16be")
        
        # Base64 编码并去掉尾部的 '='
        import base64
        b64_encoded = base64.b64encode(utf16_bytes).decode("ascii").rstrip("=")
        
        # 构造 Modified UTF-7 格式
        return f"&{b64_encoded}-"
    except Exception as e:
        print(f"编码失败: {e}")
        return folder_name  # 如果编码失败，返回原始值
    
def decode_email_senderinfo(sender_info):
    name_parts = []
    for part, charset in sender_info:
        if isinstance(part, bytes):
            if charset:
                decoded_part = part.decode(charset)
            else:
                decoded_part = part.decode('utf-8', errors='replace')
        else:
            decoded_part = part
        name_parts.append(decoded_part)

    full_name = ''.join(name_parts).strip() 
    from_person,email_address=parseaddr(full_name)
    return from_person,email_address

def decode_email_header(header):
    """
    解码电子邮件主题的头信息。
    str: 解码后的字符串。如果解码过程中包含多种编码，会返回一个元组，包含解码后的字符串和对应的编码类型。
    """
    # 列表
    decoded_header = decode_header(header)[0]

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
        print("电子邮件头解码错误")
        return None


def extract_all_parts(email_message: Message):
    """
    从电子邮件消息中提取所有部分，包括纯文本、HTML、附件等。
    
    参数:
    email_message: 一个电子邮件消息对象，可以是使用Python email库构建的或从文件中读取的。
    
    返回:
    一个字典，包含以下键值对：
    - "plain_text": 纯文本正文。
    - "html": HTML 格式的正文。
    - "attachments": 附件列表，每个附件是一个字典，包含文件名和内容。
    """
    result = {
        "plain_text": "",
        "html": "",
        "attachments": []
    }
    
    # 遍历邮件的每个部分
    for part in email_message.walk():
        # 获取当前部分的Content-Type
        content_type = part.get_content_type()
        # 获取当前部分的Content-Disposition
        content_disposition = str(part.get("Content-Disposition", "")).lower()
        
        # 获取当前部分的payload（实际内容），并解码
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        
        # 获取字符集，默认使用 utf-8
        charset = part.get_content_charset() or "utf-8"
        
        # 处理不同类型的 MIME 部分
        if content_type == "text/plain" and "attachment" not in content_disposition:
            # 提取纯文本内容
            try:
                result["plain_text"] += payload.decode(charset, errors="replace")
            except LookupError:
                result["plain_text"] += payload.decode("utf-8", errors="replace")
        
        elif content_type == "text/html" and "attachment" not in content_disposition:
            # 提取 HTML 内容
            try:
                result["html"] += payload.decode(charset, errors="replace")
            except LookupError:
                result["html"] += payload.decode("utf-8", errors="replace")
        
        elif "attachment" in content_disposition or content_type.startswith(("image/", "application/")):
            # 提取附件
            filename = part.get_filename()
            if not filename:
                filename = "unnamed_attachment"
            
            result["attachments"].append({
                "filename": filename,
                "content": payload
            })
    
    # 去除多余空白
    result["plain_text"] = result["plain_text"].strip()
    result["html"] = result["html"].strip()
    
    return result
    
def main():
    retry_limit = 5
    retry_wait = 3  # 秒
    client=None
    while True:
        try:
            if client is None:
                client = IMAIL_163("qu_personal@163.com")
                client.email_folders_info()
            client.read_emailfolder("edu66")
            # 对两个邮箱进行操作
            time.sleep(10)
        except Exception as e:
             if retry_limit > 0:
                print(f"邮件读取失败,错误：{e}--尝试重新登陆imap")
                # imap_client_close(client)
                client=IMAIL_163("qu_personal@163.com")
                retry_limit -= 1
                time.sleep(retry_wait)  # 等待一段时间后重试
             else:
                print("重试次数耗尽，退出程序")
                # imap_client_close(client)
                break


if __name__ == "__main__":
    main()