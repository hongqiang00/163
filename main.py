from window_login import login_window
from window_setting import EmailFolderApp
from ai import QwenAPIHandler
from excelsave import save_to_excel,save_to_database
import time

def main():
    client=login_window()
    # 初始化应用程序
    app = EmailFolderApp(client.fetch_floders())

    handler = QwenAPIHandler()

    # 运行主循环
    while(True):
        emails=[]   #邮件列表
        users=[]    #用户列表
        for folder in app.config["selected_folders"]:
            emails+=client.read_emailfolder(folder)

        for email in emails:
            users+=handler.call_api(email.mail_content['plain_text'])

        save_to_database(users)
        time.sleep(int(app.config["refresh_interval"]))

if __name__=="__main__":
    main()
