import tkinter as tk
import os,configparser
from tkinter import font, messagebox
from imap import IMAIL_163 
from _base_dir import get_base_dir

BASE_DIR=get_base_dir()

class UserLoginInterface:
    def __init__(self):
        self.root = tk.Tk()
        self.config_file = os.path.join(BASE_DIR,'data','settings.ini')  # 配置文件路径
        self.config = self.load_settings()  # 加载设置
        # self.saved_account,self.saved_password = self.load_credentials()
        self.chinese_front = self.chinese_front_setting()
        self.entry_account = tk.Entry(self.root, width=30)
        self.entry_password = tk.Entry(self.root, width=30, show="*")  # 使用 * 隐藏密码输入
        self.remember_var = tk.BooleanVar(value=bool(self.config["account"] and self.config["password"]))  # 根据文件状态设置初始值
        self.view_pwd_var = tk.BooleanVar(value=False)

        self.login_result = False #记录登陆状态
        self.login_object = None

    def interface(self):
        self.root.title("欢迎来到账号登录界面")
        # 账号标签与输入框
        label_account = tk.Label(self.root, text="邮箱账号:", font=self.chinese_front)
        label_account.grid(row=0, column=0, padx=10, pady=20, sticky="e")  # 放置在第0行第0列，右对齐
        self.entry_account.grid(row=0, column=1, padx=10, pady=20)  # 放置在第0行第1列
        self.entry_account.insert(0, self.config["account"])  # 填充保存的账号

        # 密码标签与输入框
        label_password = tk.Label(self.root, text="imap密码:", font=self.chinese_front)
        label_password.grid(row=1, column=0, padx=10, pady=20, sticky="e")  # 放置在第1行第0列，右对齐
        self.entry_password.grid(row=1, column=1, padx=10, pady=20)  # 放置在第1行第1列
        self.entry_password.insert(0, self.config["password"])  # 填充保存的密码

        # 记住密码复选框
        checkbutton_remember = tk.Checkbutton(
            self.root,
            text="记住密码",
            font=self.chinese_front,
            variable=self.remember_var,
            onvalue=True,
            offvalue=False
        )
        checkbutton_remember.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="w")  # 放置在第2行，跨越两列

        # 显示密码复选框
        self.view_pwd_var.trace_add("write", self.toggle_password_visibility) #只要复选框变化都会调用回调函数
        checkbutton_remember = tk.Checkbutton(
            self.root,
            text="显示密码",
            font=self.chinese_front,
            variable=self.view_pwd_var,
            onvalue=True,
            offvalue=False
        )
        checkbutton_remember.grid(row=2, column=1, columnspan=2, padx=10, pady=10, sticky="w")  # 放置在第2行，跨越两列

        # 按钮：提交
        submit_button = tk.Button(self.root, text="登录", font=self.chinese_front, command=self.on_submit)
        submit_button.grid(row=3, column=0, columnspan=2, pady=20)

        # 运行主循环
        self.root.mainloop()


    def chinese_front_setting(self):
        chinese_font=None
        try:
            chinese_font = font.Font(family="WenQuanYi Zen Hei", size=14)  # 文泉驿正黑
        except:
            chinese_font = font.Font(family="SimSun", size=14)  # 宋体
        return chinese_font

    # 提交按钮的回调函数
    def on_submit(self):
        saved_account = self.entry_account.get()
        saved_password = self.entry_password.get()
        remember = self.remember_var.get()
        print(f"账号: {saved_account}")
        print(f"密码: {saved_password }")
        print(f"记住密码: {'是' if remember else '否'}")
        if remember:
            self.save_settings()  # 记住密码时保存到文件
        else:
            self.clear_accountinfo()  # 不记住密码时删除文件

        print("登录验证中...")
        try:
            # 假设 IMAIL_163 是一个外部类，用于验证登录
            self.login_object = IMAIL_163(self.config["account"], self.config["password"])
            if(self.login_object.client is None):
                # print("登录失败，重新输入密码或账号")
                messagebox.showerror("错误", "登录失败，请检查账号或密码！")
            else:
                # print("登录成功")
                self.login_result=True            
                self.root.destroy()  # 关闭窗口
        except Exception as e:
            print(f"登录失败: {e}")
            messagebox.showerror("错误", "登录失败，请重试！")

    def toggle_password_visibility(self, *args):
        """切换密码可见性"""
        if self.view_pwd_var.get():  # 如果复选框被勾选
            self.entry_password.config(show="")  # 显示密码
        else:  # 如果复选框未勾选
            self.entry_password.config(show="*")  # 隐藏密码

    def load_settings(self):
        """
        加载配置文件中的设置。
        """
        config = configparser.ConfigParser()
        config.read(self.config_file)

        # 如果配置文件不存在或无设置，则返回默认值
        return {
            "account": config.get("Account", "account", fallback=""),
            "password": config.get("Account", "password", fallback="")
        }

    def save_settings(self):
        """
        保存当前设置到配置文件。
        """
        config = configparser.ConfigParser()
        config.read(self.config_file)  # 读取现有配置
        
        config["Account"] = {
            "account": self.entry_account.get(),
            "password": self.entry_password.get()
        }

        with open(self.config_file, "w") as configfile:
            config.write(configfile)

    def clear_accountinfo(self):
        config = configparser.ConfigParser()
        config.read(self.config_file)  # 读取现有配置
        
        config["Account"] = {
            "account": "",
            "password": ""
        }
        with open(self.config_file, "w") as configfile:
            config.write(configfile)

def login_window():
    root=UserLoginInterface()
    root.interface()
    while(root.login_result==False):
        pass
    return root.login_object

if __name__=="__main__":
    client=login_window()
    print("成功登录")







    
        