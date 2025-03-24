import tkinter as tk
from tkinter import messagebox
import configparser,os
from imap import IMAIL_163
from _base_dir import BASE_DIR



class EmailFolderApp:
    def __init__(self, folder_list):
        self.root = tk.Tk()
        self.exclude_folders = ["已发送", "已删除", "垃圾邮件", "病毒文件夹", "草稿箱", "广告邮件", "订阅邮件"]  # 需要排除的文件夹
        self.folder_list = [folder for folder in folder_list if folder not in self.exclude_folders]  # 已保存的邮箱文件夹列表
        self.selected_folders = []  # 用于存储用户选择的文件夹
        self.config_file = os.path.join(BASE_DIR,'data','settings.ini')  # 配置文件路径
        self.config = self.load_settings()  # 加载设置

        # 初始化界面组件
        self.entry_refresh_mail = tk.Entry(self.root, width=20)
        self.interface()

    def load_settings(self):
        """
        加载配置文件中的设置。
        """
        config = configparser.ConfigParser()
        config.read(self.config_file)

        # 如果配置文件不存在或无设置，则返回默认值
        return {
            "selected_folders": config.get("Settings", "selected_folders", fallback="").split(","),
            "refresh_interval": config.get("Settings", "refresh_interval", fallback="60")
        }

    def save_settings(self):
        """
        保存当前设置到配置文件。
        """
        config = configparser.ConfigParser()
        config.read(self.config_file)  # 读取现有配置
        
        config["Settings"] = {
            "selected_folders": ",".join(self.selected_folders),
            "refresh_interval": self.entry_refresh_mail.get()
        }

        with open(self.config_file, "w") as configfile:
            config.write(configfile)

    def interface(self):
        self.root.title("邮箱文件读取设置")
        # 标签：提示用户选择邮箱文件夹
        label_folder = tk.Label(self.root, text="点击选择邮箱文件夹:", font=("Arial", 12))
        label_folder.grid(row=0, column=0, padx=10, pady=20, sticky="e")

        # 多选列表框：显示邮箱文件夹列表
        self.listbox_folders = tk.Listbox(
            self.root,
            selectmode=tk.MULTIPLE,  # 允许多选
            height=len(self.folder_list),  # 设置列表框的高度
            exportselection=False,  # 确保其他组件不会干扰选择
            width=20
        )
        for folder in self.folder_list:
            self.listbox_folders.insert(tk.END, folder)

            # 如果该文件夹在之前的选择中，自动选中
            if folder in self.config["selected_folders"]:
                index = self.folder_list.index(folder)
                self.listbox_folders.selection_set(index)

        self.listbox_folders.grid(row=0, column=1, padx=10, pady=20, sticky="w")

        # 刷新设置
        label_refresh_mail = tk.Label(self.root, text="读取邮件周期（秒）:", font=("Arial", 12))
        label_refresh_mail.grid(row=1, column=0, padx=10, pady=20, sticky="e")
        self.entry_refresh_mail.insert(0, self.config["refresh_interval"])  # 加载之前的刷新周期
        self.entry_refresh_mail.grid(row=1, column=1, padx=10, pady=20)  # 放置在第1行第1列

        # 按钮：确认选择
        button_confirm = tk.Button(self.root, text="确认", command=self.confirm_selection)
        button_confirm.grid(row=2, column=0, columnspan=2, pady=10)

        # 运行主循环
        self.root.mainloop()

    def confirm_selection(self):
        # 获取用户选择的文件夹索引
        selected_indices = self.listbox_folders.curselection()
        if not selected_indices:
            messagebox.showwarning("警告", "请先选择至少一个邮箱文件夹！")
        else:
            # 根据索引获取文件夹名称
            self.selected_folders = [self.listbox_folders.get(index) for index in selected_indices]

            # 保存设置
            self.save_settings()

            # 显示选择结果
            messagebox.showinfo("选择结果", f"您选择了以下文件夹: {', '.join(self.selected_folders)}")

# 示例：运行程序
if __name__ == "__main__":
    # 假设这是已保存的邮箱文件夹列表
    saved_folders = IMAIL_163("qu_personal@163.com").fetch_floders()
    # 初始化应用程序
    app = EmailFolderApp(saved_folders)

