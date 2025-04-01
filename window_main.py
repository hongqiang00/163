import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import configparser
import os
from cryptography.fernet import Fernet, InvalidToken # <-- Import Fernet and InvalidToken

# --- Constants ---
SIDEBAR_BG = "#F0F0F0"
ACTIVE_BUTTON_COLOR = "#E0E0E0"
BUTTON_STYLE_NAME = "Sidebar.TButton"
CONFIG_FILE = "user_prefs.ini"
CONFIG_SECTION = "UserPrefs"

# --- !!! SECURITY WARNING !!! ---
# Hardcoding the key like this is INSECURE for real applications.
# Anyone with access to the code can decrypt stored passwords.
# Consider using the 'keyring' library for better security.
# Replace 'YOUR_GENERATED_KEY_HERE' with the key you generated using Fernet.generate_key()
ENCRYPTION_KEY = b'858n6UwvlAWcBIPqb5VJE2kAgAFMevvNbzCSiq-tKT4=' # <-- PASTE YOUR KEY HERE (e.g., b'...')
# --- End Security Warning ---

# --- Encryption Helpers ---
try:
    cipher_suite = Fernet(ENCRYPTION_KEY)
except Exception as e:
    print(f"CRITICAL ERROR: Invalid encryption key format: {e}")
    # In a real app, you might exit or disable password remembering here.
    cipher_suite = None # Indicate failure

def encrypt_data(data: str) -> str:
    """Encrypts string data, returns base64 encoded string."""
    if not cipher_suite or not data:
        return ""
    try:
        encrypted_bytes = cipher_suite.encrypt(data.encode('utf-8'))
        return encrypted_bytes.decode('utf-8') # Store as string
    except Exception as e:
        print(f"Encryption failed: {e}")
        return ""

def decrypt_data(encrypted_data: str) -> str:
    """Decrypts base64 encoded string data, returns original string."""
    if not cipher_suite or not encrypted_data:
        return ""
    try:
        decrypted_bytes = cipher_suite.decrypt(encrypted_data.encode('utf-8'))
        return decrypted_bytes.decode('utf-8')
    except (InvalidToken, TypeError, ValueError) as e: # Catch potential errors
        print(f"Decryption failed (InvalidToken/Format): {e}")
        return "" # Return empty string on failure
    except Exception as e:
        print(f"Decryption failed (Other): {e}")
        return ""


# --- Simulated Data ---
VALID_USERS = {
    "admin": "password123",
    "user": "pass"
}

current_settings = {
    "profile_name": "Default Profile",
    "port": 7890,
    "allow_lan": False,
    "mode": "Rule"
}

DEFAULT_PROXY_MODEL = "qwen"

# --- Main Application Class ---
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        # ... (window setup remains the same) ...
        self.title("类 Clash 交互界面")
        self.geometry("700x500")

        # --- State ---
        self.logged_in_user = None
        self.current_frame_name = None
        self.sidebar_buttons = {}
        self.remembered_username = ""
        self.remembered_password = "" # <-- Store loaded DECRYPTED password
        self.should_remember = False
        self.general_email = ""
        self.general_imap_password = ""
        self.proxy_model = DEFAULT_PROXY_MODEL # 初始化默认模型

        self.load_user_preferences()

        # --- Style Configuration ---
        self.style = ttk.Style(self)
        # ... (style configuration remains the same) ...
        self.style.configure(BUTTON_STYLE_NAME,
                             anchor="w", padding=(10, 8), font=("Arial", 11),
                             background=SIDEBAR_BG, relief="flat")
        self.style.map(BUTTON_STYLE_NAME,
                       background=[('active', ACTIVE_BUTTON_COLOR),
                                   ('selected', ACTIVE_BUTTON_COLOR)])


        # --- Create main layout frames ---
        # ... (frame creation remains the same) ...
        self.sidebar_frame = tk.Frame(self, bg=SIDEBAR_BG, width=150)
        self.sidebar_frame.pack(side="left", fill="y")
        self.sidebar_frame.pack_propagate(False)

        self.main_frame = tk.Frame(self)
        self.main_frame.pack(side="right", fill="both", expand=True)
        self.main_frame.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        self.content_frames = {}

        # --- Pass loaded preferences to LoginPage ---
        self.login_frame = LoginPage(
            parent=self.main_frame,
            controller=self,
            initial_username=self.remembered_username,
            initial_remember=self.should_remember,
            initial_password=self.remembered_password # <-- Pass loaded password
        )
        self.login_frame.grid(row=0, column=0, sticky="nsew")
        self.current_frame_name = "LoginPage"
        self.sidebar_frame.pack_forget()


    def load_user_preferences(self):
        """Loads username, encrypted password, and remember state."""
        config = configparser.ConfigParser()
        self.remembered_username = "" # Reset before loading
        self.remembered_password = ""
        self.should_remember = False
        self.general_email = ""       
        self.general_imap_password = ""
        self.proxy_model = DEFAULT_PROXY_MODEL
        
        if not os.path.exists(CONFIG_FILE):
            return # Nothing to load

        try:
            config.read(CONFIG_FILE)
            if config.has_section(CONFIG_SECTION):
                self.should_remember = config.getboolean(CONFIG_SECTION, 'remember', fallback=False)
                if self.should_remember:
                    self.remembered_username = config.get(CONFIG_SECTION, 'username', fallback="")
                    encrypted_pass = config.get(CONFIG_SECTION, 'password_enc', fallback="") # <-- Load encrypted pass
                    if encrypted_pass:
                        self.remembered_password = decrypt_data(encrypted_pass) # <-- Decrypt
                        if not self.remembered_password:
                             # Decryption failed, clear related stored data for safety
                             print("WARN: Could not decrypt stored password. Clearing remembered credentials.")
                             self.remembered_username = ""
                             self.should_remember = False
                             # Optionally: notify the user or clear the corrupt entry in the file
                # else: # No need for else, defaults are already set

                self.general_email = config.get(CONFIG_SECTION, 'general_email', fallback="")
                encrypted_imap_pass = config.get(CONFIG_SECTION, 'general_imap_password_enc', fallback="")
                if encrypted_imap_pass:
                    self.general_imap_password = decrypt_data(encrypted_imap_pass)
                    if not self.general_imap_password:
                        # 解密失败，可以选择清除 email 或仅清除密码
                        print("WARN: Could not decrypt stored IMAP password.")
                        # self.general_email = "" # 可选：如果密码无效，是否也清除关联的邮箱？

                # --- >>> 加载代理模型选择 <<< ---
                self.proxy_model = config.get(CONFIG_SECTION, 'proxy_model', fallback=DEFAULT_PROXY_MODEL)
                # 可以加个验证，确保加载的值是合法的选项之一，否则回退到默认
                if self.proxy_model not in ["qwen", "yuanbao", "fixed"]:
                    print(f"WARN: Invalid proxy_model '{self.proxy_model}' found in config. Using default.")
                    self.proxy_model = DEFAULT_PROXY_MODEL  

        except (configparser.Error, ValueError) as e:
            print(f"Error reading config file '{CONFIG_FILE}': {e}")
            # Reset to defaults on error
            self.remembered_username = ""
            self.remembered_password = ""
            self.should_remember = False
        # print(f"Loaded prefs: Remember={self.should_remember}, User='{self.remembered_username}', Pass loaded: {'Yes' if self.remembered_password else 'No'}") # Debug

    def save_user_preferences(self, username, password, remember): # <-- Accept password
        """Saves username, encrypted password, and remember state."""
        config = configparser.ConfigParser()
        try:
            if os.path.exists(CONFIG_FILE):
                config.read(CONFIG_FILE)
            if not config.has_section(CONFIG_SECTION):
                config.add_section(CONFIG_SECTION)

            config.set(CONFIG_SECTION, 'remember', str(remember))
            if remember:
                config.set(CONFIG_SECTION, 'username', username)
                encrypted_pass = encrypt_data(password) # <-- Encrypt password
                config.set(CONFIG_SECTION, 'password_enc', encrypted_pass) # <-- Save encrypted
            else:
                # Clear stored credentials if not remembering
                config.set(CONFIG_SECTION, 'username', '')
                config.set(CONFIG_SECTION, 'password_enc', '') # <-- Clear encrypted pass

            with open(CONFIG_FILE, 'w') as configfile:
                config.write(configfile)
            # print(f"Saved prefs: Remember={remember}, User='{username if remember else ''}', Pass saved: {'Yes' if remember else 'No'}") # Debug
        except (IOError, configparser.Error) as e:
            messagebox.showerror("错误", f"无法保存用户偏好设置:\n{e}")

    def save_general_credentials(self, email, imap_password):
        """Saves General page email and encrypted IMAP password."""
        config = configparser.ConfigParser()
        # 更新内存中的值
        self.general_email = email
        self.general_imap_password = imap_password # 存明文在内存供当前会话使用

        try:
            if os.path.exists(CONFIG_FILE): config.read(CONFIG_FILE)
            if not config.has_section(CONFIG_SECTION): config.add_section(CONFIG_SECTION)

            config.set(CONFIG_SECTION, 'general_email', email)
            encrypted_imap_pass = encrypt_data(imap_password) # 加密密码
            config.set(CONFIG_SECTION, 'general_imap_password_enc', encrypted_imap_pass) # 保存加密后的密码

            # --- 注意：这里不修改登录相关的偏好 ---

            with open(CONFIG_FILE, 'w') as configfile: config.write(configfile)
            print("General credentials saved to config.") # Debug print
        except (IOError, configparser.Error) as e:
            messagebox.showerror("错误", f"无法保存邮箱凭据:\n{e}")

    def save_proxy_model_preference(self, model_key):
        """Saves the selected proxy model identifier."""
        config = configparser.ConfigParser()
        # 更新内存状态
        self.proxy_model = model_key
        try:
            if os.path.exists(CONFIG_FILE): config.read(CONFIG_FILE)
            if not config.has_section(CONFIG_SECTION): config.add_section(CONFIG_SECTION)

            config.set(CONFIG_SECTION, 'proxy_model', model_key) # 直接保存标识符

            # --- 不修改其他配置 ---
            with open(CONFIG_FILE, 'w') as configfile: config.write(configfile)
            print(f"Proxy model preference saved: {model_key}") # Debug print
        except (IOError, configparser.Error) as e:
            messagebox.showerror("错误", f"无法保存代理模型设置:\n{e}")

    # --- >>> 新增: Getter 方法 (可选但推荐) <<< ---
    def get_general_email(self):
        return self.general_email

    def get_general_imap_password(self):
        # 注意：返回的是内存中当前会话的明文密码
        return self.general_imap_password
    
    def get_proxy_model(self): return self.proxy_model
    # --- Other App methods (setup_main_interface, show_frame, successful_login, logout, save_settings) ---
    # --- remain largely the same as the previous version.                       ---
    # --- Make sure successful_login doesn't clear anything prematurely          ---

    def setup_main_interface(self):
        # ... (Identical to previous version) ...
        self.sidebar_frame.pack(side="left", fill="y")
        sidebar_options = {"GeneralPage": "通用", "ProxiesPage": "代理", "ProfilesPage": "配置", "SettingsPage": "设置", "AboutPage": "关于"}
        for page_name, display_text in sidebar_options.items():
            button = ttk.Button(self.sidebar_frame, text=display_text, style=BUTTON_STYLE_NAME, command=lambda p=page_name: self.show_frame(p))
            button.pack(fill="x", pady=1, padx=5)
            self.sidebar_buttons[page_name] = button
        ttk.Separator(self.sidebar_frame, orient='horizontal').pack(fill='x', pady=10, padx=5)
        logout_button = ttk.Button(self.sidebar_frame, text="登出", style=BUTTON_STYLE_NAME, command=self.logout)
        logout_button.pack(fill="x", side="bottom", pady=10, padx=5)
        pages = {"GeneralPage": GeneralPage, "ProxiesPage": ProxiesPage, "ProfilesPage": PlaceholderPage, "SettingsPage": SettingsPage, "AboutPage": PlaceholderPage}
        print("--- 开始创建 Frame ---")
        for name, PageClass in pages.items():
            print(f"尝试创建 Frame: {name}")
            try:
                # --- 这是关键部分 ---
                frame = PageClass(parent=self.main_frame, controller=self, page_name=name)
                self.content_frames[name] = frame
                print(f"成功创建并添加 Frame: {name}")
                frame.grid(row=0, column=0, sticky="nsew")
            except Exception as e:
                # --- 如果 __init__ 出错，这里会打印详细信息 ---
                print(f"!!!!!!!! 创建 Frame '{name}' 时出错 !!!!!!!!")
                print(f"错误类型: {type(e)}")
                print(f"错误详情: {e}")
                import traceback
                traceback.print_exc() # <<< 最重要的输出信息
                print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("--- Frame 创建结束 ---")
        print("最终 content_frames 的键:", self.content_frames.keys())

    def show_frame(self, page_name):
        # ... (Identical to previous version) ...
        if page_name == "LoginPage":
             self.login_frame.tkraise()
             self.current_frame_name = page_name
             for btn in self.sidebar_buttons.values(): btn.state(['!selected'])
             return
        if page_name in self.content_frames:
            if self.current_frame_name and self.current_frame_name in self.sidebar_buttons:
                 old_button = self.sidebar_buttons[self.current_frame_name]
                 old_button.state(['!selected'])
            new_button = self.sidebar_buttons.get(page_name)
            if new_button: new_button.state(['selected'])
            frame = self.content_frames[page_name]
            frame.tkraise()
            self.current_frame_name = page_name
            if hasattr(frame, 'on_show'): frame.on_show()
        else: print(f"Warning: Frame '{page_name}' not found.")

    def successful_login(self, username):
        # ... (Identical to previous version) ...
        self.logged_in_user = username
        self.title(f"类 Clash 交互界面 - 已登录: {username}")
        self.login_frame.grid_forget()
        if not self.content_frames: self.setup_main_interface()
        self.show_frame("GeneralPage")

    def logout(self):
        # ... (Identical to previous version) ...
        self.logged_in_user = None
        self.title("类 Clash 交互界面")
        self.sidebar_frame.pack_forget()
        for frame in self.content_frames.values(): frame.grid_forget()
        self.login_frame.clear_password() # Clears only the password field visually
        # Reload preferences to check if username should still be shown
        self.load_user_preferences()
        self.login_frame.username_entry.delete(0, tk.END) # Clear current username entry
        if self.should_remember and self.remembered_username: # If still remembering, re-insert username
            self.login_frame.username_entry.insert(0, self.remembered_username)
            self.login_frame.remember_me_var.set(True)
        else: # Otherwise, ensure checkbox is off
            self.login_frame.remember_me_var.set(False)

        self.login_frame.grid(row=0, column=0, sticky="nsew")
        self.show_frame("LoginPage")

    def save_settings(self, settings_data):
        # ... (Identical to previous version) ...
        global current_settings
        current_settings.update(settings_data)
        print("设置已更新:", current_settings)
        messagebox.showinfo("成功", "参数设置已保存！")


# --- Page Frame Classes ---

# --- Login Page ---
class LoginPage(tk.Frame):
    # <-- Accept initial_password
    def __init__(self, parent, controller, initial_username="", initial_remember=False, initial_password=""):
        super().__init__(parent)
        self.controller = controller

        # ... (UI layout remains similar) ...
        center_frame = tk.Frame(self)
        center_frame.place(relx=0.5, rely=0.4, anchor="center")
        ttk.Label(center_frame, text="账号登录", font=("Arial", 18, "bold")).pack(pady=15)
        input_frame = ttk.Frame(center_frame)
        input_frame.pack(pady=5, padx=30, fill="x")
        ttk.Label(input_frame, text="账号:").grid(row=0, column=0, padx=5, pady=6, sticky="w")
        self.username_entry = ttk.Entry(input_frame, width=30)
        self.username_entry.grid(row=0, column=1, padx=5, pady=6, sticky="ew")
        ttk.Label(input_frame, text="密码:").grid(row=1, column=0, padx=5, pady=6, sticky="w")
        self.password_entry = ttk.Entry(input_frame, show="*", width=30)
        self.password_entry.grid(row=1, column=1, padx=5, pady=6, sticky="ew")
        input_frame.grid_columnconfigure(1, weight=1)

        # --- Remember Me Checkbox ---
        self.remember_me_var = tk.BooleanVar()
        remember_check = ttk.Checkbutton(
            center_frame,
            text="记住登录状态", # <-- Renamed slightly
            variable=self.remember_me_var
        )
        remember_check.pack(pady=5, anchor='w', padx=30)

        # --- Set initial state ---
        if initial_remember:
            self.remember_me_var.set(True)
            if initial_username:
                self.username_entry.insert(0, initial_username)
            if initial_password: # <-- Check if password was loaded
                self.password_entry.insert(0, initial_password) # <-- Pre-fill password
        # --- End Remember Me ---

        login_button = ttk.Button(center_frame, text="登录", command=self.attempt_login, width=15)
        login_button.pack(pady=15)
        self.bind("<Map>", self.bind_enter)
        self.bind("<Unmap>", self.unbind_enter)
        self.status_label = ttk.Label(center_frame, text="", foreground="red")
        self.status_label.pack(pady=5)

    def bind_enter(self, event=None):
        self.controller.bind('<Return>', self.attempt_login_event)
        if not self.username_entry.get(): self.username_entry.focus_set()
        elif not self.password_entry.get(): self.password_entry.focus_set() # Focus password if user exists but pass empty
        else: self.username_entry.focus_set() # Or back to user


    def unbind_enter(self, event=None):
        self.controller.unbind('<Return>')

    def attempt_login_event(self, event=None):
        self.attempt_login()

    def attempt_login(self):
        username = self.username_entry.get()
        password = self.password_entry.get() # <-- Get password from entry

        if not username or not password:
            self.status_label.config(text="账号和密码不能为空")
            return

        if username in VALID_USERS and VALID_USERS[username] == password:
            self.status_label.config(text="")
            remember_choice = self.remember_me_var.get()
            # <-- Pass password to save function
            self.controller.save_user_preferences(username, password, remember_choice)
            self.controller.successful_login(username)
        else:
            self.status_label.config(text="账号或密码错误")
            self.password_entry.delete(0, tk.END) # Clear password on failure

    def clear_password(self):
        """Clears the password entry field visually."""
        self.password_entry.delete(0, tk.END)
        # Username might be remembered, don't clear it here
        self.status_label.config(text="")


# --- General Page, Settings Page, Placeholder Page ---
# --- (These remain identical to the previous version) ---
class GeneralPage(tk.Frame):
    def __init__(self, parent, controller, page_name):
        super().__init__(parent)
        self.controller = controller
        self.page_name = page_name

        # 顶部框架（包含标题和用户信息）
        top_frame = ttk.Frame(self)
        top_frame.pack(fill="x", padx=20, pady=(20, 10))
        ttk.Label(top_frame, text="通用", font=("Arial", 16)).pack(side="left", anchor="w")
        self.user_label = ttk.Label(top_frame, text="")
        self.user_label.pack(side="right", anchor="e") # 用户信息放右边

        # 分隔线
        ttk.Separator(self, orient='horizontal').pack(fill='x', padx=20, pady=5)

        # 凭据设置框架
        credentials_frame = ttk.LabelFrame(self, text="邮箱凭据设置 (163)", padding=(10, 5)) # 使用 LabelFrame 视觉分组
        credentials_frame.pack(pady=10, padx=30, fill="x", anchor="n")

        # 邮箱账号
        ttk.Label(credentials_frame, text="邮箱账号:").grid(row=0, column=0, padx=5, pady=8, sticky="w")
        self.email_entry = ttk.Entry(credentials_frame, width=40)
        self.email_entry.grid(row=0, column=1, padx=5, pady=8, sticky="ew")

        # IMAP 授权码
        ttk.Label(credentials_frame, text="IMAP 授权码:").grid(row=1, column=0, padx=5, pady=8, sticky="w")
        self.imap_password_entry = ttk.Entry(credentials_frame, show="*", width=40) # show="*"
        self.imap_password_entry.grid(row=1, column=1, padx=5, pady=8, sticky="ew")

        # 让输入框列可以伸展
        credentials_frame.grid_columnconfigure(1, weight=1)

        # 保存按钮
        save_cred_button = ttk.Button(credentials_frame, text="保存邮箱凭据", command=self.save_credentials)
        save_cred_button.grid(row=2, column=0, columnspan=2, pady=15) # 居中或靠左/右

        # 其他通用设置内容... (可以放在凭据框架之后或之前)
        # other_frame = ttk.Frame(self)
        # other_frame.pack(pady=10, padx=30, fill="both", expand=True)
        # ttk.Label(other_frame, text="这里可以放置其他通用开关...").pack(anchor="w")

    def load_credentials(self):
        """从控制器加载邮箱和IMAP密码到输入框"""
        email = self.controller.get_general_email()
        # 注意：从控制器获取的是解密后的密码
        imap_password = self.controller.get_general_imap_password()

        self.email_entry.delete(0, tk.END)
        self.imap_password_entry.delete(0, tk.END)

        if email:
            self.email_entry.insert(0, email)
        if imap_password:
            self.imap_password_entry.insert(0, imap_password)
        print("General credentials loaded into fields.") # Debug

    def save_credentials(self):
        """获取输入框内容并调用控制器保存"""
        email = self.email_entry.get()
        imap_password = self.imap_password_entry.get()

        # (可选) 在这里添加一些基本验证，例如检查邮箱格式是否大致正确
        if not email: # 简单检查是否为空
             messagebox.showwarning("提示", "邮箱账号不能为空。")
             return
        if not imap_password: # 简单检查是否为空
             messagebox.showwarning("提示", "IMAP 授权码不能为空。")
             return

        # 调用 App 的方法来处理保存和加密
        self.controller.save_general_credentials(email, imap_password)
        messagebox.showinfo("成功", "邮箱凭据已保存！")

    def on_show(self):
        """当页面显示时调用"""
        # 更新用户信息标签
        if self.controller.logged_in_user:
            self.user_label.config(text=f"当前用户: {self.controller.logged_in_user}")
        else:
            self.user_label.config(text="未登录")

        # 加载邮箱凭据到输入框
        self.load_credentials()

        print(f"Showing {self.page_name}")

class ProxiesPage(tk.Frame):
    def __init__(self, parent, controller, page_name):
        super().__init__(parent)
        self.controller = controller
        self.page_name = page_name

        # 定义模型选项 (显示文本 -> 内部值)
        self.model_options = {
            "通义千问": "qwen",
            "腾讯元宝": "yuanbao",
            "固定算法": "fixed"
        }

        # 页面标题
        ttk.Label(self, text="代理设置", font=("Arial", 16)).pack(pady=20, padx=20, anchor="w")

        # 模型选择框架
        model_frame = ttk.LabelFrame(self, text="大模型选择", padding=(10, 5))
        model_frame.pack(pady=10, padx=30, fill="x", anchor="n")

        # 用于存储当前选中模型值的变量
        self.selected_model_var = tk.StringVar()
        self.selected_model_var.trace_add("write", self.model_selected) # 当变量被写入时调用 model_selected

        # 创建 Radiobuttons
        for (text, value) in self.model_options.items():
            rb = ttk.Radiobutton(
                model_frame,
                text=text,
                variable=self.selected_model_var,
                value=value,
                # command=self.model_selected # 使用 trace_add 代替 command 更可靠
            )
            rb.pack(anchor="w", padx=10, pady=2) # 垂直排列，左对齐

        # (可选) 在这里可以添加其他代理相关的设置...
        # ttk.Separator(self, orient='horizontal').pack(fill='x', padx=20, pady=15)
        # other_proxy_frame = ttk.Frame(self)
        # other_proxy_frame.pack(pady=10, padx=30, fill="x", anchor="n")
        # ttk.Label(other_proxy_frame, text="其他代理设置...").pack()

    def model_selected(self, *args): # *args 接收 trace_add 传来的额外参数
        """当 Radiobutton 选项改变时调用"""
        selected_value = self.selected_model_var.get()
        print(f"Model selected (UI): {selected_value}") # Debug
        # 调用 App 控制器的方法来保存这个设置
        self.controller.save_proxy_model_preference(selected_value)

    def on_show(self):
        """当页面显示时调用"""
        # 从控制器获取当前保存的模型设置
        current_model = self.controller.get_proxy_model()
        print(f"Loading proxy model to UI: {current_model}") # Debug
        # 设置 StringVar 的值，这将自动更新 Radiobutton 的选中状态
        self.selected_model_var.set(current_model)
        print(f"Showing {self.page_name}")

# --- Settings Page --- (Remains the same)
class SettingsPage(tk.Frame):
    def __init__(self, parent, controller, page_name):
        super().__init__(parent)
        self.controller = controller
        self.page_name = page_name

        # 1. 页面主标题
        ttk.Label(self, text="详细参数设置", font=("Arial", 16)).pack(pady=20, padx=20, anchor="w")

        # 2. 创建用于容纳设置控件的内部 Frame
        settings_frame = ttk.Frame(self)
        # --- >>> 关键：确保这个内部 Frame 被放置到了 SettingsPage 上 <<< ---
        settings_frame.pack(pady=10, padx=30, fill="x", anchor="n") # 使用 pack 放置
        # 或者你可以使用 grid:
        # settings_frame.grid(row=1, column=0, sticky="nsew", padx=30, pady=10)
        # self.grid_rowconfigure(1, weight=1) # 如果用 grid，可能需要让行扩展
        # self.grid_columnconfigure(0, weight=1)
        # --- >>> 关键检查点结束 <<< ---

        # 3. 在 settings_frame 内部使用 grid 布局控件
        # Profile Name
        ttk.Label(settings_frame, text="配置名称:").grid(row=0, column=0, padx=5, pady=8, sticky="w")
        self.profile_entry = ttk.Entry(settings_frame, width=40)
        self.profile_entry.grid(row=0, column=1, padx=5, pady=8, sticky="ew")

        # Port
        ttk.Label(settings_frame, text="端口 (SOCKS/HTTP):").grid(row=1, column=0, padx=5, pady=8, sticky="w")
        self.port_spinbox = ttk.Spinbox(settings_frame, from_=1024, to=65535, width=10) # Example range
        self.port_spinbox.grid(row=1, column=1, padx=5, pady=8, sticky="w") # Stick west

        # Allow LAN
        self.allow_lan_var = tk.BooleanVar()
        lan_check = ttk.Checkbutton(settings_frame, text="允许来自局域网的连接", variable=self.allow_lan_var)
        lan_check.grid(row=2, column=0, columnspan=2, padx=5, pady=8, sticky="w")

        # Mode
        ttk.Label(settings_frame, text="模式:").grid(row=3, column=0, padx=5, pady=8, sticky="w")
        self.mode_options = ["Rule", "Global", "Direct"]
        self.mode_var = tk.StringVar()
        mode_combo = ttk.Combobox(settings_frame, textvariable=self.mode_var, values=self.mode_options, state="readonly", width=15)
        mode_combo.grid(row=3, column=1, padx=5, pady=8, sticky="w") # Stick west

        # 让控件列可以伸展
        settings_frame.grid_columnconfigure(1, weight=1)

        # 4. 保存按钮（也在 settings_frame 内部）
        save_button = ttk.Button(settings_frame, text="保存设置", command=self.save)
        save_button.grid(row=4, column=0, columnspan=2, pady=20)

    def save(self):
        print("Save button clicked!") # 可以先放一个简单的打印语句测试
        try:
            port_value = int(self.port_spinbox.get())
            if not (1024 <= port_value <= 65535):
                 raise ValueError("Port out of range")
        except ValueError:
            messagebox.showerror("错误", "端口号必须是 1024 到 65535 之间的整数。")
            return

        settings_data = {
            "profile_name": self.profile_entry.get(),
            "port": port_value,
            "allow_lan": self.allow_lan_var.get(),
            "mode": self.mode_var.get()
        }
        self.controller.save_settings(settings_data)
    # --- >>> 检查结束 <<< ---

    def on_show(self):
        # ... on_show 方法的代码 ...
        pass # 示例

class PlaceholderPage(tk.Frame):
     def __init__(self, parent, controller, page_name): super().__init__(parent); self.controller = controller; self.page_name = page_name; label = ttk.Label(self, text=f"{page_name} 内容区", font=("Arial", 14)); label.pack(padx=40, pady=40); note = ttk.Label(self, text="此页面内容尚未实现。"); note.pack(padx=40, pady=10)
     def on_show(self): pass


# --- Run the Application ---
if __name__ == "__main__":
    # Ensure a valid key is set before running
    if not ENCRYPTION_KEY or ENCRYPTION_KEY == b'YOUR_GENERATED_KEY_HERE':
         print("错误：请先生成一个加密密钥并将其粘贴到脚本中的 ENCRYPTION_KEY 常量。")
         # Optionally exit or show a GUI error message
         # exit(1)
         root = tk.Tk()
         root.withdraw() # Hide the root window
         messagebox.showerror("配置错误", "加密密钥未设置！请编辑脚本并添加一个有效的密钥。")
    elif cipher_suite is None:
         root = tk.Tk()
         root.withdraw()
         messagebox.showerror("配置错误", "加密密钥格式无效！无法记住密码。")
    else:
        app = App()
        app.mainloop()