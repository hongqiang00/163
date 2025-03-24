import os
import json
from openai import OpenAI
from imap import Person

class QwenAPIHandler:
    def __init__(self, api_key=None):
        # 初始化 OpenAI 客户端
        self.client = OpenAI(
            api_key=api_key or os.getenv("DASHSCOPE_API_KEY"),  # 使用环境变量或手动设置 API Key
            base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
        )
        # 初始化对话历史，仅保留系统指令
        self.messages = [
            {
                "role": "system",
                "content": (
                    "你是一个信息提取助手。我会给你一段文本，其中可能包含多个人的信息。"
                    "请提取其中的关键信息，并按照以下 JSON 格式返回："
                    "[{\"学生姓名\":\"\",\"联系电话\":\"\",\"意向地区\":\"\",\"源文本内容\":\"\"}, ...]。"
                    "如果某条信息无法提取完整，请将其字段值设为空字符串。"
                ),
            }
        ]

    def clean_response(self, response_content):
        """
        清理返回内容，移除多余的 Markdown 标记（如 ```json）
        :param response_content: 模型返回的内容
        :return: 清理后的内容
        """
        # 去掉开头和结尾的多余标记
        response_content = response_content.strip()
        if response_content.startswith("```json"):
            response_content = response_content[len("```json"):]
        if response_content.endswith("```"):
            response_content = response_content[:-3]
        return response_content.strip()  # 去掉前后空白字符

    def call_api(self, user_input):
        """
        调用 API 并处理响应
        :param user_input: 用户输入的文本
        """
        clients=[]
        # 清空之前的用户输入，仅保留系统指令
        self.messages = self.messages[:1]  # 只保留第一个元素（系统指令）

        # 添加用户的最新输入
        self.messages.append({"role": "user", "content": user_input})

        try:
            # 调用 API
            completion = self.client.chat.completions.create(
                model="qwen-turbo",  # 模型名称
                messages=self.messages,
            )

            # 提取模型的回复
            response_message = completion.choices[0].message.content

            # 清理返回内容
            cleaned_response = self.clean_response(response_message)

            # 尝试将内容解析为 JSON 格式
            try:
                extracted_info = json.loads(cleaned_response)
                print("提取的信息:")
                for person in extracted_info:
                    print(person)
                    client=Person(person['学生姓名'],person['联系电话'],person['意向地区'],person['源文本内容'])
                    clients.append(client)
            except json.JSONDecodeError as e:
                print(f"无法解析返回的内容为 JSON: {e}")
                print("原始内容:", response_message)

        except Exception as e:
            print(f"请求过程中发生错误: {e}")
        return clients

# 使用示例
if __name__ == "__main__":
    # 创建 API 处理器实例
    handler = QwenAPIHandler()

    # 输入包含多个人的信息
    users=handler.call_api(
        "瞿红强 想咨询香港的学校，家长电话：18711546987\r\n李华 想咨询北京的学校，家长电话：13512345678"
    )
