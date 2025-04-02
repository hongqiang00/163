import pandas as pd
import sqlite3
from _base_dir import BASE_DIR
import os

def save_to_excel(persons,file_path=os.path.join(BASE_DIR, "data", "students_info.xlsx")):
    """
    使用 pandas 将多个学生信息追加保存到 Excel 文件中，并根据电话字段去重。
    
    :param file_path: Excel 文件路径
    :param students_info: 学生信息列表，每个元素是一个字典，格式为 {'姓名': '张三', '电话': '123456789', ...}
    """
    if not persons:
        print("没有学生信息需要保存。")
        return
        
    students_info=[]
    for person in persons:
        student={
            "学生姓名":person.name,
            "联系电话":person.phone,
            "微信":person.wechat,
            "意向地区":person.intention,
            "号码归属地区":person.area,
            "源文本内容":person.others
        }
        students_info.append(student)


    # 检查文件是否存在
    try:
        # 如果文件存在，加载现有数据
        existing_data = pd.read_excel(file_path,dtype={"联系电话": str})# 确保电话字段为字符串类型，并去除多余空格
        # existing_data["电话"] = existing_data["电话"].astype(str).str.strip()
    except FileNotFoundError:
        # 如果文件不存在，创建一个空的 DataFrame，并指定列名
        existing_data = pd.DataFrame(columns=["学生姓名", "联系电话", "微信", "意向地区", "号码归属地区", "源文本内容"])

    # 将新学生信息转换为 DataFrame
    new_data = pd.DataFrame(students_info)
    # 确保电话字段为字符串类型，并去除多余空格
    new_data["联系电话"] = new_data["联系电话"].astype(str).str.strip() 

    # 合并现有数据和新数据
    combined_data = pd.concat([existing_data, new_data], ignore_index=True)

    # 去重：仅保留“电话”字段唯一的记录
    combined_data = combined_data.drop_duplicates(subset=["联系电话"], keep="first")

    # 保存到 Excel 文件
    combined_data.to_excel(file_path, index=False, engine="openpyxl")
    print(f"{len(new_data)} 条学生信息已成功保存到 {file_path}")

def save_to_database(persons, db_path=os.path.join(BASE_DIR, "data", "students_info.db")):
    """
    将学生信息保存到 SQLite 数据库中，并根据电话字段去重。
    """
    if len(persons) == 0:
        return

    # 创建数据库连接
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # 创建表（如果不存在）
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS students (
            学生姓名 TEXT,
            联系电话 TEXT PRIMARY KEY,
            微信 TEXT,
            意向地区 TEXT,
            号码归属地区 TEXT,
            源文本内容 TEXT
        )
    """)

    # 插入或更新数据
    for person in persons:
        student = (
            person.name,
            person.phone,
            person.wechat,
            person.intention,
            person.area,
            person.others
        )
        cursor.execute("""
            INSERT OR REPLACE INTO students (学生姓名, 联系电话, 微信, 意向地区, 号码归属地区, 源文本内容)
            VALUES (?, ?, ?, ?, ?, ?)
        """, student)

    # 提交更改并关闭连接
    conn.commit()
    conn.close()

    print(f"{len(persons)} 条学生信息已成功保存到 {db_path}")

def read_from_database(db_path=os.path.join(BASE_DIR, "data", "students_info.db")):
    """
    从 SQLite 数据库中读取学生信息。
    
    :param db_path: 数据库文件路径
    :return: 学生信息列表（每个学生是一个字典）
    """
    # 创建数据库连接
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        # 查询所有学生信息
        cursor.execute("SELECT * FROM students")
        rows = cursor.fetchall()

        # 获取列名
        column_names = [description[0] for description in cursor.description]

        # 将查询结果转换为字典列表
        students_info = []
        for row in rows:
            student = dict(zip(column_names, row))
            students_info.append(student)

        return students_info

    except sqlite3.Error as e:
        print(f"数据库错误: {e}")
        return []

    finally:
        # 关闭连接
        conn.close()

# 示例：运行程序
if __name__ == "__main__":
    # 读取数据库中的学生信息
    students = read_from_database()

    # 打印学生信息
    for student in students:
        print(student)