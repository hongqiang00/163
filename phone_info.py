import requests
import time

COOKIES  = {
    'MicrosoftApplicationsTelemetryDeviceId': 'bb719f0b-0722-4da1-aa23-10d04162b738',
    'MicrosoftApplicationsTelemetryFirstLaunchTime': '2024-05-30T08:32:44.993Z',
}

HEADERS  = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Language': 'en,zh-CN;q=0.9,zh;q=0.8,zh-TW;q=0.7,en-US;q=0.6',
    'Cache-Control': 'max-age=0',
    'Connection': 'keep-alive',
    # 'Cookie': 'MicrosoftApplicationsTelemetryDeviceId=bb719f0b-0722-4da1-aa23-10d04162b738; MicrosoftApplicationsTelemetryFirstLaunchTime=2024-05-30T08:32:44.993Z',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'sec-ch-ua': '"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
}



API_URL = 'https://cx.shouji.360.cn/phonearea.php'


#该函数的功能是通过发送HTTP GET请求到指定的API URL来获取给定电话号码的省份和城市信息。它使用了requests库来发起请求，并通过API返回的JSON数据来解析和提取所需信息。函数中实现了重试机制，在请求失败时会按照指数退避策略进行重试，最多重试3次。如果最终请求成功，则返回获取到的省份和城市；如果请求失败，则返回False。# 通过电话号码获取IP地址所在的省份和城市
def ip_phone_get(phonenumber):
    # 构建请求参数
    params = {'number': phonenumber}

    # 定义最大重试次数
    MAX_RETRIES = 3
    # 初始重试延迟时间为1秒
    delay = 1

    # 尝试获取IP地址信息
    for i in range(MAX_RETRIES):
        try:
            # 发起GET请求
            response = requests.get(API_URL, params=params, cookies=COOKIES, headers=HEADERS, timeout=10)
            # 解析响应的JSON数据
            res_json = response.json()
            # 检查响应状态码和业务码是否成功
            if response.status_code == 200 and res_json.get('code') == 0:
                # 返回省份和城市信息
                return res_json['data'].get('province')+' '+res_json['data'].get('city')
            else:
                # 打印错误信息
                print(f"API response error: {res_json.get('msg', 'Unknown error')}")
        except requests.exceptions.RequestException as e:
            # 打印请求异常信息
            print(f"Request error: {e}")
        
        # 重试逻辑
        if i < MAX_RETRIES - 1:
            # 打印重试信息，并根据重试次数增加延迟时间
            print(f"Retrying in {delay} seconds ({i+1}/{MAX_RETRIES})...")
            delay *= 2  # 指数退避策略
            # 等待
            time.sleep(delay)

    # 所有重试失败后打印失败信息
    print("phone_ip Request failed after maximum retries.")
    # 返回''表示获取失败
    return ''



def main():  
    phonenumber='15727953846'
    print(ip_phone_get(phonenumber))

if __name__ == '__main__':
    main()

