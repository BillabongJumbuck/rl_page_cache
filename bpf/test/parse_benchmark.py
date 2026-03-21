import re
import csv

def parse_benchmark_log(input_filename, output_filename):
    # 正则表达式匹配 Header，例如: Workload [wl1] | Policy [linux] | Run: 1/3
    header_regex = re.compile(r"Workload \[([^\]]+)\]\s*\|\s*Policy \[([^\]]+)\]\s*\|\s*Run:\s*(\d+)")

    parsed_data = []
    current_record = {}

    try:
        with open(input_filename, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
            # 将多行内容合并，并清理掉 "" 这种干扰标签
            raw_text = "".join(lines)
            clean_text = re.sub(r'\n?\\s*', '', raw_text)
            
            for line in clean_text.split('\n'):
                line = line.strip()
                if not line or line.startswith('====') or line.startswith('Chameleon'):
                    continue
                
                header_match = header_regex.search(line)
                if header_match:
                    # 遇到新的测试块时，保存上一个块的数据
                    if current_record:
                        parsed_data.append(current_record)
                    
                    # 初始化新的一行记录
                    current_record = {
                        "Workload": header_match.group(1),
                        "Policy": header_match.group(2),
                        "Run": header_match.group(3)
                    }
                elif ":" in line and current_record:
                    # 以冒号为界限切分键值对
                    parts = line.split(":", 1)
                    key = parts[0].strip()
                    value = parts[1].strip()
                    current_record[key] = value

        # 保存最后一个块的数据
        if current_record:
            parsed_data.append(current_record)

        # 写入 CSV
        if parsed_data:
            # 动态获取所有的列名（保持日志中输出的顺序）
            fieldnames = list(parsed_data[0].keys())
            with open(output_filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(parsed_data)
            print(f"转换成功！共解析了 {len(parsed_data)} 条记录，已保存至 {output_filename}")
        else:
            print("未能从文件中解析到有效数据，请检查 result.txt 是否为空或格式不匹配。")

    except FileNotFoundError:
        print(f"错误: 找不到文件 {input_filename}，请确保文件和脚本在同一目录下。")

if __name__ == "__main__":
    parse_benchmark_log("result.txt", "result.csv")