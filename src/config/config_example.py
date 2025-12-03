"""
项目配置模块
"""
import os

# DeepSeek AI API 配置 - 优先从环境变量读取，其次使用默认值
DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "API_KEY")
DEEPSEEK_MODEL = os.environ.get("DEEPSEEK_MODEL", "Pro/deepseek-ai/DeepSeek-V3.2-Exp")
DEEPSEEK_BASE_URL = os.environ.get("DEEPSEEK_BASE_URL", "https://api.siliconflow.cn")
DEEPSEEK_MAX_RETRIES = int(os.environ.get("DEEPSEEK_MAX_RETRIES", "5"))
DEEPSEEK_TIMEOUT = int(os.environ.get("DEEPSEEK_TIMEOUT", "60"))
DEEPSEEK_MAX_TOKENS = int(os.environ.get("DEEPSEEK_MAX_TOKENS", "8000"))
