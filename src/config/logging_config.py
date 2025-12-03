"""
日志配置模块

此模块提供了统一的日志配置功能，支持同时输出日志到控制台和本地文件。
配置包括不同级别的日志处理、日志轮转、格式化等功能。
"""

import os
import logging
import logging.handlers
from datetime import datetime


def setup_logger(
    logger_name: str = "tara_logger",
    log_dir: str = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "logs",
    ),
    log_level: int = logging.INFO,
    console_level: int = logging.INFO,
    file_level: int = logging.INFO,
    max_bytes: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5,
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s",
) -> logging.Logger:
    """
    设置日志记录器，同时输出到控制台和文件

    Args:
        logger_name (str): 日志记录器名称
        log_dir (str): 日志文件保存目录
        log_level (int): 日志记录器的基础级别
        console_level (int): 控制台输出的日志级别
        file_level (int): 文件输出的日志级别
        max_bytes (int): 单个日志文件最大字节数
        backup_count (int): 保留的备份文件数量
        log_format (str): 日志格式字符串

    Returns:
        logging.Logger: 配置好的日志记录器实例
    """
    # 确保日志目录存在
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    # 创建日志记录器
    logger = logging.getLogger(logger_name)
    logger.setLevel(log_level)
    logger.propagate = False  # 防止日志被重复处理

    # 移除现有的处理器（避免重复添加）
    if logger.handlers:
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)

    # 创建格式化器
    formatter = logging.Formatter(log_format)

    # 创建控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(console_level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # 创建文件处理器 - 每日轮转
    current_date = datetime.now().strftime("%Y-%m-%d")
    log_filename = os.path.join(log_dir, f"tara_{current_date}.log")

    # 使用RotatingFileHandler进行文件大小轮转
    file_handler = logging.handlers.RotatingFileHandler(
        filename=log_filename,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    file_handler.setLevel(file_level)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger


def get_logger(logger_name: str = "tara_logger") -> logging.Logger:
    """
    获取已配置的日志记录器

    Args:
        logger_name (str): 日志记录器名称

    Returns:
        logging.Logger: 日志记录器实例
    """
    logger = logging.getLogger(logger_name)
    # 如果logger还没有处理器，使用默认配置
    if not logger.handlers:
        setup_logger(logger_name)
    return logger


# 默认配置的根日志记录器
DEFAULT_LOGGER = setup_logger()
