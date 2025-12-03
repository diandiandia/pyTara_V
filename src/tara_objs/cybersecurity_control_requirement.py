"""
网络安全控制与需求模块

这个模块定义了网络安全控制与需求相关的类，用于管理与资产相关的网络安全控制措施和需求。
"""

import json
from typing import Optional, Dict, Any
import hashlib
import time


class CybersecurityControlRequirement:
    """
    网络安全控制与需求类

    包含网络安全控制措施及其对应的需求信息，用于TARA分析中的风险处理部分。

    属性:
    - allocated_to_device: 是否分配给ADCU设备
    - cybersecurity_control_id: 网络安全控制ID
    - cybersecurity_control: 网络安全控制措施描述
    - cybersecurity_requirement_id: 网络安全需求ID
    - cybersecurity_requirement: 网络安全需求描述
    """

    def __init__(
        self,
        cybersecurity_control_id: Optional[str] = None,
        cybersecurity_control: Optional[str] = None,
        allocated_to_device: Optional[bool] = None,
        cybersecurity_requirement_id: Optional[str] = None,
        cybersecurity_requirement: Optional[str] = None,
    ):
        """
        初始化网络安全控制与需求对象

        Args:
            allocated_to_device: 是否分配给ADCU设备
            cybersecurity_control_id: 网络安全控制ID
            cybersecurity_control: 网络安全控制措施描述
            cybersecurity_requirement_id: 网络安全需求ID
            cybersecurity_requirement: 网络安全需求描述
        """
        self.cybersecurity_control_id = cybersecurity_control_id
        self.cybersecurity_control = cybersecurity_control
        self.allocated_to_device = allocated_to_device
        self.cybersecurity_requirement_id = cybersecurity_requirement_id
        self.cybersecurity_requirement = cybersecurity_requirement

    def __str__(self) -> str:
        """
        返回网络安全控制与需求的字符串表示

        Returns:
            str: 格式化的网络安全控制与需求信息
        """
        info = "cybersecurity_control_requirement:\n"
        info += (
            f"cybersecurity_control_id: {self.cybersecurity_control_id or 'not set'}\n"
        )
        info += f"cybersecurity_control: {self.cybersecurity_control or 'not set'}\n"
        info += f"allocated_to_device: {'yes' if self.allocated_to_device else 'no' if self.allocated_to_device is not None else 'not set'}\n"
        info += f"cybersecurity_requirement_id: {self.cybersecurity_requirement_id or 'not set'}\n"
        info += f"cybersecurity_requirement: {self.cybersecurity_requirement or 'not set'}\n"
        return info

    def to_dict(self) -> Dict[str, Any]:
        """
        将网络安全控制与需求信息转换为字典格式

        Returns:
            Dict[str, Any]: 包含网络安全控制与需求信息的字典
        """
        return {
            "cybersecurity_control_id": self.cybersecurity_control_id,
            "cybersecurity_control": self.cybersecurity_control,
            "allocated_to_device": (
                "yes"
                if self.allocated_to_device
                else "no" if self.allocated_to_device is not None else None
            ),
            "cybersecurity_requirement_id": self.cybersecurity_requirement_id,
            "cybersecurity_requirement": self.cybersecurity_requirement,
        }

    def regenerate_csr_id(self):
        """
        重新生成网络安全需求ID - 使用短哈希
        生成一个新的唯一ID，用于标识网络安全需求。
        """
        # 使用SHA256然后截取前8位，比MD5更安全且更短
        current_time = int(time.time() * 1000)  # 转换为毫秒级时间戳，确保是整数
        hash_obj = hashlib.sha256(
            self.cybersecurity_requirement.encode("utf-8") + current_time.to_bytes(8, byteorder="big")
        )
        short_hash = hash_obj.hexdigest()[:8]
        self.cybersecurity_requirement_id = f"CSR-{short_hash}"

    def to_dict01(self) -> Dict[str, Any]:
        """
        将网络安全控制与需求信息转换为字典格式

        Returns:
            Dict[str, Any]: 包含网络安全控制与需求信息的字典
        """
        return {
            "cybersecurity_requirement_id": self.cybersecurity_requirement_id,
            "cybersecurity_requirement": self.cybersecurity_requirement,
        }

    def to_json(self) -> str:
        """
        将网络安全控制与需求信息转换为JSON字符串

        Returns:
            str: 包含网络安全控制与需求信息的JSON字符串
        """
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    def prepare_for_ai(self) -> str:
        """
        准备网络安全控制与需求信息，用于AI模型输入

        Returns:
            str: 格式化的网络安全控制与需求信息
        """
        return json.dumps(self.to_dict(), ensure_ascii=False)
