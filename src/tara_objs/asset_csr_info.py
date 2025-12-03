"""
资产CSR信息模块

这个模块定义了资产网络安全要求(CSR)信息的类，用于存储和管理资产相关的网络安全要求。
"""

from typing import Optional
import json
import csv


class AssetCSRInfo:
    """
    资产网络安全要求信息类

    用于存储和管理资产的网络安全要求相关信息，包括资产标识、要求ID、标题、副标题和具体要求内容。
    """

    def __init__(
        self,
        asset_id: Optional[str] = None,
        asset_name: Optional[str] = None,
        cybersecurity_requirement_id: Optional[str] = None,
        csr_id: Optional[str] = None,
        title: Optional[str] = None,
        sub_title: Optional[str] = None,
        cybersecurity_requirement: Optional[str] = None,
    ):
        """
        初始化资产网络安全要求信息对象

        Args:
            asset_id: 资产ID
            asset_name: 资产名称
            cybersecurity_requirement_id: 网络安全要求ID
            csr_id: CSR ID (可能与cybersecurity_requirement_id相同或不同的标识符)
            title: 要求标题
            sub_title: 要求副标题
            cybersecurity_requirement: 网络安全要求内容
        """
        self.asset_id = asset_id
        self.asset_name = asset_name
        self.cybersecurity_requirement_id = cybersecurity_requirement_id
        self.csr_id = csr_id
        self.title = title
        self.sub_title = sub_title
        self.cybersecurity_requirement = cybersecurity_requirement

    def set_asset_info(self, asset_id: str, asset_name: str) -> None:
        """
        设置资产基本信息

        Args:
            asset_id: 资产ID
            asset_name: 资产名称
        """
        self.asset_id = asset_id
        self.asset_name = asset_name

    def set_requirement_info(
        self,
        cybersecurity_requirement_id: str,
        csr_id: str,
        title: str,
        sub_title: str,
        cybersecurity_requirement: str,
    ) -> None:
        """
        设置网络安全要求信息

        Args:
            cybersecurity_requirement_id: 网络安全要求ID
            csr_id: CSR ID
            title: 要求标题
            sub_title: 要求副标题
            cybersecurity_requirement: 网络安全要求内容
        """
        self.cybersecurity_requirement_id = cybersecurity_requirement_id
        self.csr_id = csr_id
        self.title = title
        self.sub_title = sub_title
        self.cybersecurity_requirement = cybersecurity_requirement

    def to_dict(self) -> dict:
        """
        将资产网络安全要求信息转换为字典格式

        Returns:
            dict: 包含资产网络安全要求信息的字典
        """
        return {
            "asset_id": self.asset_id,
            "asset_name": self.asset_name,
            "cybersecurity_requirement_id": self.cybersecurity_requirement_id,
            "csr_id": self.csr_id,
            "title": self.title,
            "sub_title": self.sub_title,
            "cybersecurity_requirement": self.cybersecurity_requirement,
        }

    def to_json(self) -> str:
        """
        将资产网络安全要求信息转换为JSON字符串

        Returns:
            str: JSON格式的资产网络安全要求信息
        """
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: dict) -> "AssetCSRInfo":
        """
        从字典创建资产网络安全要求信息对象

        Args:
            data: 包含资产网络安全要求信息的字典

        Returns:
            AssetCSRInfo: 资产网络安全要求信息对象
        """
        return cls(
            asset_id=data.get("asset_id"),
            asset_name=data.get("asset_name"),
            cybersecurity_requirement_id=data.get("cybersecurity_requirement_id"),
            csr_id=data.get("csr_id"),
            title=data.get("title"),
            sub_title=data.get("sub_title"),
            cybersecurity_requirement=data.get("cybersecurity_requirement"),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "AssetCSRInfo":
        """
        从JSON字符串创建资产网络安全要求信息对象

        Args:
            json_str: JSON格式的资产网络安全要求信息字符串

        Returns:
            AssetCSRInfo: 资产网络安全要求信息对象
        """
        data = json.loads(json_str)
        return cls.from_dict(data)

    def __str__(self) -> str:
        """
        返回资产网络安全要求信息的字符串表示

        Returns:
            str: 包含资产网络安全要求信息的字符串
        """
        return (
            f"AssetCSRInfo(\n"
            f"  asset_id: {self.asset_id}\n"
            f"  asset_name: {self.asset_name}\n"
            f"  cybersecurity_requirement_id: {self.cybersecurity_requirement_id}\n"
            f"  csr_id: {self.csr_id}\n"
            f"  title: {self.title}\n"
            f"  sub_title: {self.sub_title}\n"
            f"  cybersecurity_requirement: {self.cybersecurity_requirement}\n"
            f")"
        )

    def __repr__(self) -> str:
        """
        返回资产网络安全要求信息的正式字符串表示

        Returns:
            str: 资产网络安全要求信息的正式字符串表示
        """
        return self.__str__()

    def prepare_for_ai(self) -> str:
        """
        为AI模型准备资产网络安全要求信息

        Returns:
            str: 包含资产网络安全要求信息的字符串，用于AI模型输入
        """
        return self.to_json()

    def get_prompt(self) -> str:
        """
        获取资产网络安全要求信息的提示字符串

        Returns:
            str: 包含资产网络安全要求信息的提示字符串
        """
        return """
        请根据提供的asset_name, cybersecurity_requirement_id, cybersecurity_requirement信息，完成资产信息安全要求的归纳总结，然后将信息安全需求梳理成没有重复的几条独立的、具体的、可执行可验证的原子化的信息安全需求。
        1. 合并完全相同的重复条目。
        3. 如果两条目虽然相似但包含不同关键细节（如加密算法、具体接口、特定场景），请保留为两条或合理合并并补充说明。
        2. 将整理好的条目，拆解为多条简洁、具体、可验证的原子化要求（保留最严格、最详细的描述），每条对应一个csr_id
        4. 按照ISO 21434常用分类对最终结果进行分组（建议分类包括但不限于：访问控制、身份认证、数据加密、完整性保护、可用性保护、日志与监控、安全更新、物理保护等）。写入title与sub_title，如果某条不适合以上分类，可放在“其他”类。
        5. 每条整体出来的新的信息安全需求分配一个csr_id，并注明来自于哪些cybersecurity_requirement_id，如果有多个来源，用逗号隔开。
        返回的JSON格式示例为：'{"asset_cybersecurity_requirement_list":[{"asset_id":"资产ID","asset_name":"资产名称","cybersecurity_requirement_id":"网络安全要求ID","csr_id":"CSR ID","title":"要求标题","sub_title":"要求副标题","cybersecurity_requirement":"网络安全要求内容"},{"asset_id":"资产ID","asset_name":"资产名称","cybersecurity_requirement_id":"网络安全要求ID","csr_id":"CSR ID","title":"要求标题","sub_title":"要求副标题","cybersecurity_requirement":"网络安全要求内容"}，...]}'
        """

    @staticmethod
    def write_asset_csr_info_to_csv(
        asset_csr_info_list: list["AssetCSRInfo"], output_file: str
    ):
        """
        将资产网络安全要求信息列表写入CSV文件

        Args:
            asset_csr_info_list: 资产网络安全要求信息对象列表
            output_file: 输出的CSV文件路径
        """

        fieldnames = [
            "asset_id",
            "asset_name",
            "cybersecurity_requirement_id",
            "csr_id",
            "title",
            "sub_title",
            "cybersecurity_requirement",
        ]

        def generate_numerical_id(prefix: str, index: int) -> str:
            index = index + 1
            return f"{prefix}_{index:05d}"

        with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=";")
            writer.writeheader()
            # 修改csr_id属性为generate_numerical_id("CSR", index)
            for index, asset_csr_info in enumerate(asset_csr_info_list):
                # 替换原文中的";"为","
                asset_csr_info.asset_name = asset_csr_info.asset_name.replace(";", ",")
                asset_csr_info.title = asset_csr_info.title.replace(";", ",")
                asset_csr_info.sub_title = asset_csr_info.sub_title.replace(";", ",")
                asset_csr_info.cybersecurity_requirement = asset_csr_info.cybersecurity_requirement.replace(";", ",")

                asset_csr_info.csr_id = generate_numerical_id("CSR", index)
                writer.writerow(asset_csr_info.to_dict())
