"""
ISO21434资产类模块

这个模块定义了符合ISO21434标准的资产类，用于TARA（威胁分析和风险评估）过程中的资产管理。
"""

from enum import Enum
import pandas as pd
import json  # 确保导入了json模块
from typing import List


class AssetType(Enum):
    """
    资产类型枚举类，定义了ISO21434标准中的资产类型
    """

    HARDWARE = "Hardware"
    SOFTWARE = "Software"
    DATA = "Data"
    COMMUNICATION = "Communication"


class AssetInfo:
    """
    ISO21434资产类，用于存储和管理符合ISO21434标准的资产信息

    属性:
    - asset_id: 资产编号
    - asset_name: 资产名称
    - communication_protocol: 通讯协议（使用何种协议进行通讯）
    - asset_type: 资产类型（硬件，软件，数据，通讯）
    - remarks: 备注（对资产信息安全关注点的补充）
    """

    def __init__(
        self,
        asset_id: str = "",
        asset_name: str = "",
        communication_protocol: str = "",
        asset_type: AssetType = AssetType.HARDWARE,
        remarks: str = "",
    ):
        """
        初始化ISO21434资产对象

        Args:
            asset_id (str): 资产编号
            asset_name (str): 资产名称
            communication_protocol (str): 通讯协议
            asset_type (AssetType): 资产类型，默认为硬件
            remarks (str): 备注信息
        """
        self.asset_id = asset_id
        self.asset_name = asset_name
        self.communication_protocol = communication_protocol
        self.asset_type = asset_type
        self.remarks = remarks

    def __str__(self) -> str:
        """
        返回资产信息的字符串表示

        Returns:
            str: 格式化的资产信息字符串
        """
        info = "Asset Information:\n"
        info += f"Asset ID: {self.asset_id}\n"
        info += f"Asset Name: {self.asset_name}\n"
        info += f"Communication Protocol: {self.communication_protocol}\n"
        info += f"Asset Type: {self.asset_type.value}\n"
        info += f"Remarks: {self.remarks}\n"
        return info

    def to_dict(self) -> dict:
        """
        将资产信息转换为字典格式

        Returns:
            dict: 包含资产信息的字典
        """
        return {
            "asset_id": self.asset_id,
            "asset_name": self.asset_name,
            "communication_protocol": self.communication_protocol,
            "asset_type": self.asset_type.value,
            "remarks": self.remarks,
        }

    def validate(self) -> tuple[bool, str]:
        """
        验证资产信息的有效性

        Returns:
            tuple[bool, str]: (是否有效, 错误信息)
        """
        if not self.asset_id:
            return False, "资产编号不能为空"
        if not self.asset_name:
            return False, "资产名称不能为空"
        if not isinstance(self.asset_type, AssetType):
            return False, "资产类型必须是AssetType枚举类型"
        return True, ""

    def update_remarks(self, new_remarks: str) -> None:
        """
        更新资产的备注信息

        Args:
            new_remarks (str): 新的备注信息
        """
        self.remarks = new_remarks

    def get_asset_type_display(self) -> str:
        """
        获取资产类型的显示名称

        Returns:
            str: 资产类型的中文名称
        """
        return self.asset_type.value

    @staticmethod
    def read_assets_from_excel(
        excel_path: str, sheet_name: str = "Assets"
    ) -> List["AssetInfo"]:
        """
        从Excel文件的指定表中读取资产信息并生成AssetInfo对象列表（简化版）

        Args:
            excel_path (str): Excel文件路径
            sheet_name (str): 表名，默认为'Assets'

        Returns:
            List[AssetInfo]: AssetInfo对象列表
        """
        # 读取Excel文件
        df = pd.read_excel(excel_path, sheet_name=sheet_name)
        columns = {
            "资产编号": "asset_id",
            "资产名称": "asset_name",
            "资产类型": "asset_type",
            "通讯协议": "communication_protocol",
            "备注": "remarks",
        }

        # 方案1：使用模糊匹配和标准化处理列名
        df.columns = [col.strip() for col in df.columns]  # 去除列名前后空格

        df.rename(columns=columns, inplace=True)

        # 初始化资产列表
        assets = []

        # 遍历每一行创建AssetInfo对象
        for _, row in df.iterrows():
            # 获取字段值，空值转为空字符串
            asset_id = str(row.get("asset_id", "")).strip()
            asset_name = str(row.get("asset_name", "")).strip()
            asset_type_str = str(row.get("asset_type", "")).strip()
            # 支持两种列名：communication_protocol 或 protocol
            if "communication_protocol" in df.columns:
                communication_protocol = str(
                    row.get("communication_protocol", "")
                ).strip()
            else:
                communication_protocol = str(row.get("protocol", "")).strip()
            remarks = str(row.get("remarks", "")).strip()

            # 跳过无效数据
            if not asset_id or not asset_name:
                continue

            # 将asset_type字符串转换为枚举类型（默认Hardware）
            asset_type = AssetType.HARDWARE
            for at in AssetType:
                if at.value == asset_type_str:
                    asset_type = at
                    break

            # 创建并添加资产对象
            assets.append(
                AssetInfo(
                    asset_id=asset_id,
                    asset_name=asset_name,
                    communication_protocol=communication_protocol,
                    asset_type=asset_type,
                    remarks=remarks,
                )
            )

        return assets

    def prepare_for_ai(self) -> str:
        # 将字典转换为JSON字符串
        return json.dumps(self.to_dict(), ensure_ascii=False)

    def get_prompt(self) -> str:
        return (
            "请根据以上资产asset_id, asset_name, asset_type, communication_protocol, remarks，"
            "评估资产是否应该被赋于以下安全属性："
            "Authenticity, Integrity, Non-repudiation, Confidentiality, Availability, Authorization, Privacy。"
            "评分标准如下：0表示不相关，5表示高度相关。"
            "返回JSON结果示例："
            "{"
            '    "Authenticity": 4,'
            '    "Integrity": 3,'
            '    "Non-repudiation": 1,'
            '    "Confidentiality": 1,'
            '    "Availability": 1,'
            '    "Authorization": 1,'
            '    "Privacy": 5'
            "}"
        )
