"""
资产安全属性分析模块

这个模块定义了符合ISO21434标准的资产安全属性分析类，用于TARA（威胁分析和风险评估）过程中
对资产进行安全属性分析，为每个资产分配安全属性。
"""

from enum import Enum
from tara_objs.asset_info import AssetInfo
import json
from typing import Optional, Union


class CybersecurityAttribute(Enum):
    """
    网络安全属性枚举类，定义了ISO21434标准中的关键安全属性
    """

    AUTHENTICITY = "Authenticity"  # 真实性
    INTEGRITY = "Integrity"  # 完整性
    NON_REPUDIATION = "Non-repudiation"  # 不可否认性
    CONFIDENTIALITY = "Confidentiality"  # 机密性
    AVAILABILITY = "Availability"  # 可用性
    AUTHORIZATION = "Authorization"  # 授权
    PRIVACY = "Privacy"  # 隐私

    @classmethod
    def from_string(cls, value: str) -> Optional["CybersecurityAttribute"]:
        """从字符串创建枚举实例"""
        for attribute in cls:
            if attribute.value.lower() == value.lower():
                return attribute
        return None


class AssetInfoCybersecurityAttribute:
    """
    资产安全属性分析类，用于存储和管理资产的安全属性分析结果

    属性:
    - asset_info: 资产信息对象
    - assigned_security_attribute: 分配给资产的主要安全属性
    """

    def __init__(
        self,
        asset_info: AssetInfo,
        assigned_security_attribute: CybersecurityAttribute = None,
    ):
        """
        初始化资产安全属性分析对象

        Args:
            asset_info (AssetInfo): 资产信息对象
            assigned_security_attribute (CybersecurityAttribute): 分配给资产的主要安全属性
        """
        self.asset_info = asset_info
        self.assigned_security_attribute = assigned_security_attribute

    def assign_security_attribute(self, attribute: str) -> None:
        """
        为资产分配安全属性

        Args:
            attribute (CybersecurityAttribute): 要分配的安全属性
        """
        self.assigned_security_attribute = self._parse_enum(
            attribute, CybersecurityAttribute
        )

    def _parse_enum(
        self, value: Optional[Union[str, Enum]], enum_class: type
    ) -> Optional[Enum]:
        """解析枚举类型，支持字符串或枚举实例输入"""
        if value is None:
            return None
        if isinstance(value, str):
            parsed = enum_class.from_string(value)
            if parsed is None:
                valid_values = [e.value for e in enum_class]
                raise ValueError(
                    f"Invalid value '{value}' for {enum_class.__name__}. Valid values: {valid_values}"
                )
            return parsed
        if isinstance(value, enum_class):
            return value
        raise TypeError(
            f"Expected str or {enum_class.__name__}, got {type(value).__name__}"
        )

    def to_dict(self) -> dict:
        """
        将资产安全属性分析结果转换为字典格式

        Returns:
            dict: 包含资产安全属性分析信息的字典
        """
        return {
            "asset_info": self.asset_info.to_dict(),
            "assigned_security_attribute": (
                self.assigned_security_attribute.value
                if self.assigned_security_attribute
                else None
            ),
        }

    def to_dict01(self) -> dict:
        """
        将资产安全属性分析结果转换为字典格式

        Returns:
            dict: 包含资产安全属性分析信息的字典
        """
        return {
            "asset_id": self.asset_info.asset_id,
            "asset_name": self.asset_info.asset_name,
            "assigned_security_attribute": (
                self.assigned_security_attribute.value
                if self.assigned_security_attribute
                else None
            ),
        }

    def __str__(self) -> str:
        """
        返回资产安全属性分析的字符串表示
        Returns:
            str: 格式化的资产安全属性分析字符串
        """
        info = "Asset Security Analysis:\n"
        info += f"Asset: {self.asset_info}\n"
        info += f"Assigned Security Attribute: {self.assigned_security_attribute.value if self.assigned_security_attribute else 'Not assigned'}\n"

        return info

    def prepare_for_ai(self) -> str:
        """
        为AI模型准备资产安全属性分析的输入字符串

        Returns:
            str: 格式化的资产安全属性分析字符串，用于AI模型输入
        """
        return json.dumps(self.to_dict(), ensure_ascii=False)

    def get_prompt(self) -> str:
        """
        获取资产安全属性分析的提示字符串

        Returns:
            str: 格式化的资产安全属性分析提示字符串，用于AI模型输入
        """
        return """
        资产损坏场景分析提示：
        资产信息：根据资产的asset_id,asset_name, assigned_security_attribute信息，请分析资产可能遭受的损害场景有几个，然后生成这些可能的损害场景。
        返回JSON格式：{"possible_damage_scenario_info":{"damage_scenario_1":"资产被未授权用户访问", "damage_scenario_2":"资产数据被篡改"}}
        """
