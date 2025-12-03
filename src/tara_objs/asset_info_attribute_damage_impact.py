"""
资产综合分析模块

这个模块定义了TARA分析中的资产综合分析类，整合了资产基本信息、网络安全属性和损害场景影响级别。
"""

import json
from tara_objs.asset_info_cybersecurity_attribute import AssetInfoCybersecurityAttribute
from tara_objs.damage_scenario_impact_level import DamageScenarioImpactLevel


class AssetInfoAttributeDamageImpact:
    """
    资产综合分析类，整合资产信息、网络安全属性和损害场景影响级别

    属性:
    - asset_info: 资产信息对象
    - asset_cybersecurity_attribute: 资产网络安全属性对象
    - damage_scenario_impact_level: 损害场景影响级别对象
    """

    def __init__(
        self,
        asset_info_attribute: AssetInfoCybersecurityAttribute = None,
        damage_scenario_impact_level: DamageScenarioImpactLevel = None,
    ):
        """
        初始化资产综合分析对象

        Args:
            asset_info_attribute: 资产信息安全属性对象
            damage_scenario_impact_level: 损害场景影响级别对象
        """
        self.asset_info_attribute = (
            asset_info_attribute
            if asset_info_attribute
            else AssetInfoCybersecurityAttribute()
        )
        self.damage_scenario_impact_level = (
            damage_scenario_impact_level
            if damage_scenario_impact_level
            else DamageScenarioImpactLevel()
        )

    def __str__(self) -> str:
        """
        返回资产综合分析的字符串表示

        Returns:
            str: 格式化的资产综合分析信息
        """
        info = (
            "Asset info, cybersecurity attribute, damage scenario and impact level:\n"
        )
        info += str(self.asset_info_attribute) + "\n"
        info += str(self.damage_scenario_impact_level) + "\n"
        return info

    def to_dict(self) -> dict:
        """
        将资产综合分析信息转换为字典格式

        Returns:
            dict: 包含资产综合分析信息的字典
        """
        return {
            "asset_info_attribute": self.asset_info_attribute.to_dict(),
            "damage_scenario_impact_level": self.damage_scenario_impact_level.to_dict(),
        }

    def to_json(self) -> str:
        """
        将资产综合分析信息转换为JSON字符串

        Returns:
            str: JSON格式的资产综合分析信息
        """
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    def prepare_for_ai(self) -> str:
        """
        准备资产综合分析信息，用于AI模型输入

        Returns:
            str: 格式化的资产综合分析信息，用于AI模型输入
        """
        return json.dumps(self.to_dict(), ensure_ascii=False)

    def get_prompt(self) -> str:
        """
        获取资产综合分析提示字符串，用于AI模型输入

        Returns:
            str: 格式化的资产综合分析提示字符串，用于AI模型输入
        """
        return """
        资产损坏场景严重性评估提示：
        资产信息：根据资产的asset_id,asset_name, assigned_security_attribute, damage_scenario信息，对资产的损害场景进行从safety,financial,operational, privacy四个方面进行评估。
        评估指标：
        - safety: 车内或者车外人员的安全性，可选Negligible, Moderate, Major, Severe。
        - financial: 车辆所有者，路人的资产价值损失，可选Negligible, Moderate, Major, Severe。
        - operational: 车辆的可操作性，可选Negligible, Moderate, Major, Severe。
        - privacy: 对个人数据的泄露和隐私侵犯的影响，可选Negligible, Moderate, Major, Severe。
        返回JSON格式：{"possible_damage_scenario_impact_level":{"safety":"Negligible", "financial":"Moderate", "operational":"Major", "privacy":"Severe"}}
        """

    def get_prompt2(self) -> str:
        """
        获取资产综合分析提示字符串，用于AI模型输入

        Returns:
            str: 格式化的资产信息与资产损害场景影响级别提示字符串，用于AI模型输入
        """
        return """
        资产信息与资产损害场景影响级别提示：
        资产信息：根据资产的asset_id,asset_name, assigned_security_attribute, damage_scenario,safety,financial,operational, privacy信息，分析可能存在的威胁场景信息，
        返回JSON格式：{"possible_threat_scenario_list":[{"threat_scenario_1":"threat_scenario_discription_1"},{"threat_scenario_2":"threat_scenario_discription_2"}]}
        """
