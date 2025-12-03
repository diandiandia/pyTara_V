"""
资产威胁影响综合分析模块

这个模块定义了TARA分析中的资产威胁影响综合分析类，整合了资产信息、网络安全属性、损害场景影响级别和威胁场景攻击可行性。
"""

import json
from typing import Optional, Dict, Any
from tara_objs.asset_info_attribute_damage_impact import AssetInfoAttributeDamageImpact
from tara_objs.threat_scenario_attack_feasibility import ThreatScenarioAttackFeasibility


class AssetInfoDamageScenarioThreatScenario:
    """
    资产信息损害场景威胁场景综合分析类，整合资产信息、网络安全属性、损害场景影响级别和威胁场景攻击可行性

    属性:
    - asset_info_attribute_damage_impact: 资产信息属性损害影响对象
    - threat_scenario_attack_feasibility: 威胁场景攻击可行性对象
    """

    def __init__(
        self,
        asset_info_attribute_damage_impact: Optional[
            AssetInfoAttributeDamageImpact
        ] = None,
        threat_scenario_attack_feasibility: Optional[
            ThreatScenarioAttackFeasibility
        ] = None,
    ):
        """
        初始化资产威胁影响综合分析对象

        Args:
            asset_info_attribute_damage_impact: 资产信息属性损害影响对象
            threat_scenario_attack_feasibility: 威胁场景攻击可行性对象
        """
        self.asset_info_attribute_damage_impact = (
            asset_info_attribute_damage_impact
            if asset_info_attribute_damage_impact
            else AssetInfoAttributeDamageImpact()
        )
        self.threat_scenario_attack_feasibility = (
            threat_scenario_attack_feasibility
            if threat_scenario_attack_feasibility
            else ThreatScenarioAttackFeasibility(
                threat_id="", threat_scenario="", attack_path=""
            )
        )

    def __str__(self) -> str:
        """
        返回资产威胁影响综合分析的字符串表示

        Returns:
            str: 格式化的资产威胁影响综合分析信息
        """
        info = "Asset Info Damage Scenario Threat Scenario Analysis:\n"
        info += str(self.asset_info_attribute_damage_impact) + "\n"
        info += "Threat Scenario Attack Feasibility:\n"
        info += str(self.threat_scenario_attack_feasibility) + "\n"
        return info

    def to_dict(self) -> Dict[str, Any]:
        """
        将资产威胁影响综合分析信息转换为字典格式

        Returns:
            Dict[str, Any]: 包含资产威胁影响综合分析信息的字典
        """
        return {
            "asset_info_attribute_damage_impact": self.asset_info_attribute_damage_impact.to_dict(),
            "threat_scenario_attack_feasibility": self.threat_scenario_attack_feasibility.to_dict(),
        }

    def prepare_for_ai(self) -> str:
        """
        准备资产威胁影响综合分析信息，用于AI模型输入

        Returns:
            str: 格式化的资产威胁影响综合分析信息，用于AI模型输入
        """
        return json.dumps(self.to_dict(), ensure_ascii=False)

    def get_prompt(self) -> str:
        """
        获取为AI模型准备的提示字符串

        Returns:
            str: 要求ai按照time_consuming/expertise/knowledge_about_toe/window_of_opportunity/equipment评估攻击路径的可行性
        """
        return """
        请根据time_consuming/expertise/knowledge_about_toe/window_of_opportunity/equipment评估攻击路径的可行性，
        time_consuming可选：no_more_than_1d(小于等于1天)，no_more_than_1w(小于等于1周)，no_more_than_1m(小于等于1月)，no_more_than_6m(小于等于6个月)，more_than_6m(大于6个月)
        expertise可选：layman(普通用户)，proficient(专业用户)，expert(专家用户)，multiple expert(多个专家用户)
        knowledge_about_toe可选：public(公开)，restricted(受限)，confidential(机密)，strictly confidential(严格机密)
        window_of_opportunity可选：unlimited(无时间限制)，easy(容易)，moderate(中等)，difficult(困难)
        equipment可选：standard(标准设备)，specialized(专业设备)，bespoke(定制设备)，multiple bespoke(多个定制设备)
        返回的json数据结构为：{"time_consuming":"no_more_than_1d", "expertise":"layman", "knowledge_about_toe":"public", "window_of_opportunity":"unlimited", "equipment":"standard"}
        """
