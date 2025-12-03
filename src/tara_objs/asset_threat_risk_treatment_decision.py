"""
资产威胁风险处理决策模块

这个模块定义了整合资产威胁场景与风险处理决策的综合类，用于TARA分析中的风险评估和处理决策。
"""

from typing import Optional, Dict, Any, Union
from tara_objs.asset_info_damage_scenario_threat_scenario import (
    AssetInfoDamageScenarioThreatScenario,
)
from tara_objs.risk_treatment_decision import RiskTreatmentDecision
import json
from tara_objs.damage_scenario_impact_level import SeverityLevel


class AssetThreatRiskTreatmentDecision:
    """
    资产威胁风险处理决策类

    整合资产威胁场景信息与风险处理决策，提供完整的风险评估和处理框架

    属性:
    - asset_info_damage_scenario_threat_scenario: 资产信息损害场景威胁场景对象
    - risk_treatment: 风险处理选项
    """

    def __init__(
        self,
        asset_info_damage_scenario_threat_scenario: Optional[
            AssetInfoDamageScenarioThreatScenario
        ] = None,
        risk_treatment: Optional[Union[str, RiskTreatmentDecision]] = None,
    ):
        """
        初始化资产威胁风险处理决策对象

        Args:
            asset_info_damage_scenario_threat_scenario: 资产信息损害场景威胁场景对象
            risk_treatment: 风险处理选项（字符串或枚举实例）
        """
        self.asset_info_damage_scenario_threat_scenario = asset_info_damage_scenario_threat_scenario or AssetInfoDamageScenarioThreatScenario()
        self.risk_treatment = risk_treatment

    def calculate_risk_value(self) -> int:
        """
        计算综合风险级别

        根据损害影响级别和攻击可行性计算风险级别

        Returns:
            str: 风险级别 (Very Low, Low, Medium, High, Very High)
        """
        # 获取损害场景影响级别
        impact_level = (
            self.asset_info_damage_scenario_threat_scenario.asset_info_attribute_damage_impact.damage_scenario_impact_level.impact_level
        )

        # 获取攻击可行性评级
        feasibility_rating = (
            self.asset_info_damage_scenario_threat_scenario.threat_scenario_attack_feasibility.attack_feasibility_rating
        )

        # 如果未设置，先更新攻击可行性评级
        if not feasibility_rating:
            self.asset_info_damage_scenario_threat_scenario.threat_scenario_attack_feasibility.calculate_attack_feasibility_rating(
                self.asset_info_damage_scenario_threat_scenario
            )
            feasibility_rating = (
                self.asset_info_damage_scenario_threat_scenario.threat_scenario_attack_feasibility.attack_feasibility_rating
            )

        # 风险矩阵映射
        # 行: attack feasibility rating: verylow,low,medium,high
        # 列: damage scenario impact level:severe,major,moderate,negligible
        risk_matrix = [[2, 3, 4, 5], [1, 2, 3, 4], [1, 2, 2, 3], [1, 1, 1, 1]]

        # 获取索引
        impact_index = 0
        if impact_level:
            impact_values = [SeverityLevel.SEVERE, SeverityLevel.MAJOR, SeverityLevel.MODERATE, SeverityLevel.NEGLIGIBLE]
            if impact_level in impact_values:
                impact_index = impact_values.index(impact_level)

        feasibility_index = 0
        if feasibility_rating:
            feasibility_values = ["verylow", "low", "medium", "high"]
            feasibility_value = feasibility_rating.value
            if feasibility_value in feasibility_values:
                feasibility_index = feasibility_values.index(feasibility_value)

        self.risk_treatment.risk_value = risk_matrix[impact_index][feasibility_index]

    def to_dict(self) -> Dict[str, Any]:
        """
        将资产威胁风险处理决策信息转换为字典格式

        Returns:
            Dict[str, Any]: 包含资产威胁风险处理决策信息的字典
        """
        return {
            "asset_info_damage_scenario_threat_scenario": self.asset_info_damage_scenario_threat_scenario.to_dict(),
            "risk_treatment": (
                self.risk_treatment.to_dict() if self.risk_treatment else None
            ),
        }

    def __str__(self) -> str:
        """
        返回资产威胁风险处理决策的字符串表示

        Returns:
            str: 格式化的资产威胁风险处理决策信息
        """
        info = "Asset Info Damage Scenario Threat Scenario:\n"
        info += str(self.asset_info_damage_scenario_threat_scenario) + "\n"
        info += f"risk treatment decision: {self.risk_treatment}\n"
        return info

    def prepare_for_ai(self) -> str:
        """
        准备资产威胁风险处理决策信息，用于AI模型输入

        Returns:
            str: JSON格式的资产威胁风险处理决策信息，适用于AI模型输入
        """
        return json.dumps(self.to_dict(), ensure_ascii=False)

    def get_prompt(self) -> str:
        """
        获取资产威胁风险处理决策的提示信息

        Returns:
            str: 包含资产威胁风险处理决策信息的提示字符串
        """
        return """
        资产信息：根据资产的asset_id,asset_name, assigned_security_attribute, damage_scenario,threat_scenario,attack_path,attack_feasibility_rating信息，考虑对资产信息安全处理决策，
        风险处理选项包括：avoid（主动放弃或者修改系统设计，避免damage scenario和threat scenario的发生）, reduce（采取信息安全管控措施，减少风险发生）, share（考虑风险可以分配给其他车辆组件，例如某个安全控制措施可以在tbox实施，从而减少自己所涉及的设备的安全风险，或者采用购买保险的方式）, retain（风险的影响很小，是可以接受的）
        风险处理risk_treatment一旦确定后，需要提供相关理由：
        如果选择avoid，需要提供item_change的相关信息，如：通过移除危险源，停止相关安全开发活动来避免风险发生。
        如果选择reduce，需要提供cybersecurity_goal的相关信息，如：通过采用加密技术，确保数据在传输和存储过程中的安全性。
        如果选择share/retain，需要提供cybersecurity_claim的相关信息，如：供应商开发相关组件或者通过购买保险， cover 资产的安全风险。
        返回JSON格式：{"risk_treatment":"Avoid","item_change":"通过移除危险源，停止相关安全开发活动来避免风险发生", "cybersecurity_goal":"","cybersecurity_claim":""}
        """
