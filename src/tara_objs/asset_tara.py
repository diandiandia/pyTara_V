"""
风险处理实施模块

这个模块定义了整合风险处理决策与网络安全控制需求的综合类，用于TARA分析中的风险处理实施阶段。
"""

import json
from typing import Optional, Dict, Any
from tara_objs.asset_threat_risk_treatment_decision import (
    AssetThreatRiskTreatmentDecision,
)
from tara_objs.cybersecurity_control_requirement import CybersecurityControlRequirement
import csv
from typing import List


class AssetTARAInfo:
    """
    风险处理实施类

    整合风险处理决策与网络安全控制需求，提供完整的风险处理实施框架

    属性:
    - risk_treatment_decision: 资产威胁风险处理决策对象
    - cybersecurity_controls: 网络安全控制与需求列表
    """

    def __init__(
        self,
        risk_treatment_decision: Optional[AssetThreatRiskTreatmentDecision] = None,
        cybersecurity_control: Optional[CybersecurityControlRequirement] = None,
    ):
        """
        初始化风险处理实施对象

        Args:
            risk_treatment_decision: 资产威胁风险处理决策对象
            cybersecurity_controls: 网络安全控制与需求列表
        """
        self.risk_treatment_decision = (
            risk_treatment_decision or AssetThreatRiskTreatmentDecision()
        )
        self.cybersecurity_control = cybersecurity_control

    def to_dict(self) -> Dict[str, Any]:
        """
        将风险处理实施信息转换为字典格式

        Returns:
            Dict[str, Any]: 包含风险处理实施信息的字典
        """
        return {
            "risk_treatment_decision": self.risk_treatment_decision.to_dict(),
            "cybersecurity_control": self.cybersecurity_control.to_dict(),
        }

    def to_json(self) -> str:
        """
        将风险处理实施信息转换为JSON字符串

        Returns:
            str: 包含风险处理实施信息的JSON字符串
        """
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    def __str__(self) -> str:
        """
        返回风险处理实施的字符串表示

        Returns:
            str: 格式化的风险处理实施信息
        """
        info = "Asset TARA Info:\n"
        info += str(self.risk_treatment_decision) + "\n"
        info += str(self.cybersecurity_control) + "\n"

        return info

    def prepare_for_ai(self) -> str:
        """
        准备风险处理实施信息，用于AI模型输入

        Returns:
            str: 格式化的风险处理实施信息
        """
        return json.dumps(self.to_dict(), ensure_ascii=False)

    def get_prompt(self) -> str:
        """
        获取风险处理实施的提示信息

        Returns:
            str: 格式化的风险处理实施提示信息
        """
        return """
        资产信息：根据资产的asset_id,asset_name, assigned_security_attribute, damage_scenario,threat_scenario,attack_path,attack_feasibility_rating,cybersecurity_goal信息，考虑编写信息安全目标cybersecurity_goal信息，编写规则：
        1. 每条必须以 “防止未授权……” 或 “将未授权……的影响限制在……” 开头（必须用“防止”或“将…限制在”）
        2. 必须明确指出“谁”对“哪个具体资产/功能”做了“什么坏事”
        3. 必须出现“未授权”或“恶意”字样
        4. 绝对不能出现任何技术实现手段（不能出现加密、签名、HSM、TLS、安全启动、防火墙、MAC、认证、检测、监控、审计等任何技术词）
        5. 绝对禁止用“保证、确保、实现、保护、提供、支持、检测、识别”等动词
        6. 如果完全防止不了，必须用“将……的影响限制在不影响安全相关功能”或“限制在……范围内”
        7. 每条都必须是否定形式（写不想发生的事）
        8. 每条后面要能直接挂TARA中的威胁场景编号
        根据cybersecurity_goal，确认是否分配给device，例如分配给了OEM OTA服务器，那这个cybersecurity_goal就是和device不相关，allocated_to_device为No，否则为Yes。
        如果allocated_to_device为yes,根据cybersecurity_control描述，编写cybersecurity_requirement信息，cybersecurity_requirement的编写要求：
        1. 每条必须用“必须……”或“应当……”开头，结尾用“，以实现XX网络安全目标”
        2. 必须使用“shall”对应的中文强制词：必须 / 应当（禁止“应”“宜”“建议”“推荐”）
        3. 每条必须100%可验证（必须包含具体技术实现方式，使用什么协议、使用什么算法、界面描述、物理条件等可测项）
        4. 必须明确区分并标注【部件要求】或【运行环境要求】
        5. 必须明确可以追溯到cybersecurity_goal
        6. 运行环境要求必须明确由谁实现（云后台/T-Box/诊断仪/HMI/网关等）
        7. 加密算法必须写明具体算法名称
        8. 涉及用户同意的必须明确交互方式（如“长按确认键≥3秒”）
        返回格式：{"cybersecurity_control_id":"CSO-001", "cybersecurity_control":"通过移除危险源，停止相关安全开发活动来避免风险发生", "allocated_to_device":"yes", "cybersecurity_requirement_id":"CSR-001", "cybersecurity_requirement":"确保资产的安全开发活动得到适当的支持和监控"}
        """

    @staticmethod
    def write_assets_to_csv(assets: List["AssetTARAInfo"], output_file: str):
        """
        将资产安全信息列表写入CSV文件

        Args:
            assets: 资产安全信息对象列表，按照选择的列名写入CSV文件
            output_file: 输出CSV文件路径
        """
        fieldnames = [
            "asset_id",
            "asset_name",
            "assigned_security_attribute",
            "damage_scenario_id",
            "damage_scenario",
            "safety",
            "financial",
            "operational",
            "privacy",
            "impact_level",
            "threat_scenario_id",
            "threat_scenario",
            "attack_path",
            "time_consuming",
            "expertise",
            "knowledge_about_toe",
            "window_of_opportunity",
            "equipment",
            "difficulty",
            "attack_feasibility_rating",
            "cal_level",
            "risk_value",
            "risk_treatment",
            "item_change",
            "cybersecurity_claim_id",
            "cybersecurity_claim",
            "cybersecurity_goal_id",
            "cybersecurity_goal",
            "cybersecurity_control_id",
            "cybersecurity_control",
            "allocated_to_device",
            "cybersecurity_requirement_id",
            "cybersecurity_requirement",
        ]

        with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for asset in assets:
                # 创建一个空的行字典
                row = {}

                # 从嵌套结构中提取数据
                risk_decision = asset.risk_treatment_decision
                if risk_decision:
                    # 从asset_info_damage_scenario_threat_scenario提取数据
                    scenario = risk_decision.asset_info_damage_scenario_threat_scenario
                    if scenario:
                        # 资产信息
                        if hasattr(
                            scenario, "asset_info_attribute_damage_impact"
                        ) and hasattr(
                            scenario.asset_info_attribute_damage_impact,
                            "asset_cybersecurity_attribute",
                        ):
                            asset_attr = (
                                scenario.asset_info_attribute_damage_impact.asset_cybersecurity_attribute
                            )
                            if asset_attr:
                                row["asset_id"] = getattr(asset_attr, "asset_id", "")
                                row["asset_name"] = getattr(
                                    asset_attr, "asset_name", ""
                                )
                                row["assigned_security_attribute"] = getattr(
                                    asset_attr, "assigned_security_attribute", ""
                                )

                        # 损害场景信息
                        if hasattr(
                            scenario, "asset_info_attribute_damage_impact"
                        ) and hasattr(
                            scenario.asset_info_attribute_damage_impact,
                            "damage_scenario_impact_level",
                        ):
                            damage_impact = (
                                scenario.asset_info_attribute_damage_impact.damage_scenario_impact_level
                            )
                            if damage_impact:
                                row["damage_scenario_id"] = getattr(
                                    damage_impact, "damage_scenario_id", ""
                                )
                                row["damage_scenario"] = getattr(
                                    damage_impact, "damage_scenario", ""
                                )
                                row["safety"] = getattr(damage_impact, "safety", "")
                                row["financial"] = getattr(
                                    damage_impact, "financial", ""
                                )
                                row["operational"] = getattr(
                                    damage_impact, "operational", ""
                                )
                                row["privacy"] = getattr(damage_impact, "privacy", "")
                                row["impact_level"] = getattr(
                                    damage_impact, "impact_level", ""
                                )

                        # 威胁场景信息
                        if hasattr(scenario, "threat_scenario_attack_feasibility"):
                            threat_feasibility = (
                                scenario.threat_scenario_attack_feasibility
                            )
                            if threat_feasibility:
                                row["threat_scenario_id"] = getattr(
                                    threat_feasibility, "threat_scenario_id", ""
                                )
                                row["threat_scenario"] = getattr(
                                    threat_feasibility, "threat_scenario", ""
                                )
                                row["attack_path"] = getattr(
                                    threat_feasibility, "attack_path", ""
                                )
                                row["time_consuming"] = getattr(
                                    threat_feasibility, "time_consuming", ""
                                )
                                row["expertise"] = getattr(
                                    threat_feasibility, "expertise", ""
                                )
                                row["knowledge_about_toe"] = getattr(
                                    threat_feasibility, "knowledge_about_toe", ""
                                )
                                row["window_of_opportunity"] = getattr(
                                    threat_feasibility, "window_of_opportunity", ""
                                )
                                row["equipment"] = getattr(
                                    threat_feasibility, "equipment", ""
                                )

                                # 获取difficulty（可能是属性或方法）
                                if hasattr(threat_feasibility, "difficulty"):
                                    difficulty = getattr(
                                        threat_feasibility, "difficulty"
                                    )
                                    row["difficulty"] = (
                                        difficulty()
                                        if callable(difficulty)
                                        else difficulty
                                    )

                                # 获取attack_feasibility_rating
                                feasibility_rating = getattr(
                                    threat_feasibility,
                                    "attack_feasibility_rating",
                                    None,
                                )
                                row["attack_feasibility_rating"] = (
                                    getattr(feasibility_rating, "value", "")
                                    if feasibility_rating
                                    else ""
                                )

                                # 计算风险值
                                if hasattr(risk_decision, "calculate_risk_value"):
                                    row["risk_value"] = (
                                        risk_decision.calculate_risk_value()
                                    )

                    # 风险处理信息
                    if hasattr(risk_decision, "risk_treatment"):
                        treatment = risk_decision.risk_treatment
                        if treatment:
                            row["risk_treatment"] = (
                                getattr(treatment.risk_treatment, "value", "")
                                if hasattr(treatment, "risk_treatment") and treatment.risk_treatment else ""
                            )
                            row["item_change"] = getattr(treatment, "item_change", "")
                            row["cybersecurity_claim_id"] = getattr(
                                treatment, "cybersecurity_claim_id", ""
                            )
                            row["cybersecurity_claim"] = getattr(
                                treatment, "cybersecurity_claim", ""
                            )
                            row["cybersecurity_goal_id"] = getattr(
                                treatment, "cybersecurity_goal_id", ""
                            )
                            row["cybersecurity_goal"] = getattr(
                                treatment, "cybersecurity_goal", ""
                            )

                # 网络安全控制信息
                if (
                    hasattr(asset, "cybersecurity_control") and asset.cybersecurity_control
                ):
                    control = asset.cybersecurity_control
                    row["cybersecurity_control_id"] = getattr(
                        control, "cybersecurity_control_id", ""
                    )
                    row["cybersecurity_control"] = getattr(
                        control, "cybersecurity_control", ""
                    )
                    row["allocated_to_device"] = getattr(
                        control, "allocated_to_device", ""
                    )
                    row["cybersecurity_requirement_id"] = getattr(
                        control, "cybersecurity_requirement_id", ""
                    )
                    row["cybersecurity_requirement"] = getattr(
                        control, "cybersecurity_requirement", ""
                    )

                # 为缺失的字段设置空字符串，确保CSV格式一致
                for field in fieldnames:
                    if field not in row:
                        row[field] = ""

                writer.writerow(row)
