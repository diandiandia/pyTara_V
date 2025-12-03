"""
TARA资产信息整合模块

这个模块定义了整合所有TARA相关信息的类，包括资产信息、安全属性、损害场景、威胁场景、风险处理决策和网络安全控制需求。
"""

from typing import Optional, List
import json
from tara_objs.asset_info_cybersecurity_attribute import AssetInfoCybersecurityAttribute
from tara_objs.damage_scenario_impact_level import DamageScenarioImpactLevel
from tara_objs.threat_scenario_attack_feasibility import ThreatScenarioAttackFeasibility
from tara_objs.risk_treatment_decision import RiskTreatmentDecision
from tara_objs.cybersecurity_control_requirement import CybersecurityControlRequirement
import csv


class AssetTaraInfo:
    """
    TARA资产信息整合类

    整合了资产的完整TARA分析信息，包括资产基本信息、安全属性、损害场景、威胁场景、风险处理决策和网络安全控制需求。
    """

    def __init__(
        self,
        asset_cybersecurity_attribute: Optional[AssetInfoCybersecurityAttribute] = None,
        damage_scenario_impact_level: Optional[DamageScenarioImpactLevel] = None,
        threat_scenario_attack_feasibility: Optional[
            ThreatScenarioAttackFeasibility
        ] = None,
        risk_treatment_decision: Optional[RiskTreatmentDecision] = None,
        cybersecurity_control_requirement: Optional[
            CybersecurityControlRequirement
        ] = None,
    ):
        """
        初始化TARA资产信息整合对象

        Args:
            asset_cybersecurity_attribute: 资产安全属性信息
            damage_scenario_impact_level: 损害场景影响级别
            threat_scenario_attack_feasibility: 威胁场景攻击可行性
            risk_treatment_decision: 风险处理决策
            cybersecurity_control_requirement: 网络安全控制需求列表
        """
        self.asset_cybersecurity_attribute = asset_cybersecurity_attribute
        self.damage_scenario_impact_level = damage_scenario_impact_level
        self.threat_scenario_attack_feasibility = threat_scenario_attack_feasibility
        self.risk_treatment_decision = risk_treatment_decision
        self.cybersecurity_control_requirement = cybersecurity_control_requirement

    def set_asset_cybersecurity_attribute(
        self, attribute: AssetInfoCybersecurityAttribute
    ) -> None:
        """
        设置资产安全属性信息

        Args:
            attribute: 资产安全属性对象
        """
        self.asset_cybersecurity_attribute = attribute

    def set_damage_scenario(self, scenario: DamageScenarioImpactLevel) -> None:
        """
        设置损害场景影响级别

        Args:
            scenario: 损害场景影响级别对象
        """
        self.damage_scenario_impact_level = scenario

    def set_threat_scenario(self, scenario: ThreatScenarioAttackFeasibility) -> None:
        """
        设置威胁场景攻击可行性

        Args:
            scenario: 威胁场景攻击可行性对象
        """
        self.threat_scenario_attack_feasibility = scenario

    def set_risk_treatment_decision(self, decision: RiskTreatmentDecision) -> None:
        """
        设置风险处理决策

        Args:
            decision: 风险处理决策对象
        """
        self.risk_treatment_decision = decision

    def set_cybersecurity_control_requirement(
        self, cybersecurity_control_requirement: CybersecurityControlRequirement
    ) -> None:
        """
        设置网络安全控制需求

        Args:
            requirement: 网络安全控制需求对象
        """
        self.cybersecurity_control_requirement = cybersecurity_control_requirement

    def calculate_overall_risk(self):
        """
        计算总体风险值
        """
        # 否则尝试根据损害场景和威胁场景计算
        if (
            self.damage_scenario_impact_level and self.threat_scenario_attack_feasibility
        ):
            # 这里可以实现具体的风险计算逻辑
            # 例如：基于损害场景影响级别和威胁场景攻击可行性的矩阵计算
            impact_level = self.damage_scenario_impact_level.impact_level.value
            attack_feasibility = (
                self.threat_scenario_attack_feasibility.attack_feasibility_rating
            )

            # 简单的风险矩阵映射（示例）
            risk_matrix = {
                "verylow": [1, 1, 1, 2],
                "low": [1, 2, 2, 3],
                "medium": [1, 2, 3, 4],
                "high": [1, 3, 4, 5],
            }

            if attack_feasibility and attack_feasibility.value in risk_matrix:
                self.risk_treatment_decision.risk_value = risk_matrix[
                    attack_feasibility.value
                ][impact_level]

    def __str__(self) -> str:
        """
        返回TARA资产信息的字符串表示

        Returns:
            str: 包含资产安全属性、损害场景、威胁场景、风险处理决策和网络安全控制需求的字符串
        """
        return (
            f"AssetTaraInfo(\n"
            f"  Asset Cybersecurity Attribute: {self.asset_cybersecurity_attribute}\n"
            f"  Damage Scenario Impact Level: {self.damage_scenario_impact_level}\n"
            f"  Threat Scenario Attack Feasibility: {self.threat_scenario_attack_feasibility}\n"
            f"  Risk Treatment Decision: {self.risk_treatment_decision}\n"
            f"  Cybersecurity Control Requirement: {self.cybersecurity_control_requirement}\n"
            f")"
        )

    def to_dict(self) -> dict:
        """
        将TARA资产信息转换为字典格式

        Returns:
            dict: 包含TARA资产信息的字典
        """
        return {
            "asset_cybersecurity_attribute": (
                self.asset_cybersecurity_attribute.to_dict()
                if self.asset_cybersecurity_attribute
                else None
            ),
            "damage_scenario_impact_level": (
                self.damage_scenario_impact_level.to_dict()
                if self.damage_scenario_impact_level
                else None
            ),
            "threat_scenario_attack_feasibility": (
                self.threat_scenario_attack_feasibility.to_dict()
                if self.threat_scenario_attack_feasibility
                else None
            ),
            "risk_treatment_decision": (
                self.risk_treatment_decision.to_dict()
                if self.risk_treatment_decision
                else None
            ),
            "cybersecurity_control_requirement": (
                self.cybersecurity_control_requirement.to_dict()
                if self.cybersecurity_control_requirement
                else None
            ),
        }

    def to_json(self) -> str:
        """
        将TARA资产信息转换为JSON字符串

        Returns:
            str: JSON格式的TARA资产信息
        """
        return json.dumps(self.to_dict(), ensure_ascii=False)

    @staticmethod
    def write_asset_tara_info_to_csv(assets: List["AssetTaraInfo"], output_file: str):
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

        def generate_numerical_id(prefix: str, index: int) -> str:
            index = index + 1
            return f"{prefix}_{index:05d}"

        with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, delimiter=";")
            writer.writeheader()

            for i, asset in enumerate(assets):
                # 创建一个空的行字典
                row = {}

                # 从嵌套结构中提取数据
                asset_cybersecurity_attribute = asset.asset_cybersecurity_attribute
                if asset_cybersecurity_attribute:
                    # 从asset_cybersecurity_attribute提取数据
                    # 资产信息
                    if hasattr(asset_cybersecurity_attribute, "asset_info") and hasattr(
                        asset_cybersecurity_attribute,
                        "assigned_security_attribute",
                    ):
                        asset_attr = asset_cybersecurity_attribute.asset_info
                        if asset_attr:
                            row["asset_id"] = getattr(asset_attr, "asset_id", "")
                            row["asset_name"] = getattr(asset_attr, "asset_name", "")
                            row["asset_id"] = row["asset_id"].strip().replace("\n", "") if row["asset_id"] else ""
                            row["asset_name"] = row["asset_name"].strip().replace("\n", "") if row["asset_name"] else ""
                            # 获取 enum 的name
                            row["assigned_security_attribute"] = asset_cybersecurity_attribute.assigned_security_attribute.name
                damage_scenario_impact_level = asset.damage_scenario_impact_level
                # 损害场景信息
                if damage_scenario_impact_level:
                    if damage_scenario_impact_level:
                        # 重写一个damage_scenario_id编号函数，以ds_00为前缀,后面为数字序号
                        row["damage_scenario_id"] = generate_numerical_id("DS", i)
                        row["damage_scenario"] = getattr(
                            damage_scenario_impact_level, "damage_scenario", ""
                        )
                        row["damage_scenario"] = row["damage_scenario"].strip().replace("\n", "") if row["damage_scenario"] else ""
                        row["safety"] = damage_scenario_impact_level.safety.name
                        row["financial"] = damage_scenario_impact_level.financial.name
                        row["operational"] = damage_scenario_impact_level.operational.name
                        row["privacy"] = damage_scenario_impact_level.privacy.name
                        row["impact_level"] = damage_scenario_impact_level.impact_level.name

                threat_scenario_attack_feasibility = (
                    asset.threat_scenario_attack_feasibility
                )
                if threat_scenario_attack_feasibility:
                    # 威胁场景信息
                    row["threat_scenario_id"] = generate_numerical_id("TS", i)
                    row["threat_scenario"] = getattr(
                        threat_scenario_attack_feasibility, "threat_scenario", ""
                    )
                    row["threat_scenario"] = row["threat_scenario"].strip().replace("\n", "") if row["threat_scenario"] else ""
                    row["attack_path"] = getattr(
                        threat_scenario_attack_feasibility, "attack_path", ""
                    )
                    row["attack_path"] = row["attack_path"].strip().replace("\n", "") if row["attack_path"] else ""
                    row["time_consuming"] = threat_scenario_attack_feasibility.time_consuming.name
                    row["expertise"] = threat_scenario_attack_feasibility.expertise.name
                    row["knowledge_about_toe"] = threat_scenario_attack_feasibility.knowledge_about_toe.name
                    row["window_of_opportunity"] = threat_scenario_attack_feasibility.window_of_opportunity.name
                    row["equipment"] = threat_scenario_attack_feasibility.equipment.name

                    row["difficulty"] = getattr(
                        threat_scenario_attack_feasibility, "difficulty", ""
                    )
                    row["attack_feasibility_rating"] = threat_scenario_attack_feasibility.attack_feasibility_rating.name

                risk_treatment_decision = asset.risk_treatment_decision
                if risk_treatment_decision:
                    # 风险处理信息
                    row["risk_value"] = getattr(
                        risk_treatment_decision, "risk_value", ""
                    )
                    row["risk_treatment"] = risk_treatment_decision.risk_treatment.name
                    row["item_change"] = getattr(
                        risk_treatment_decision, "item_change", ""
                    )
                    row["item_change"] = row["item_change"].strip().replace("\n", "") if row["item_change"] else ""
                    row["cybersecurity_claim_id"] = generate_numerical_id("CCL", i)
                    row["cybersecurity_claim"] = getattr(
                        risk_treatment_decision, "cybersecurity_claim", ""
                    )
                    row["cybersecurity_claim"] = row["cybersecurity_claim"].strip().replace("\n", "") if row["cybersecurity_claim"] else ""
                    row["cybersecurity_goal_id"] = generate_numerical_id("CG", i)
                    row["cybersecurity_goal"] = getattr(
                        risk_treatment_decision, "cybersecurity_goal", ""
                    )
                    row["cybersecurity_goal"] = row["cybersecurity_goal"].strip().replace("\n", "") if row["cybersecurity_goal"] else ""

                cybersecurity_control_requirement = (
                    asset.cybersecurity_control_requirement
                )
                # 网络安全控制信息
                if cybersecurity_control_requirement:
                    row["cybersecurity_control_id"] = generate_numerical_id("CCO", i)
                    row["cybersecurity_control"] = getattr(
                        cybersecurity_control_requirement, "cybersecurity_control", ""
                    )
                    row["cybersecurity_control"] = row["cybersecurity_control"].strip().replace("\n", "") if row["cybersecurity_control"] else ""
                    row["allocated_to_device"] = getattr(
                        cybersecurity_control_requirement, "allocated_to_device", ""
                    )
                    row["cybersecurity_requirement_id"] = getattr(
                        cybersecurity_control_requirement, "cybersecurity_requirement_id", ""
                    )
                    row["cybersecurity_requirement"] = getattr(
                        cybersecurity_control_requirement,
                        "cybersecurity_requirement",
                        "",
                    )
                    row["cybersecurity_requirement"] = row["cybersecurity_requirement"].strip().replace("\n", "") if row["cybersecurity_requirement"] else ""
                # 为缺失的字段设置空字符串，确保CSV格式一致
                for field in fieldnames:
                    if field not in row:
                        row[field] = ""

                writer.writerow(row)

    def prepare_for_ai01(self) -> str:
        # 将字典转换为JSON字符串
        payload_dict = {
            "asset_cybersecurity_attribute": (
                self.asset_cybersecurity_attribute.to_dict()
                if self.asset_cybersecurity_attribute
                else None
            ),
        }
        return json.dumps(payload_dict, ensure_ascii=False)

    def prepare_for_ai02(self) -> str:
        """
        准备TARA资产信息，用于AI模型输入

        Returns:
            str: 格式化的TARA资产信息字符串，用于AI模型输入
        """

        payload_dict = {
            "asset_cybersecurity_attribute": (
                self.asset_cybersecurity_attribute.to_dict()
                if self.asset_cybersecurity_attribute
                else None
            ),
            "damage_scenario_impact_level": (
                self.damage_scenario_impact_level.to_dict()
                if self.damage_scenario_impact_level
                else None
            ),
        }
        return json.dumps(payload_dict, ensure_ascii=False)

    def prepare_for_ai03(self) -> str:
        """
        准备资产威胁影响综合分析信息，用于AI模型输入

        Returns:
            str: 格式化的资产威胁影响综合分析信息，用于AI模型输入
        """

        payload_dict = {
            "asset_cybersecurity_attribute": (
                self.asset_cybersecurity_attribute.to_dict()
                if self.asset_cybersecurity_attribute
                else None
            ),
            "damage_scenario_impact_level": (
                self.damage_scenario_impact_level.to_dict()
                if self.damage_scenario_impact_level
                else None
            ),
            "threat_scenario_attack_feasibility": (
                self.threat_scenario_attack_feasibility.to_dict()
                if self.threat_scenario_attack_feasibility
                else None
            ),
        }
        return json.dumps(payload_dict, ensure_ascii=False)

    def prepare_for_ai04(self) -> str:
        """
        准备资产威胁影响综合分析信息，用于AI模型输入

        Returns:
            str: 格式化的资产威胁影响综合分析信息，用于AI模型输入
        """

        payload_dict = {
            "asset_cybersecurity_attribute": (
                self.asset_cybersecurity_attribute.to_dict()
                if self.asset_cybersecurity_attribute
                else None
            ),
            "damage_scenario_impact_level": (
                self.damage_scenario_impact_level.to_dict()
                if self.damage_scenario_impact_level
                else None
            ),
            "threat_scenario_attack_feasibility": (
                self.threat_scenario_attack_feasibility.to_dict()
                if self.threat_scenario_attack_feasibility
                else None
            ),
            "risk_treatment_decision": (
                self.risk_treatment_decision.to_dict()
                if self.risk_treatment_decision
                else None
            ),
        }
        return json.dumps(payload_dict, ensure_ascii=False)

    def prepare_for_ai05(self) -> str:
        """
        准备资产威胁影响综合分析信息，用于AI模型输入

        Returns:
            str: 格式化的资产威胁影响综合分析信息，用于AI模型输入
        """

        payload_dict = {
            "asset_cybersecurity_attribute": (
                self.asset_cybersecurity_attribute.to_dict()
                if self.asset_cybersecurity_attribute
                else None
            ),
            "damage_scenario_impact_level": (
                self.damage_scenario_impact_level.to_dict()
                if self.damage_scenario_impact_level
                else None
            ),
            "threat_scenario_attack_feasibility": (
                self.threat_scenario_attack_feasibility.to_dict()
                if self.threat_scenario_attack_feasibility
                else None
            ),
            "risk_treatment_decision": (
                self.risk_treatment_decision.to_dict()
                if self.risk_treatment_decision
                else None
            ),
            "cybersecurity_control_requirement": (
                self.cybersecurity_control_requirement.to_dict()
                if self.cybersecurity_control_requirement
                else None
            ),
        }
        return json.dumps(payload_dict, ensure_ascii=False)

    def prepare_for_ai06(self) -> str:
        """
        准备资产威胁影响综合分析信息，用于AI模型输入
        Returns:
            str: 格式化的资产威胁影响综合分析信息，用于AI模型输入
        """
        payload_dict = {
            "asset_cybersecurity_attribute": (
                self.asset_cybersecurity_attribute.to_dict01()
                if self.asset_cybersecurity_attribute
                else None
            ),
            "cybersecurity_control_requirement": (
                self.cybersecurity_control_requirement.to_dict01()
                if self.cybersecurity_control_requirement
                else None
            ),
        }
        return json.dumps(payload_dict, ensure_ascii=False)

    def get_prompt01(self) -> str:
        return (
            "请根据以上资产asset_id, asset_name, asset_type, communication_protocol, remarks，"
            "评估资产是否应该被赋于以下安全属性："
            "Authenticity, Integrity, Non-repudiation, Confidentiality, Availability, Authorization, Privacy。"
            "评分标准：0-不相关，1-低相关，2-中等相关，3-高相关，4-关键相关，5-必需属性"
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

    def get_prompt02(self) -> str:
        """
        获取资产安全属性分析的提示字符串

        Returns:
            str: 格式化的资产安全属性分析提示字符串，用于AI模型输入
        """
        return """
        资产信息：请严格按照 ISO 21434 [RQ-15-01] 的要求，根据资产的asset_id,asset_name, assigned_security_attribute信息，为该 Item 识别所有可能的 Damage Scenario
        每个损害场景可以包含如下几点，请使用逻辑清晰的语言描述每个damage_scenario，将以下四点符合逻辑的编写成一句话。
        1. 导致功能失效的攻击入口点（ECU、通信通道、后端系统等）
        2. 被破坏的安全属性与损害场景的关联关系
        3. 资产功能与不良后果的因果关系链
        4. 对道路使用者的潜在伤害类型（身体伤害、财产损失等）
        返回JSON格式：{"possible_damage_scenario_list":[{"damage_scenario_1":"XXXXXXXXX"},{"damage_scenario_2":"XXXXXXXXXXX"}]}
        """

    def get_prompt03(self) -> str:
        """
        获取资产综合分析提示字符串，用于AI模型输入

        Returns:
            str: 格式化的资产综合分析提示字符串，用于AI模型输入
        """
        return """
        资产信息：根据资产的asset_id,asset_name, assigned_security_attribute, damage_scenario信息，对资产的损害场景进行从safety,financial,operational, privacy四个方面进行评估。
        评估指标：
        - safety: 对道路使用者（驾驶员、乘客、行人、其他车辆）的人身伤害程度，可选Negligible, Moderate, Major, Severe。Severe-致命伤害, Major-严重伤害, Moderate-中等伤害, Negligible-轻微伤害）
        - financial: 车辆所有者，路人的资产价值损失，可选Negligible, Moderate, Major, Severe。（Severe-重大损失, Major-较大损失, Moderate-中等损失, Negligible-轻微损失）
        - operational: 车辆预期功能受损程度（不能开车、不能泊车等），可选Negligible, Moderate, Major, Severe。（Severe-功能完全丧失, Major-功能严重降级, Moderate-功能部分影响, Negligible-轻微影响）
        - privacy: 个人数据或隐私泄露程度，可选Negligible, Moderate, Major, Severe。(Severe-大量个人数据泄露, Major-敏感个人数据泄露, Moderate-一般个人数据泄露, Negligible-匿名数据泄露）
        返回JSON格式：{"possible_damage_scenario_impact_level":{"safety":"Negligible", "financial":"Moderate", "operational":"Major", "privacy":"Severe"}}
        """

    def get_prompt04(self) -> str:
        """
        获取资产综合分析提示字符串，用于AI模型输入

        Returns:
            str: 格式化的资产信息与资产损害场景影响级别提示字符串，用于AI模型输入
        """
        return """
        资产信息：根据资产的asset_id,asset_name, assigned_security_attribute, damage_scenario,safety,financial,operational, privacy信息，分析可能存在的威胁场景信息，
        每个威胁场景必须同时清晰包含以下四要素，并写成逻辑连贯的一句话：
        1. 目标资产（明确写J6P PCBA电路板）；
        2. 被破坏的网络安全属性（必须是Authenticity）；
        3. 导致真实性被破坏的具体原因/攻击方式（必须描述明确的攻击入口点和具体技术手段或缺失的防护措施）；
        4. 简要说明该威胁场景如何导致之前识别的某个或多个damage scenario。
        返回JSON格式：{"possible_threat_scenario_list":[{"threat_scenario_1":"XXXXXXXXXXX"},{"threat_scenario_2":"XXXXXXXXXXX"}]}
        """

    def get_prompt05(self) -> str:
        """
        获取为AI模型准备的提示字符串

        Returns:
            str: 包含威胁场景信息的提示字符串
        """
        return """
        请根据asset_id,asset_name,assigned_security_attribute,damage_scenario,threat_scenario信息，评估可能存在的攻击场景。
        每个攻击场景需包含如下信息：
        1. 攻击入口点(Entry Point)
        2. 具体攻击技术（可引用CVE、常见汽车攻击手法）
        3. 涉及的资产组件
        4. 前提条件(Prerequisites)
        5. 所需攻击者能力
        整体思考以上5点，生成多个符合逻辑的攻击场景后，然后对每个场景进行按步骤拆解，生成逻辑完整，语言表达顺畅的攻击步骤
        返回的json数据结构为：{"possible_attack_path_list":[{"attack_path1":"XXXXXXXXX"},{"attack_path2":"XXXXXXXXXXXXXXXXXXXX"}]}
        """

    def get_prompt06(self) -> str:
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

    def get_prompt07(self) -> str:
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
        cybersecurity_goal编写标准：
        1. 网络安全目标是一个需求，用来针对威胁场景来保护资产。
        2. 网络安全目标cybersecurity_goal可以针对item的生命周期的任何一个阶段
        3. 如果有CAL信息，可以对安全目标订一个CAL，如果没有CAL信息，就不需要订一个安全目标。
        cybersecurity_claim编写标准：
        1. 声明性质
        - 基于分析过程中的假设
        - 描述风险被接受或转移的依据
        - 可用于网络安全监控

        2. 必须包含要素
        - 声明的具体内容
        - 相关的假设条件
        - 风险处理依据
        - 监控要求（如适用）

        3. 表述要求
        - 明确声明风险被接受的理由
        - 描述风险分担的责任方
        - 包含监控和维护要求
        返回JSON格式：{"risk_treatment":"Avoid","item_change":"通过移除危险源，停止相关安全开发活动来避免风险发生", "cybersecurity_goal":"","cybersecurity_claim":""}
        """

    def get_prompt08(self) -> str:
        """
        获取风险处理实施的提示信息

        Returns:
            str: 格式化的风险处理实施提示信息
        """
        return """
        资产信息：根据资产的asset_id,asset_name, assigned_security_attribute, damage_scenario,threat_scenario,attack_path,attack_feasibility_rating,cybersecurity_goal信息，且risk_treatment为reduce，考虑编写信息安全目标cybersecurity_control与cybersecurity_requirement信息，编写规则：
        Cybersecurity Control描述必须包含：
        1. 说明控制措施cybersecurity_control是技术性（technical）还是操作性（operational），并给出具体实现方式（例如：AES-256-GCM、Secure Boot + HSM、消息MAC + Freshness、OTA双向证书认证等）。
        2. 明确说明该控制措施在威胁场景中的作用（是预防、检测、响应、恢复，还是降低后果严重度）。
        3. 必须说明依赖关系（dependencies）：
        - 依赖 Item 的哪个功能？
        - 依赖其他哪些控制措施才能生效？
        4. 所有控制措施之间如果存在相互作用（interaction），必须明确描述（例如“消息认证依赖密钥分发服务，密钥分发服务又依赖PKI和预共享根证书”）。
        根据cybersecurity_control描述，确认是否分配给device，例如分配给了OEM OTA服务器，那这个cybersecurity_control就是和device不相关，allocated_to_device为No，否则为Yes。
        如果allocated_to_device为"yes",根据cybersecurity_control描述，编写cybersecurity_requirement信息，如果如果allocated_to_device为为"no",不需要编写，cybersecurity_requirement的编写要求：
        Cybersecurity Requirement必须包含两类要求：
        1. 项目要求 (Item Requirements)：
        - 项目本身的网络安全要求
        - 分配到项目或其组件
        2. 运行环境要求 (Operational Environment Requirements)：
        - 在项目外部实现但包含在网络安全验证中
        - 可包括对其他项目的要求
        编写具体要求：
        a) 必须包含的具体特性：
        - 更新能力 (update capabilities)
        - 运行期间获取用户同意的能力 (user consent during operations)
        - 具体算法、协议、必须是现有的车联网安全中可以落地的设计，方法，并且可以验证其安全性。（例如secoc是没有加密的，can/canfd/uart等协议都是明文传输的，增加加密方式现阶段看起来是没法实施的）
        b) 分配要求：
        - 必须分配到项目
        - 如适用，分配到项目的一个或多个组件
        - 明确运行环境要求的责任方
        c) 验证要求：
        - 100%可验证
        - 包含具体验证标准和方法
        - 明确验证环境和条件
        返回格式：{"cybersecurity_control_id":"CSO-001", "cybersecurity_control":"通过移除危险源，停止相关安全开发活动来避免风险发生", "allocated_to_device":"yes", "cybersecurity_requirement_id":"CSR-001", "cybersecurity_requirement":"确保资产的安全开发活动得到适当的支持和监控"}
        """
