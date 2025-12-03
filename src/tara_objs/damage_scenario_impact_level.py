"""
损害场景影响级别模块

这个模块定义了TARA分析中的损害场景类，包含损害场景序号、描述、各方面影响等级和总体影响级别。
"""

from enum import Enum
import json


class SeverityLevel(Enum):
    """
    严重性级别枚举类，定义了影响的严重程度
    """

    NEGLIGIBLE = 0  # 可忽略
    MODERATE = 1  # 中等
    MAJOR = 2  # 重大
    SEVERE = 3  # 严重

    @staticmethod
    def get(severity: str) -> "SeverityLevel":
        """
        通过字符串获取SeverityLevel枚举值

        Args:
            severity: 严重性级别字符串

        Returns:
            SeverityLevel: 对应的枚举值，默认为NEGLIGIBLE
        """
        for member in SeverityLevel:
            if member.name == severity.upper():
                return member
        return SeverityLevel.NEGLIGIBLE

    @property
    def display_name(self) -> str:
        """
        获取显示名称（首字母大写）

        Returns:
            str: 格式化的显示名称
        """
        return self.name.capitalize()


class DamageScenarioImpactLevel:
    """
    损害场景影响级别类，包含损害场景信息和各方面影响等级

    属性:
    - damage_scenario_sn: 损害场景序号
    - damage_scenario: 损害场景描述
    - safety: 安全影响级别
    - financial: 财务影响级别
    - operational: 运营影响级别
    - privacy: 隐私影响级别
    - impact_level: 总体影响级别
    """

    def __init__(
        self,
        damage_scenario_sn: str = "",
        damage_scenario: str = "",
        safety: SeverityLevel = SeverityLevel.NEGLIGIBLE,
        financial: SeverityLevel = SeverityLevel.NEGLIGIBLE,
        operational: SeverityLevel = SeverityLevel.NEGLIGIBLE,
        privacy: SeverityLevel = SeverityLevel.NEGLIGIBLE,
    ):
        """
        初始化损害场景影响级别对象

        Args:
            damage_scenario_sn: 损害场景序号
            damage_scenario: 损害场景描述
            safety: 安全影响级别
            financial: 财务影响级别
            operational: 运营影响级别
            privacy: 隐私影响级别
        """
        self.damage_scenario_sn = damage_scenario_sn
        self.damage_scenario = damage_scenario
        self.safety = safety
        self.financial = financial
        self.operational = operational
        self.privacy = privacy
        self.impact_level = self._calculate_impact_level()

    def _calculate_impact_level(self) -> SeverityLevel:
        """
        根据各方面影响等级计算总体影响级别（取最大值）

        Returns:
            SeverityLevel: 总体影响级别
        """
        max_level = max(
            self.safety.value,
            self.financial.value,
            self.operational.value,
            self.privacy.value,
        )
        return SeverityLevel(max_level)

    def set_impact_levels(
        self,
        safety: SeverityLevel = None,
        financial: SeverityLevel = None,
        operational: SeverityLevel = None,
        privacy: SeverityLevel = None,
    ) -> None:
        """
        设置各方面影响级别

        Args:
            safety: 安全影响级别
            financial: 财务影响级别
            operational: 运营影响级别
            privacy: 隐私影响级别
        """
        if safety is not None:
            self.safety = safety
        if financial is not None:
            self.financial = financial
        if operational is not None:
            self.operational = operational
        if privacy is not None:
            self.privacy = privacy
        # 重新计算总体影响级别
        self.impact_level = self._calculate_impact_level()

    def set_impact_levels_by_strings(
        self,
        attributes: dict = {
            "safety": None,
            "financial": None,
            "operational": None,
            "privacy": None,
        },
    ) -> None:
        """
        通过字符串设置各方面影响级别

        Args:
            safety: 安全影响级别字符串
            financial: 财务影响级别字符串
            operational: 运营影响级别字符串
            privacy: 隐私影响级别字符串
        """
        self.set_impact_levels(
            safety=(
                SeverityLevel.get(attributes["safety"])
                if attributes["safety"]
                else None
            ),
            financial=(
                SeverityLevel.get(attributes["financial"])
                if attributes["financial"]
                else None
            ),
            operational=(
                SeverityLevel.get(attributes["operational"])
                if attributes["operational"]
                else None
            ),
            privacy=(
                SeverityLevel.get(attributes["privacy"])
                if attributes["privacy"]
                else None
            ),
        )

        self.impact_level = self._calculate_impact_level()

    def __str__(self) -> str:
        """
        返回对象的字符串表示

        Returns:
            str: 格式化的损害场景信息
        """
        info = f"Damage Scenario SN: {self.damage_scenario_sn}\n"
        info += f"Damage Scenario: {self.damage_scenario}\n"
        info += f"Safety: {self.safety.display_name}\n"
        info += f"Financial: {self.financial.display_name}\n"
        info += f"Operational: {self.operational.display_name}\n"
        info += f"Privacy: {self.privacy.display_name}\n"
        info += f"Impact Level: {self.impact_level.display_name}\n"
        return info

    def to_dict(self) -> dict:
        """
        将对象转换为字典

        Returns:
            dict: 包含损害场景信息的字典
        """
        return {
            "damage_scenario_sn": self.damage_scenario_sn,
            "damage_scenario": self.damage_scenario,
            "safety": self.safety.name,
            "financial": self.financial.name,
            "operational": self.operational.name,
            "privacy": self.privacy.name,
            "impact_level": self.impact_level.name,
        }

    def to_json(self) -> str:
        """
        将对象转换为JSON字符串

        Returns:
            str: JSON格式的损害场景信息
        """
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    @classmethod
    def from_dict(cls, data: dict) -> "DamageScenarioImpactLevel":
        """
        从字典创建对象

        Args:
            data: 包含损害场景信息的字典

        Returns:
            DamageScenarioImpactLevel: 创建的对象
        """
        return cls(
            damage_scenario_sn=data.get("damage_scenario_sn", ""),
            damage_scenario=data.get("damage_scenario", ""),
            safety=SeverityLevel.get(data.get("safety", "NEGLIGIBLE")),
            financial=SeverityLevel.get(data.get("financial", "NEGLIGIBLE")),
            operational=SeverityLevel.get(data.get("operational", "NEGLIGIBLE")),
            privacy=SeverityLevel.get(data.get("privacy", "NEGLIGIBLE")),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "DamageScenarioImpactLevel":
        """
        从JSON字符串创建对象

        Args:
            json_str: JSON格式的损害场景信息

        Returns:
            DamageScenarioImpactLevel: 创建的对象
        """
        data = json.loads(json_str)
        return cls.from_dict(data)

    def validate(self) -> bool:
        """
        验证对象的有效性

        Returns:
            bool: 对象是否有效
        """
        if not self.damage_scenario_sn:
            return False
        if not self.damage_scenario:
            return False
        return True
