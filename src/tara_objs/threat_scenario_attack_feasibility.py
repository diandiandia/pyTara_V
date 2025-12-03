from enum import Enum
from typing import Dict, Optional, Union
import json


class TimeConsumingLevel(Enum):
    """攻击时间消耗级别枚举"""

    NO_MORE_THAN_ONE_DAY = "<=1d"
    NO_MORE_THAN_ONE_WEEK = "<=1w"
    NO_MORE_THAN_ONE_MONTH = "<=1m"
    NO_MORE_THAN_SIX_MONTHS = "<=6m"
    MORE_THAN_SIX_MONTHS = ">6m"

    @staticmethod
    def from_string(value: str) -> Optional["TimeConsumingLevel"]:
        """从字符串创建枚举实例"""
        for level in TimeConsumingLevel:
            if level.value == value:
                return level
        return None


class ExpertiseLevel(Enum):
    """专业知识要求级别枚举"""

    LAYMAN = "layman"
    PROFICIENT = "proficient"
    EXPERT = "expert"
    MULTIPLE_EXPERT = "multiple expert"

    @staticmethod
    def from_string(value: str) -> Optional["ExpertiseLevel"]:
        """从字符串创建枚举实例"""
        for level in ExpertiseLevel:
            if level.value == value:
                return level
        return None


class KnowledgeAboutTOELevel(Enum):
    """关于目标设备知识级别枚举"""

    PUBLIC = "public"
    RESTRICTED = "restricted"
    CONFIDENTIAL = "confidential"
    STRICTLY_CONFIDENTIAL = "strictly confidential"

    @staticmethod
    def from_string(value: str) -> Optional["KnowledgeAboutTOELevel"]:
        """从字符串创建枚举实例"""
        for level in KnowledgeAboutTOELevel:
            if level.value == value:
                return level
        return None


class WindowOfOpportunityLevel(Enum):
    """机会窗口级别枚举"""

    UNLIMITED = "unlimited"
    EASY = "easy"
    MODERATE = "moderate"
    DIFFICULT = "difficult"

    @staticmethod
    def from_string(value: str) -> Optional["WindowOfOpportunityLevel"]:
        """从字符串创建枚举实例"""
        for level in WindowOfOpportunityLevel:
            if level.value == value:
                return level
        return None


class EquipmentLevel(Enum):
    """所需设备级别枚举"""

    STANDARD = "standard"
    SPECIALIZED = "specialized"  # 注意：原文中为"specialied"，可能是拼写错误
    BESPOKE = "bespoke"
    MULTIPLE_BESPOKE = "multiple bespoke"

    @staticmethod
    def from_string(value: str) -> Optional["EquipmentLevel"]:
        """从字符串创建枚举实例"""
        for level in EquipmentLevel:
            if level.value == value:
                return level
        return None


class AttackFeasibilityRating(Enum):
    """攻击可行性评级枚举"""

    VERY_LOW = "verylow"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @staticmethod
    def from_string(value: str) -> Optional["AttackFeasibilityRating"]:
        """从字符串创建枚举实例"""
        for rating in AttackFeasibilityRating:
            if rating.value == value:
                return rating
        return None


class ThreatScenarioAttackFeasibility:
    """
    威胁场景攻击可行性评估类

    包含威胁场景ID、描述、攻击路径以及各种攻击可行性评估因素
    """

    def __init__(
        self,
        threat_id: str,
        threat_scenario: str,
        attack_path: str,
        time_consuming: Optional[Union[str, TimeConsumingLevel]] = None,
        expertise: Optional[Union[str, ExpertiseLevel]] = None,
        knowledge_about_toe: Optional[Union[str, KnowledgeAboutTOELevel]] = None,
        window_of_opportunity: Optional[Union[str, WindowOfOpportunityLevel]] = None,
        equipment: Optional[Union[str, EquipmentLevel]] = None,
        difficulty: Optional[int] = None,
        attack_feasibility_rating: Optional[Union[str, AttackFeasibilityRating]] = None,
    ):
        """
        初始化威胁场景攻击可行性评估对象

        Args:
            threat_id: 威胁场景ID
            threat_scenario: 威胁场景描述
            attack_path: 攻击路径描述
            time_consuming: 时间消耗级别
            expertise: 专业知识要求级别
            knowledge_about_toe: 关于目标设备的知识级别
            window_of_opportunity: 机会窗口级别
            equipment: 所需设备级别
            difficulty: 难度评分（0-10）
            attack_feasibility_rating: 攻击可行性评级
        """
        self.threat_id = threat_id
        self.threat_scenario = threat_scenario
        self.attack_path = attack_path

        # 处理评估维度字段
        self.time_consuming = self._parse_enum(time_consuming, TimeConsumingLevel)
        self.expertise = self._parse_enum(expertise, ExpertiseLevel)
        self.knowledge_about_toe = self._parse_enum(
            knowledge_about_toe, KnowledgeAboutTOELevel
        )
        self.window_of_opportunity = self._parse_enum(
            window_of_opportunity, WindowOfOpportunityLevel
        )
        self.equipment = self._parse_enum(equipment, EquipmentLevel)

        # 验证难度评分范围
        if difficulty is not None and not (0 <= difficulty <= 10):
            raise ValueError("Difficulty must be between 0 and 10")
        self.difficulty = difficulty

        self.attack_feasibility_rating = self._parse_enum(
            attack_feasibility_rating, AttackFeasibilityRating
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

    def set_time_consuming(self, value: str):
        """设置时间消耗级别"""
        """time_consuming可选：no_more_than_1d(小于等于1天)，no_more_than_1w(小于等于1周)，no_more_than_1m(小于等于1月)，no_more_than_6m(小于等于6个月)，more_than_6m(大于6个月)"""

        if value == "no_more_than_1d":
            self.time_consuming = TimeConsumingLevel.NO_MORE_THAN_ONE_DAY
        elif value == "no_more_than_1w":
            self.time_consuming = TimeConsumingLevel.NO_MORE_THAN_ONE_WEEK
        elif value == "no_more_than_1m":
            self.time_consuming = TimeConsumingLevel.NO_MORE_THAN_ONE_MONTH
        elif value == "no_more_than_6m":
            self.time_consuming = TimeConsumingLevel.NO_MORE_THAN_SIX_MONTHS
        elif value == "more_than_6m":
            self.time_consuming = TimeConsumingLevel.MORE_THAN_SIX_MONTHS
        else:
            self.time_consuming = self._parse_enum(value, TimeConsumingLevel)

    def set_expertise(self, value: Union[str, ExpertiseLevel]):
        """设置专业知识要求级别"""
        """expertise可选：layman(普通用户)，proficient(专业用户)，expert(专家用户)，multiple expert(多个专家用户)"""
        self.expertise = self._parse_enum(value, ExpertiseLevel)

    def set_knowledge_about_toe(self, value: Union[str, KnowledgeAboutTOELevel]):
        """设置关于目标设备的知识级别"""
        self.knowledge_about_toe = self._parse_enum(value, KnowledgeAboutTOELevel)

    def set_window_of_opportunity(self, value: Union[str, WindowOfOpportunityLevel]):
        """设置机会窗口级别"""
        self.window_of_opportunity = self._parse_enum(value, WindowOfOpportunityLevel)

    def set_equipment(self, value: Union[str, EquipmentLevel]):
        """设置所需设备级别"""
        self.equipment = self._parse_enum(value, EquipmentLevel)

    def calculate_difficulty(self) -> int:
        """
        根据查表规则计算难度总分

        Returns:
            int: 计算得到的难度总分
        """
        # 定义各个维度的分值映射表
        time_consuming_values = {
            TimeConsumingLevel.NO_MORE_THAN_ONE_DAY: 0,
            TimeConsumingLevel.NO_MORE_THAN_ONE_WEEK: 1,
            TimeConsumingLevel.NO_MORE_THAN_ONE_MONTH: 4,
            TimeConsumingLevel.NO_MORE_THAN_SIX_MONTHS: 17,
            TimeConsumingLevel.MORE_THAN_SIX_MONTHS: 19,
        }

        expertise_values = {
            ExpertiseLevel.LAYMAN: 0,
            ExpertiseLevel.PROFICIENT: 3,
            ExpertiseLevel.EXPERT: 6,
            ExpertiseLevel.MULTIPLE_EXPERT: 8,  # 注意名称与枚举定义保持一致
        }

        knowledge_values = {
            KnowledgeAboutTOELevel.PUBLIC: 0,
            KnowledgeAboutTOELevel.RESTRICTED: 3,
            KnowledgeAboutTOELevel.CONFIDENTIAL: 7,
            KnowledgeAboutTOELevel.STRICTLY_CONFIDENTIAL: 11,
        }

        window_values = {
            WindowOfOpportunityLevel.UNLIMITED: 0,
            WindowOfOpportunityLevel.EASY: 1,
            WindowOfOpportunityLevel.MODERATE: 4,
            WindowOfOpportunityLevel.DIFFICULT: 10,
        }

        equipment_values = {
            EquipmentLevel.STANDARD: 0,
            EquipmentLevel.SPECIALIZED: 4,
            EquipmentLevel.BESPOKE: 7,
            EquipmentLevel.MULTIPLE_BESPOKE: 9,  # 注意名称与枚举定义保持一致
        }

        # 计算总分
        total_difficulty = 0

        if self.time_consuming:
            total_difficulty += time_consuming_values.get(self.time_consuming, 0)

        if self.expertise:
            total_difficulty += expertise_values.get(self.expertise, 0)

        if self.knowledge_about_toe:
            total_difficulty += knowledge_values.get(self.knowledge_about_toe, 0)

        if self.window_of_opportunity:
            total_difficulty += window_values.get(self.window_of_opportunity, 0)

        if self.equipment:
            total_difficulty += equipment_values.get(self.equipment, 0)

        return total_difficulty

    def calculate_attack_feasibility_rating(self) -> AttackFeasibilityRating:
        """
        根据各评估维度计算攻击可行性评级

        Returns:
            AttackFeasibilityRating: 计算得到的攻击可行性评级
        """
        self.difficulty = self.calculate_difficulty()

        if self.difficulty >= 25:
            return AttackFeasibilityRating.VERY_LOW
        elif self.difficulty >= 20:
            return AttackFeasibilityRating.LOW
        elif self.difficulty >= 14:
            return AttackFeasibilityRating.MEDIUM
        else:
            return AttackFeasibilityRating.HIGH

    def update_feasibility_rating(self) -> None:
        """更新攻击可行性评级"""
        self.attack_feasibility_rating = self.calculate_attack_feasibility_rating()

    def to_dict(self) -> Dict[str, any]:
        """
        将对象转换为字典

        Returns:
            Dict: 包含对象所有属性的字典
        """
        return {
            "threat_id": self.threat_id,
            "threat_scenario": self.threat_scenario,
            "attack_path": self.attack_path,
            "time_consuming": (
                self.time_consuming.value if self.time_consuming else None
            ),
            "expertise": self.expertise.value if self.expertise else None,
            "knowledge_about_toe": (
                self.knowledge_about_toe.value if self.knowledge_about_toe else None
            ),
            "window_of_opportunity": (
                self.window_of_opportunity.value if self.window_of_opportunity else None
            ),
            "equipment": self.equipment.value if self.equipment else None,
            "difficulty": self.difficulty,
            "attack_feasibility_rating": (
                self.attack_feasibility_rating.value
                if self.attack_feasibility_rating
                else None
            ),
        }

    def __str__(self) -> str:
        """
        返回对象的字符串表示

        Returns:
            str: 对象的字符串表示
        """
        return (
            f"ThreatScenarioAttackFeasibility("
            f"threat_id='{self.threat_id}', "
            f"threat_scenario='{self.threat_scenario}', "
            f"attack_path='{self.attack_path}', "
            f"time_consuming={self.time_consuming.value if self.time_consuming else None}, "
            f"expertise={self.expertise.value if self.expertise else None}, "
            f"knowledge_about_toe={self.knowledge_about_toe.value if self.knowledge_about_toe else None}, "
            f"window_of_opportunity={self.window_of_opportunity.value if self.window_of_opportunity else None}, "
            f"equipment={self.equipment.value if self.equipment else None}, "
            f"difficulty={self.difficulty}, "
            f"attack_feasibility_rating={self.attack_feasibility_rating.value if self.attack_feasibility_rating else None}"
        )

    def prepare_for_ai(self) -> str:
        """
        为AI模型准备输入字符串

        Returns:
            str: 包含威胁场景信息的字符串
        """
        return json.dumps(self.to_dict(), ensure_ascii=False)

    def get_prompt(self) -> str:
        """
        获取为AI模型准备的提示字符串

        Returns:
            str: 包含威胁场景信息的提示字符串
        """
        return """
        请根据asset_id,asset_name,assigned_security_attribute,damage_scenario,threat_scenario信息，评估可能存在的攻击路径，将每个攻击路径拆解为多个步骤，每个步骤包含具体的操作细节。
        返回的json数据结构为：{"possible_attack_path_list":[{"attack_path1":"XXXXXXXXXX"},{"attack_path2":"XXXXXXXXXX"}]}
        """
