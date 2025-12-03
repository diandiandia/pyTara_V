from enum import Enum
from typing import Optional, Union
import json


class RiskTreatmentOption(Enum):
    """
    风险处理选项枚举类avoid, reduce, share, retain
    """

    AVOID = "Avoid"
    REDUCE = "Reduce"
    SHARE = "Share"
    RETAIN = "Retain"

    @staticmethod
    def from_string(value: str) -> Optional["RiskTreatmentOption"]:
        """
        从字符串创建风险处理选项枚举实例

        Args:
            value: 风险处理选项字符串

        Returns:
            Optional[RiskTreatmentOption]: 对应的枚举实例，如果不存在则返回None
        """
        for option in RiskTreatmentOption:
            if option.value.lower() == value.lower():
                return option
        return None


class RiskTreatmentDecision:
    """
    风险处理决策类

    包含风险值和对应的风险处理决策
    """

    def __init__(
        self,
        risk_treatment: Optional[Union[str, RiskTreatmentOption]] = None,
        item_change: Optional[str] = None,
        cybersecurity_claim_id: Optional[str] = None,
        cybersecurity_claim: Optional[str] = None,
        cybersecurity_goal_id: Optional[str] = None,
        cybersecurity_goal: Optional[str] = None,
    ):
        """
        初始化风险处理决策对象

        Args:
            risk_value: 风险值级别
            risk_treatment: 风险处理选项
        """
        self.risk_value = 0
        self.risk_treatment = (
            self._parse_enum(risk_treatment, RiskTreatmentOption)
            if risk_treatment
            else None
        )
        self.item_change = item_change
        self.cybersecurity_claim_id = cybersecurity_claim_id
        self.cybersecurity_claim = cybersecurity_claim
        self.cybersecurity_goal_id = cybersecurity_goal_id
        self.cybersecurity_goal = cybersecurity_goal

    def _parse_enum(
        self, value: Optional[Union[str, Enum]], enum_class: type
    ) -> Optional[Enum]:
        """
        解析枚举类型，支持字符串或枚举实例输入

        Args:
            value: 输入值（字符串或枚举实例）
            enum_class: 目标枚举类

        Returns:
            Optional[Enum]: 解析后的枚举实例

        Raises:
            ValueError: 如果字符串值不匹配任何枚举
            TypeError: 如果输入类型不正确
        """
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

    def set_risk_treatment(self, risk_treatment: Optional[Union[str, RiskTreatmentOption]] = None):
        """
        设置风险处理选项

        Args:
            risk_treatment: 风险处理选项（字符串或枚举实例）
        """
        self.risk_treatment = self._parse_enum(risk_treatment, RiskTreatmentOption) if risk_treatment else None

    def to_dict(self) -> dict:
        """
        将对象转换为字典

        Returns:
            dict: 包含风险处理决策信息的字典
        """
        return {
            "risk_value": self.risk_value,
            "risk_treatment": (
                self.risk_treatment.value if self.risk_treatment else None
            ),
            "item_change": self.item_change,
            "cybersecurity_claim_id": self.cybersecurity_claim_id,
            "cybersecurity_claim": self.cybersecurity_claim,
            "cybersecurity_goal_id": self.cybersecurity_goal_id,
            "cybersecurity_goal": self.cybersecurity_goal,
        }

    def prepare_for_ai(self) -> dict:
        """
        准备风险处理决策信息，用于AI模型输入

        Returns:
            dict: 包含风险处理决策信息的字典，适用于AI模型输入
        """
        return json.dumps(self.to_dict(), ensure_ascii=False)

    def __str__(self) -> str:
        """
        返回风险处理决策的字符串表示

        Returns:
            str: 包含风险值和处理选项的字符串
        """
        return f"RiskValue: {self.risk_value}, RiskTreatment: {self.risk_treatment.value if self.risk_treatment else 'None'}"
