# pyTara V - 汽车网络安全TARA分析系统

项目概述 pyTara V是一个基于ISO 21434标准的汽车网络安全威胁分析与风险评估(TARA)系统。该系统利用AI技术自动化分析汽车电子资产的安全属性，生成损害场景、威胁场景、风险处理决策和网络安全控制需求。

## 系统架构 核心模块

```
pyTara V/
├── src/
│ ├── tara_workflow.py # 主工作流引擎
│ ├── ai_assistant/ # AI助手模块
│ │ ├── deepseek_ai.py # DeepSeek AI实现
│ │ ├── tara_analyzer.py # TARA分析器
│ │ └── base_ai.py # AI助手基类
│ ├── tara_objs/ # TARA对象模型
│ │ ├── asset_info.py # 资产信息
│ │ ├── asset_tara_info.py # TARA分析结果
│ │ ├── asset_csr_info.py # 网络安全要求
│ │ └── ... # 其他TARA对象
│ └── config/ # 配置模块
│ ├── config.py # 主配置文件
│ └── logging_config.py # 日志配置
├── files/ # 输入输出文件
├── tmp/ # 临时文件
└── logs/ # 日志文件
```

## 技术栈

- Python 3.12+: 主要编程语言 

- DeepSeek AI: 大语言模型API 

- pandas: 数据处理 

- openpyxl: Excel文件处理 

- aiohttp: 异步HTTP请求 

- asyncio: 异步编程 

## 核心功能

### 资产安全管理

**资产信息模型 (asset_info.py):**

- 支持硬件、软件、数据、通信四种资产

- 类型包含资产ID、名称、通信协议、备注等属性

- 提供Excel文件读取功能

### AI驱动的安全分析

**TARA分析器 (tara_analyzer.py):**

- 基于DeepSeek AI的安全专家系统

- 自动生成损害场景和影响评估

- 威胁场景分析和攻击可行性评估

- 风险处理决策建议

- 网络安全控制需求(CSR)生成

**DeepSeek AI集成 (deepseek_ai.py):**

- 支持同步和异步API调用

- 连接池和重试机制

- 可配置的温度和token限制

- JSON格式响应处理

### TARA分析工作流

**主工作流引擎 (tara_workflow.py):**

- 支持同步和异步处理模式

- 并发控制（最大并发资产数和属性数）

- 分阶段分析：资产属性→损害场景→威胁场景→风险处理→控制需求

- 自动生成临时文件和最终结果

## 对象模型系统

**核心TARA对象:**

AssetTaraInfo: 整合所有TARA分析信息

AssetCSRInfo: 网络安全要求信息

DamageScenarioImpactLevel: 损害场景和影响级别

ThreatScenarioAttackFeasibility: 威胁场景和攻击可行性

RiskTreatmentDecision: 风险处理决策

CybersecurityControlRequirement: 网络安全控制需求


## 配置系统

**环境配置 配置文件 (config.py):**

```
DeepSeek AI API配置

DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "your-api-key")
DEEPSEEK_MODEL = os.environ.get("DEEPSEEK_MODEL", "Pro/deepseek-ai/DeepSeek-V3.2-Exp")
DEEPSEEK_BASE_URL = os.environ.get("DEEPSEEK_BASE_URL", "https://api.siliconflow.cn")
DEEPSEEK_MAX_RETRIES = int(os.environ.get("DEEPSEEK_MAX_RETRIES", "5"))
DEEPSEEK_TIMEOUT = int(os.environ.get("DEEPSEEK_TIMEOUT", "120"))
DEEPSEEK_MAX_TOKENS = int(os.environ.get("DEEPSEEK_MAX_TOKENS", "8000"))
```

### 数据截断问题解决

系统已解决AI响应数据截断问题：

- 配置DEEPSEEK_MAX_TOKENS默认值为8000

- 可通过环境变量动态调整

- 支持范围：一般分析4000-8000，复杂分析8000-12000，详细分析12000-16000
  

## 使用方法

1. 环境准备
   
   ```
   安装依赖
   
   pip install -r requirements.txt
   配置环境变量
   
   export DEEPSEEK_API_KEY="your-api-key"
   export DEEPSEEK_MAX_TOKENS="8000"
   
   ```

2. 运行TARA分析
   
   ```
   python src\tara_workflow.py
   ```

3. 输出结果
   
   系统生成两个主要输出文件：
    ```
    asset_tara_info.csv: 完整的TARA分析结果
    asset_csr_info.csv: 网络安全控制需求
    ```