# NovaGuard AI Defense Matrix

> 两阶段 LLM Prompt 注入检测系统：LoRA-BERT 快速筛查 + DeepSeek 语义分析，专为大模型输入安全设计。

[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/) [![Streamlit](https://img.shields.io/badge/Streamlit-Latest-FF4B4B.svg)](https://streamlit.io/) [![LoRA](https://img.shields.io/badge/LoRA-PEFT-FFB000.svg)](https://github.com/huggingface/peft) [![LLM](https://img.shields.io/badge/LLM-DeepSeek--V3-orange.svg)](https://www.deepseek.com/)

---

## 项目简介

NovaGuard 是一个面向大模型应用的 **Prompt 注入攻击检测系统**。针对 Jailbreak、Roleplay、Hypothetical Scenario、Ethical Boundary Testing 等常见攻击手法，构建了一套级联式（Cascade）检测管线：

- **Stage 1 · LoRA-BERT 快速筛查**：基于 BERT-base-uncased + LoRA 微调的轻量分类器，对所有输入做毫秒级二分类（恶意/安全）打分；可疑样本才进入 Stage 2。
- **Stage 2 · DeepSeek 语义分析**：仅在 Stage 1 命中时触发，使用 DeepSeek 对可疑样本做意图识别、攻击机理分析与缓解建议生成。

整体目标是 **在不显著增加正常输入延迟的前提下，把高风险的 prompt 拦截在进入下游 LLM 之前**。

---

## 核心特性

- 🛡️ **两阶段级联架构**：Stage 1 轻量过滤绝大多数安全流量，仅对可疑样本调用大模型，兼顾准确率与成本
- ⚡ **毫秒级响应**：Stage 1 平均 14ms（GPU），整体平均 142ms（含 Stage 2 时）
- 🎚️ **三档检测模式**：Strict / Balanced / Lenient，对应不同风险阈值（0.35 / 0.50 / 0.75），适配不同业务场景
- 🧑‍💻 **人工干预（HITL）**：一键标记 False Positive / False Negative，沉淀到反馈队列
- 📚 **威胁签名库**：内置 `threat_cases.json`，支持关键词检索与子类浏览
- 🧹 **AI 净化沙箱**：对恶意 prompt 自动生成"已剥离危险指令"的安全替代文本
- 🎛️ **完整运维看板**：节点健康度、流量分布（今日 / 本月 / 本季 / 全年）、攻击向量分布

---

## 系统架构

```
                    用户输入 (raw prompt)
                          │
                          ▼
        ┌──────────────────────────────────┐
        │  Stage 1: LoRA-BERT 快速筛查     │
        │  (bert-base-uncased + LoRA r=8)  │
        │                                  │
        │   is_malicious?  risk_score?     │
        └──────────┬───────────────────────┘
                   │
        ┌──────────┴──────────┐
        │                     │
     Safe（放行）         Malicious（可疑）
        │                     │
        ▼                     ▼
   返回 Safe 结果    ┌────────────────────────────┐
                    │  Stage 2: DeepSeek 分析    │
                    │  - 攻击类型识别            │
                    │  - 攻击者意图              │
                    │  - 攻击机理                │
                    │  - 缓解建议                │
                    └────────────┬───────────────┘
                                 ▼
                        返回详细诊断 + 建议
```

---

## 技术栈

- **前端**：Streamlit（重度自定义 CSS，仪表盘风格 UI）
- **Stage 1 模型**：BERT-base-uncased + PEFT (LoRA, r=8, alpha=16, target_modules=[query, value])
- **Stage 2 模型**：DeepSeek-V3（OpenAI 兼容接口，`response_format=json_object`）
- **推理后端**：PyTorch + Transformers
- **部署**：纯 CPU 可跑 Stage 1；Stage 2 需要 DeepSeek API

---

## 项目结构

```
NovaGuard-AI-System/
├── app.py                       # Streamlit 主界面与可视化（仪表盘 / Tab / 节点健康度）
├── main_pipeline.py             # 级联管线编排（Stage 1 → Stage 2）
├── threat_analyzer.py           # DeepSeek 威胁分析调用
├── best_lora_detector/          # LoRA-BERT 模型权重（适配器）
│   ├── adapter_config.json
│   ├── adapter_model.safetensors
│   ├── tokenizer.json
│   └── tokenizer_config.json
├── threat_cases.json            # 威胁签名库（子类 / 意图 / 分析）
├── frontend_demo_data.json      # 前端 Demo 案例（与威胁库联动）
├── requirements.txt
├── runtime.txt                  # python-3.11
└── README.md
```

---

## 快速开始

### 1. 环境准备

```bash
pip install -r requirements.txt
```

依赖关键项：`torch`, `transformers`, `peft`, `accelerate`, `streamlit`, `openai`, `safetensors`。

### 2. 配置 DeepSeek API Key

> ⚠️ **强烈推荐**：使用 `.env` 或环境变量注入 API key，**不要把 key 直接写在 `threat_analyzer.py` 中**（详见下方"安全提示"）。

```python
# threat_analyzer.py 推荐写法
import os
from openai import OpenAI

client = OpenAI(
    api_key=os.environ["DEEPSEEK_API_KEY"],
    base_url="https://api.deepseek.com"
)
```

设置环境变量：

```bash
# Linux / macOS
export DEEPSEEK_API_KEY="sk-xxxxxxxxxxxxxxxx"

# Windows PowerShell
$env:DEEPSEEK_API_KEY="sk-xxxxxxxxxxxxxxxx"
```

### 3. 启动应用

```bash
streamlit run app.py
```

浏览器打开 `http://localhost:8501` 即可使用。

### 4. 单独验证管线

```bash
python main_pipeline.py
```

会跑两个内置测试用例（Safe + Malicious），打印完整 JSON 输出。

---

## 检测模式

| 模式 | 阈值 | 适用场景 |
|------|------|----------|
| Strict | 0.35 | 高敏感场景，宁可误报也要拦截 |
| Balanced（默认） | 0.50 | 推荐默认 |
| Lenient | 0.75 | 低敏感场景，减少误报干扰 |

阈值对应 Stage 1 的 BERT risk_score：超过阈值即视为命中 Stage 2。

---

## 攻击类型覆盖

威胁签名库 `threat_cases.json` 与 DeepSeek 分析覆盖以下类别：

- **Jailbreak**（越狱指令）
- **Roleplay**（角色扮演绕过）
- **Hypothetical Scenario**（假设场景绕过）
- **Ethical Boundary Testing**（伦理边界探测）

每个攻击样本都包含：原始 prompt、攻击类型、攻击者意图、机理分析、缓解建议。

---

## ⚠️ 安全提示（重要）

如果 `threat_analyzer.py` 中**仍然硬编码了真实的 DeepSeek API key**，请立即按以下步骤处理：

1. **撤销旧 key**：登录 DeepSeek 平台 → API Keys → 删除已泄露的 key
2. **生成新 key**：创建新的 API key
3. **从代码中移除**：把 key 改为从环境变量读取（见上方"快速开始"）
4. **清理 Git 历史**（可选但推荐）：因为 key 已经在 commit 历史里，仅删除当前文件不够；可考虑：
   - 用 `git filter-repo` / `bfg` 清理历史后 force push
   - 或者在新仓库中重新提交（保留本地不含 key 的代码）
5. **加 `.env` 到 `.gitignore`**：确保 `.env` 文件不会被提交

> 即使你不再使用该 key，也必须撤销——GitHub 是公开仓库，任何人都能看到历史 commit。

---

## 关于作者

- 学校：马来亚大学（University of Malaya）
- 专业：数据科学硕士（Master of Data Science）

## 许可协议

MIT License。威胁签名库数据来源于公开 Jailbreak 评测集，仅用于安全研究。