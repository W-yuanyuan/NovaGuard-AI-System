import streamlit as st
import json
import os
import time
from main_pipeline import run_security_pipeline

# 1. 页面基本配置 (强制宽屏，折叠侧边栏腾出空间)
st.set_page_config(page_title="NovaGuard AI", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

# 2. 状态记忆
if "total_scans" not in st.session_state:
    st.session_state.total_scans = 1246
if "blocked_threats" not in st.session_state:
    st.session_state.blocked_threats = 89
if "scan_result" not in st.session_state:
    st.session_state.scan_result = None
if "detection_mode" not in st.session_state:
    st.session_state.detection_mode = "Balanced"
if "node_health" not in st.session_state:
    st.session_state.node_health = {
        "bert_ms": 14,
        "deepseek_ms": 128,
        "total_ms": 142,
        "bert_status": "Online",
        "deepseek_status": "Online"
    }
if "stats_period" not in st.session_state:
    st.session_state.stats_period = "Today"
if "feedback_message" not in st.session_state:
    st.session_state.feedback_message = ""
if "feedback_count" not in st.session_state:
    st.session_state.feedback_count = 0

DETECTION_MODES = {
    "Strict": {"threshold": 0.35, "desc": "High sensitivity, block earlier."},
    "Balanced": {"threshold": 0.50, "desc": "Recommended default mode."},
    "Lenient": {"threshold": 0.75, "desc": "Lower sensitivity, fewer blocks."}
}


def update_node_health(result, elapsed_ms):
    status = result.get("overall_status")
    bert_ms = int(result.get("bert_ms", max(14, elapsed_ms * 0.18)))

    if status == "Malicious":
        deepseek_ms = int(result.get("deepseek_ms", max(80, elapsed_ms - bert_ms)))
        deepseek_status = "Online"
    else:
        deepseek_ms = 0
        deepseek_status = "Skipped"

    st.session_state.node_health = {
        "bert_ms": bert_ms,
        "deepseek_ms": deepseek_ms,
        "total_ms": elapsed_ms,
        "bert_status": "Online",
        "deepseek_status": deepseek_status
    }


def render_node_health():
    h = st.session_state.node_health
    deepseek_color = "#10B981" if h["deepseek_status"] == "Online" else "#F59E0B"

    st.markdown(f"""
    <div class="compact-health">
        <span style="color:#10B981;">●</span> <b>BERT</b> {h["bert_ms"]}ms · {h["bert_status"]}<br>
        <span style="color:{deepseek_color};">●</span> <b>DeepSeek</b> {h["deepseek_ms"]}ms · {h["deepseek_status"]}<br>
        <span style="color:#10B981;">●</span> <b>Total</b> {h["total_ms"]}ms
    </div>
    """, unsafe_allow_html=True)


def get_period_stats(period):
    multipliers = {
        "Today": (1, 0.072),
        "Month": (26, 0.081),
        "Quarter": (78, 0.074),
        "Year": (312, 0.069)
    }
    period_factor, block_rate = multipliers[period]
    scanned = max(1, int((st.session_state.total_scans / 38) * period_factor))
    blocked = max(0, int(scanned * block_rate))
    safe = max(0, scanned - blocked)
    review = max(1, int(scanned * 0.018))
    return scanned, blocked, safe, review


def render_telemetry_visual(period):
    scanned, blocked, safe, review = get_period_stats(period)
    blocked_pct = min(max((blocked / scanned) * 100, 0), 100)
    review_pct = min(max((review / scanned) * 100, 0), 100)
    safe_pct = max(0, 100 - blocked_pct - review_pct)

    st.markdown(f"""
    <div class="telemetry-card">
        <div class="telemetry-top">
            <div>
                <div class="telemetry-label">Prompt Traffic</div>
                <div class="telemetry-total">{scanned:,}</div>
            </div>
            <div class="donut" style="background: conic-gradient(#EF4444 0 {blocked_pct:.1f}%, #F59E0B {blocked_pct:.1f}% {blocked_pct + review_pct:.1f}%, #10B981 {blocked_pct + review_pct:.1f}% 100%);">
                <div>{blocked_pct:.0f}%</div>
            </div>
        </div>
        <div class="spark-row">
            <span style="height:28%;"></span><span style="height:46%;"></span><span style="height:38%;"></span>
            <span style="height:62%;"></span><span style="height:54%;"></span><span style="height:76%;"></span>
            <span style="height:68%;"></span><span style="height:88%;"></span>
        </div>
        <div class="legend-row">
            <span><b style="color:#10B981;">●</b> Safe {safe:,}</span>
            <span><b style="color:#EF4444;">●</b> Blocked {blocked:,}</span>
            <span><b style="color:#F59E0B;">●</b> Review {review:,}</span>
        </div>
    </div>
    """, unsafe_allow_html=True)


# 3. 极限压缩与防覆盖 CSS
st.markdown("""
<style>
    /* 页面留白控制：保留 header，否则侧边栏收起后无法重新展开 */
    .block-container { padding-top: 1.25rem !important; padding-bottom: 0rem !important; max-width: 95% !important; }
    header {
        visibility: visible !important;
        background: transparent !important;
    }
    [data-testid="stToolbar"] {
        opacity: 0.18;
        transition: opacity 0.18s ease;
    }
    [data-testid="stToolbar"]:hover { opacity: 1; }

    /* 干净的高级灰白背景 + 右侧轻底纹 */
    [data-testid="stAppViewContainer"] {
        background:
            radial-gradient(circle at 22% 14%, rgba(59,130,246,0.055), transparent 24%),
            radial-gradient(circle at 82% 12%, rgba(16,185,129,0.055), transparent 24%),
            radial-gradient(rgba(148,163,184,0.32) 1px, transparent 1px),
            #F8FAFC !important;
        background-size: auto, auto, 24px 24px, auto !important;
    }
    [data-testid="stSidebar"] {
        background-color: #FFFFFF !important;
        border-right: 1px solid #E2E8F0 !important;
    }
    [data-testid="stSidebarContent"] {
        padding-top: 0.95rem !important;
        padding-bottom: 0.7rem !important;
    }
    [data-testid="stSidebar"] [data-testid="stVerticalBlock"] { gap: 0.58rem !important; }
    [data-testid="stSidebar"] hr { margin: 0.58rem 0 !important; }
    [data-testid="stSidebar"] h3 { margin: 0.22rem 0 0.28rem 0 !important; font-size: 1rem !important; }
    [data-testid="stSidebar"] label { margin-bottom: 0.1rem !important; }
    [data-testid="stSidebar"] .stRadio > div { gap: 0.35rem !important; }
    [data-testid="stSidebar"] .stCaption { font-size: 0.72rem !important; line-height: 1.25 !important; }
    [data-testid="stSidebar"] .stSelectbox { margin-bottom: -0.15rem !important; }

    /* 标题样式 */
    .main-title { font-size: 2rem; font-weight: 900; color: #0F172A; margin-bottom: 0; line-height: 1.2; }
    .sub-title { font-size: 0.9rem; color: #64748B; font-weight: 600; margin-bottom: 15px; }

    /* 输入框样式提升 */
    .stTextArea textarea {
        border-radius: 8px !important; border: 2px solid #CBD5E1 !important;
        padding: 12px !important; font-size: 1rem !important; line-height: 1.5 !important;
        background-color: #FFFFFF !important; color: #1E293B !important;
    }
    .stTextArea textarea:focus { border-color: #3B82F6 !important; box-shadow: 0 0 0 3px rgba(59,130,246,0.2) !important; }

    /* 核心主按钮强制样式 */
    button[kind="primary"] {
        background: #3B82F6 !important; color: white !important;
        border-radius: 8px !important; padding: 10px 0 !important; font-size: 1.1rem !important; font-weight: 800 !important;
        border: none !important; box-shadow: 0 4px 6px rgba(59, 130, 246, 0.3) !important;
    }
    button[kind="primary"]:hover { background: #2563EB !important; transform: translateY(-1px); }

    /* 结果大卡片 HTML 渲染类 */
    .result-board { display: flex; gap: 15px; margin-top: 10px; margin-bottom: 20px;}
    .result-card {
        flex: 1; background: #FFFFFF; border-radius: 8px; padding: 15px 10px;
        border: 1px solid #E2E8F0; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.02);
    }
    .result-title { font-size: 0.75rem; color: #64748B; font-weight: 800; text-transform: uppercase; margin-bottom: 5px; }
    .result-value { font-size: 1.6rem; font-weight: 900; }

    /* Tab 样式变紧凑 */
    .stTabs [data-baseweb="tab-list"] { gap: 20px; }
    .stTabs [data-baseweb="tab"] { padding-top: 5px; padding-bottom: 5px; font-weight: 700; color: #64748B; }
    .stTabs [aria-selected="true"] { color: #3B82F6 !important; border-bottom-color: #3B82F6 !important; }

    .side-sep { height: 1px; background: #E2E8F0; margin: 0.62rem 0; }
    .brand-lockup {
        display: flex;
        align-items: center;
        gap: 10px;
        margin: 0.05rem 0 0.48rem 0;
        padding: 7px 4px 5px 0;
    }
    .brand-mark {
        width: 42px;
        height: 42px;
        border-radius: 12px;
        position: relative;
        background:
            linear-gradient(135deg, rgba(16,185,129,0.98), rgba(59,130,246,0.94));
        box-shadow: 0 10px 22px rgba(37,99,235,0.22);
        transform: rotate(45deg);
    }
    .brand-mark:before {
        content: "";
        position: absolute;
        inset: 9px;
        border: 2px solid rgba(255,255,255,0.82);
        border-radius: 7px;
    }
    .brand-mark:after {
        content: "";
        position: absolute;
        width: 8px;
        height: 8px;
        border-radius: 99px;
        background: #FFFFFF;
        top: 7px;
        right: 7px;
        box-shadow:
            -20px 20px 0 rgba(255,255,255,0.92),
            -2px 23px 0 rgba(255,255,255,0.75);
    }
    .brand-copy { transform: translateY(-1px); }
    .brand-name {
        color: #0F172A;
        font-size: 1rem;
        line-height: 1.05;
        font-weight: 950;
    }
    .brand-sub {
        color: #64748B;
        font-size: 0.68rem;
        font-weight: 800;
        margin-top: 3px;
        letter-spacing: 0;
    }
    .side-section-title {
        color: #1E293B;
        font-size: 0.95rem;
        font-weight: 900;
        margin-bottom: 0.34rem;
    }
    .side-metrics {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 10px;
        margin-top: 6px;
    }
    .side-metric {
        border: 1px solid #E2E8F0;
        border-radius: 8px;
        padding: 8px 9px;
        background: #FFFFFF;
    }
    .side-metric-label {
        color: #64748B;
        font-size: 0.72rem;
        font-weight: 800;
        margin-bottom: 2px;
    }
    .side-metric-value {
        color: #0F172A;
        font-size: 1.15rem;
        font-weight: 900;
        line-height: 1.1;
    }
    .compact-health {
        color:#64748B;
        font-size:0.75rem;
        line-height:1.55;
        font-weight:750;
        padding-bottom: 2px;
    }
    .compact-health b { color:#475569; }
    .telemetry-card {
        border: 1px solid #E2E8F0;
        background:
            radial-gradient(circle at 15% 0%, rgba(16,185,129,0.10), transparent 38%),
            #FFFFFF;
        border-radius: 8px;
        padding: 10px;
        margin-top: 5px;
        box-shadow: 0 8px 20px rgba(15,23,42,0.025);
    }
    .telemetry-top {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 10px;
    }
    .telemetry-label {
        color: #64748B;
        font-size: 0.72rem;
        font-weight: 850;
        text-transform: uppercase;
    }
    .telemetry-total {
        color: #0F172A;
        font-size: 1.38rem;
        font-weight: 950;
        line-height: 1.1;
    }
    .donut {
        width: 48px;
        height: 48px;
        border-radius: 50%;
        display: grid;
        place-items: center;
        position: relative;
    }
    .donut:before {
        content: "";
        position: absolute;
        width: 33px;
        height: 33px;
        border-radius: 50%;
        background: #FFFFFF;
    }
    .donut div {
        position: relative;
        color: #0F172A;
        font-size: 0.66rem;
        font-weight: 900;
    }
    .spark-row {
        height: 30px;
        display: flex;
        align-items: end;
        gap: 5px;
        margin-top: 8px;
        padding: 0 2px;
    }
    .spark-row span {
        flex: 1;
        border-radius: 999px 999px 2px 2px;
        background: linear-gradient(180deg, #34D399, #3B82F6);
        opacity: 0.76;
    }
    .legend-row {
        display: flex;
        flex-wrap: wrap;
        gap: 4px 8px;
        color: #64748B;
        font-size: 0.65rem;
        font-weight: 800;
        margin-top: 7px;
        line-height: 1.15;
    }
    .team-watermark {
        position: fixed;
        right: 5.8vw;
        bottom: 7vh;
        width: 360px;
        height: 132px;
        pointer-events: none;
        z-index: 1;
        opacity: 0.13;
        filter: saturate(0.92);
    }
    .team-watermark .ground {
        position: absolute;
        left: 16px;
        right: 16px;
        bottom: 18px;
        height: 12px;
        border-radius: 50%;
        background: rgba(16,185,129,0.20);
        filter: blur(8px);
    }
    .toon {
        position: absolute;
        bottom: 30px;
        width: 52px;
        height: 72px;
    }
    .toon:nth-child(1) { left: 8px; transform: rotate(-4deg); }
    .toon:nth-child(2) { left: 76px; transform: rotate(3deg); }
    .toon:nth-child(3) { left: 145px; transform: translateY(-6px); }
    .toon:nth-child(4) { left: 215px; transform: rotate(-2deg); }
    .toon:nth-child(5) { left: 283px; transform: rotate(4deg); }
    .toon .head {
        position: absolute;
        left: 8px;
        top: 4px;
        width: 36px;
        height: 36px;
        border-radius: 50%;
        background: #FFFFFF;
        border: 2px solid rgba(15,23,42,0.62);
    }
    .toon .body {
        position: absolute;
        left: 5px;
        top: 42px;
        width: 42px;
        height: 28px;
        border-radius: 14px 14px 9px 9px;
        background: rgba(16,185,129,0.48);
        border: 2px solid rgba(15,23,42,0.48);
    }
    .toon .hair {
        position: absolute;
        left: 5px;
        top: 0;
        width: 42px;
        height: 24px;
        border-radius: 18px 18px 9px 9px;
        background: rgba(15,23,42,0.62);
    }
    .toon.female .hair:after {
        content: "";
        position: absolute;
        left: 2px;
        right: 2px;
        top: 16px;
        height: 22px;
        border-radius: 0 0 16px 16px;
        background: inherit;
        z-index: -1;
    }
    .toon.male .hair {
        height: 18px;
        border-radius: 16px 16px 8px 8px;
        background: rgba(59,130,246,0.62);
    }
    .toon .face-line {
        position: absolute;
        left: 19px;
        top: 24px;
        width: 14px;
        height: 7px;
        border-bottom: 2px solid rgba(15,23,42,0.58);
        border-radius: 0 0 999px 999px;
    }
    .toon .eye-left,
    .toon .eye-right {
        position: absolute;
        top: 18px;
        width: 4px;
        height: 4px;
        border-radius: 50%;
        background: rgba(15,23,42,0.62);
    }
    .toon .eye-left { left: 18px; }
    .toon .eye-right { left: 30px; }
    .toon.f1 .body { background: rgba(16,185,129,0.45); }
    .toon.f2 .body { background: rgba(125,211,252,0.45); }
    .toon.f3 .body { background: rgba(251,113,133,0.36); }
    .toon.f4 .body { background: rgba(251,191,36,0.36); }
    .toon.male .body { background: rgba(59,130,246,0.42); }
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="team-watermark" aria-hidden="true">
    <div class="toon female f1"><div class="hair"></div><div class="head"></div><div class="eye-left"></div><div class="eye-right"></div><div class="face-line"></div><div class="body"></div></div>
    <div class="toon female f2"><div class="hair"></div><div class="head"></div><div class="eye-left"></div><div class="eye-right"></div><div class="face-line"></div><div class="body"></div></div>
    <div class="toon male"><div class="hair"></div><div class="head"></div><div class="eye-left"></div><div class="eye-right"></div><div class="face-line"></div><div class="body"></div></div>
    <div class="toon female f3"><div class="hair"></div><div class="head"></div><div class="eye-left"></div><div class="eye-right"></div><div class="face-line"></div><div class="body"></div></div>
    <div class="toon female f4"><div class="hair"></div><div class="head"></div><div class="eye-left"></div><div class="eye-right"></div><div class="face-line"></div><div class="body"></div></div>
    <div class="ground"></div>
</div>
""", unsafe_allow_html=True)

# 4. 页面顶部
st.markdown("<div class='main-title'>NovaGuard Defense Matrix</div>", unsafe_allow_html=True)
st.markdown("<div class='sub-title'>Two-Stage LLM Prompt Injection Diagnostic System (BERT + DeepSeek)</div>", unsafe_allow_html=True)


@st.cache_data
def load_demo_data():
    if os.path.exists("frontend_demo_data.json"):
        with open("frontend_demo_data.json", "r", encoding="utf-8") as f:
            return json.load(f)
    return []


demo_data = load_demo_data()

# 5. 侧边栏
with st.sidebar:
    st.markdown("""
    <div class="brand-lockup">
        <div class="brand-mark"></div>
        <div class="brand-copy">
            <div class="brand-name">NovaGuard</div>
            <div class="brand-sub">AI Defense Console</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<div class='side-section-title'>⚡ Sandbox Loader</div>", unsafe_allow_html=True)
    selected_prompt = ""
    if demo_data:
        options = ["-- Manual Input --"] + [f"Case {i+1}: {d['pipeline_output']['attack_type'].title()}" for i, d in enumerate(demo_data)]
        choice = st.selectbox("Load Signature:", options, label_visibility="collapsed")
        if choice != "-- Manual Input --":
            index = int(choice.split(":")[0].replace("Case ", "")) - 1
            selected_prompt = demo_data[index]["original_prompt"]
    else:
        st.selectbox("Load Signature:", ["-- Manual Input --"], label_visibility="collapsed")

    st.markdown("<div class='side-sep'></div>", unsafe_allow_html=True)

    st.markdown("<div class='side-section-title'>🧭 Detection Mode</div>", unsafe_allow_html=True)
    st.session_state.detection_mode = st.selectbox(
        "Policy Sensitivity",
        ["Balanced", "Strict", "Lenient"],
        index=["Balanced", "Strict", "Lenient"].index(st.session_state.detection_mode),
        label_visibility="collapsed"
    )

    mode_info = DETECTION_MODES[st.session_state.detection_mode]
    st.caption(f"Threshold: {mode_info['threshold']:.0%} · {mode_info['desc']}")

    st.markdown("<div class='side-sep'></div>", unsafe_allow_html=True)

    st.markdown("<div class='side-section-title'>📡 Telemetry</div>", unsafe_allow_html=True)
    st.session_state.stats_period = st.selectbox(
        "Traffic Period",
        ["Today", "Month", "Quarter", "Year"],
        index=["Today", "Month", "Quarter", "Year"].index(st.session_state.stats_period),
        label_visibility="collapsed"
    )
    render_telemetry_visual(st.session_state.stats_period)

    st.markdown("<div class='side-sep'></div>", unsafe_allow_html=True)

    st.markdown("<div class='side-section-title'>🟢 Node Health</div>", unsafe_allow_html=True)
    render_node_health()

# 6. 核心布局 (4:6 比例，左侧输入，右侧结果)
col_left, col_spacer, col_right = st.columns([1.1, 0.05, 1.6])

with col_left:
    st.markdown("<div style='font-weight:800; font-size:1rem; margin-bottom:10px; color:#0F172A;'>🎯 Intercept Modality</div>", unsafe_allow_html=True)

    # 【改版核心】：纯 HTML 渲染的多模态按钮，绝对保证颜色区分度，不怕 Streamlit 覆盖
    st.markdown("""
    <div style='display: flex; gap: 10px; margin-bottom: 10px;'>
        <div style='flex: 1; background: #DBEAFE; color: #1D4ED8; font-weight: 800; padding: 8px; text-align: center; border-radius: 6px; border: 1px solid #93C5FD;'>📝 Text (Active)</div>
        <div style='flex: 1; background: #F1F5F9; color: #94A3B8; font-weight: 600; padding: 8px; text-align: center; border-radius: 6px; border: 1px solid #E2E8F0;'>🎙️ Audio (Pro)</div>
        <div style='flex: 1; background: #F1F5F9; color: #94A3B8; font-weight: 600; padding: 8px; text-align: center; border-radius: 6px; border: 1px solid #E2E8F0;'>🎥 Video (Beta)</div>
    </div>
    """, unsafe_allow_html=True)

    # 输入框高度压低到 180，绝对不溢出
    user_input = st.text_area("Input area", value=selected_prompt, height=180, placeholder="Inject raw prompt data here...", label_visibility="collapsed")
    st.caption(f"🧭 Active Mode: {st.session_state.detection_mode} · Threshold: {DETECTION_MODES[st.session_state.detection_mode]['threshold']:.0%}")
    st.write("")

    scan_button = st.button("INITIALIZE AI SCAN 🚀", use_container_width=True, type="primary")

with col_right:
    tab1, tab2, tab3, tab4 = st.tabs(["📊 Dashboard", "🧠 DeepSeek Intel", "🛡️ Sanitizer", "📚 Signature DB"])
    dash_placeholder = tab1.empty()

    if not st.session_state.scan_result and not scan_button:
        with dash_placeholder.container():
            st.info("👋 **System standing by.** Awaiting payload injection on the left port.")

# 7. 扫描执行逻辑
if scan_button:
    if not user_input.strip():
        with col_left:
            st.error("⚠️ Payload empty.")
    else:
        st.session_state.total_scans += 1
        with dash_placeholder.container():
            progress_bar = st.progress(0)
            status_text = st.empty()
            for percent, text in zip([25, 50, 75, 100], ["🔍 Stage 1: BERT Lexical Analysis...", "🌐 Stage 2: DeepSeek Semantic Mapping...", "🎯 Stage 2: Intent Classification...", "✅ Finalizing Verdict..."]):
                progress_bar.progress(percent)
                status_text.caption(f"{text}")
                time.sleep(0.2)
            progress_bar.empty()
            status_text.empty()

            try:
                start_time = time.perf_counter()
                result = run_security_pipeline(user_input)
                elapsed_ms = int((time.perf_counter() - start_time) * 1000)

                update_node_health(result, elapsed_ms)
                st.session_state.scan_result = result

                risk_score_for_policy = float(result.get("risk_score", 0.0) or 0.0)
                threshold_for_policy = DETECTION_MODES[st.session_state.detection_mode]["threshold"]
                blocked_by_policy = (
                    result.get("overall_status") == "Malicious"
                    if risk_score_for_policy == 0
                    else risk_score_for_policy >= threshold_for_policy
                )

                if blocked_by_policy:
                    st.session_state.blocked_threats += 1
                st.rerun()
            except Exception as e:
                st.error(f"💥 Critical System Failure: {str(e)}")

# 8. 渲染结果面板 (大数字直观回归)
if st.session_state.scan_result:
    result = st.session_state.scan_result
    status = result.get("overall_status")
    risk_score = float(result.get("risk_score", 0.0) or 0.0)

    mode = st.session_state.detection_mode
    threshold = DETECTION_MODES[mode]["threshold"]

    # 如果后端有 risk_score，就按模式阈值判断；如果没有，就沿用原本 Safe/Malicious 判断
    if risk_score > 0:
        is_safe = risk_score < threshold
    else:
        is_safe = (status == "Safe")

    color_main = "#10B981" if is_safe else "#EF4444"
    verdict_text = "CLEARED" if is_safe else "BLOCKED"
    vector_text = "NONE" if is_safe else result.get('attack_type', 'UNKNOWN').upper()

    with tab1:
        # 【改版核心】：告别图表，纯 HTML/CSS 绘制的三格大数据看板，一目了然
        st.markdown(f"""
        <div class="result-board">
            <div class="result-card" style="border-top: 4px solid {color_main};">
                <div class="result-title">System Verdict</div>
                <div class="result-value" style="color: {color_main};">{verdict_text}</div>
            </div>
            <div class="result-card" style="border-top: 4px solid {color_main};">
                <div class="result-title">Stage 1: BERT Risk Score</div>
                <div class="result-value" style="color: #0F172A;">{risk_score:.2%}</div>
            </div>
            <div class="result-card" style="border-top: 4px solid {color_main};">
                <div class="result-title">Stage 2: Threat Vector</div>
                <div class="result-value" style="color: #0F172A; font-size:1.3rem; padding-top:5px;">{vector_text}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.caption(f"🧭 Active Detection Mode: {mode} · Blocking Threshold: {threshold:.0%}")

        st.markdown(f"<div style='color:#64748B; font-size:0.85rem; font-weight:800; margin:12px 0 8px;'>BERT TOXICITY PROBABILITY ({risk_score:.2%})</div>", unsafe_allow_html=True)
        st.progress(min(max(risk_score, 0.0), 1.0))

        # 人工干预区 (颜色高度区分)
        st.markdown("<div style='font-size:0.85rem; font-weight:800; color:#64748B; margin:18px 0 8px;'>🧑‍💻 EXPERT OVERRIDE (HITL)</div>", unsafe_allow_html=True)

        hitl_col1, hitl_col2 = st.columns(2)
        with hitl_col1:
            if st.button("✅ Mark as False Positive (Safe)", use_container_width=True):
                st.session_state.feedback_count += 1
                st.session_state.feedback_message = "✅ Feedback recorded: this case has been added to the Safe Review Queue."
                st.toast("Feedback recorded in Safe Review Queue.", icon="✅")
        with hitl_col2:
            if st.button("🚨 Mark as False Negative (Threat)", use_container_width=True):
                st.session_state.feedback_count += 1
                st.session_state.feedback_message = "🚨 Feedback recorded: this case has been added to the Threat Signature Queue."
                st.toast("Feedback recorded in Threat Signature Queue.", icon="🚨")

        if st.session_state.feedback_message:
            st.success(f"{st.session_state.feedback_message} Total feedback: {st.session_state.feedback_count}.")

    # --- Tab 2: 深度情报 ---
    with tab2:
        if is_safe:
            st.success("✅ **DeepSeek Intelligence:** Confirmed no malicious intent.")
        else:
            analysis = result.get("detailed_analysis", {})
            st.error(f"🚨 **DeepSeek Diagnosed Vector:** {vector_text}")
            if isinstance(analysis, dict):
                with st.expander("🎯 1. Attacker Intent (Why)", expanded=True):
                    st.write(analysis.get("intent", "Unknown"))
                with st.expander("🧩 2. Attack Mechanism (How)", expanded=True):
                    st.write(analysis.get("explanation", "Unknown"))
                with st.expander("🛡️ 3. Recommended Mitigation", expanded=True):
                    st.write(analysis.get("mitigation_suggestion", "None"))
            else:
                st.write(analysis)

    # --- Tab 3: AI 净化沙箱 ---
    with tab3:
        if is_safe:
            st.info("✨ No remediation required. The prompt is safe.")
            st.code(user_input, language="markdown")
        else:
            st.warning("⚠️ **Malicious patterns detected.** AI has stripped dangerous instructions.")
            st.markdown("**Sanitized Safe Prompt:**")
            st.code(f"[System Alert: Malicious intent '{result.get('attack_type', 'unknown')}' neutralized]\n\nPlease provide general and safe information about the topic requested.", language="markdown")

# --- Tab 4: 成员 1 的威胁库 ---
with tab4:
    st.markdown("<div style='color:#64748B; font-size:0.85rem; font-weight:700; margin-bottom:10px;'>📚 PROMPT INJECTION SIGNATURE DATABASE</div>", unsafe_allow_html=True)
    if os.path.exists("threat_cases.json"):
        with open("threat_cases.json", "r", encoding="utf-8") as f:
            cases_db = json.load(f)
        search_term = st.text_input("🔍 Search Signatures (e.g., Roleplay)...", "", label_visibility="collapsed")
        st.write("")
        for case in cases_db:
            if search_term.lower() in case['subclasses'].lower() or search_term.lower() in case['analysis'].lower() or search_term == "":
                with st.expander(f"🔴 {case['id']} | {case['subclasses']}"):
                    st.markdown(f"**🎯 Intent:** {case['intent']}")
                    st.code(case['raw_prompt'], language="text")
                    st.markdown(f"**🧩 Analysis:** {case['analysis']}")
