"""
Pixel-perfect AWS Architecture Diagram
Project 3: CloudTrail Threat Hunting Copilot
Uses Pillow for full layout control. Output: architecture.png
"""
import math
from PIL import Image, ImageDraw, ImageFont

# ── Canvas & DPI ──────────────────────────────────────────────────────────────
W, H   = 5600, 3600
BG     = "#0D1117"
SCALE  = 1          # drawn at full size; save at this scale

img  = Image.new("RGB", (W, H), BG)
draw = ImageDraw.Draw(img)

# ── Colour palette ────────────────────────────────────────────────────────────
ORANGE     = (255, 153,   0)
ORANGE_DIM = (140,  85,   0)
GREEN      = ( 46, 160,  67)
GREEN_LT   = ( 63, 185,  80)
BLUE       = ( 31, 111, 235)
BLUE_LT    = ( 88, 166, 255)
PURPLE     = (130,  80, 255)
PURPLE_LT  = (163, 113, 247)
PURPLE_DIM = (110,  64, 201)
TEAL       = ( 20, 184, 166)
TEAL_LT    = ( 57, 211, 187)
RED        = (248,  81,  73)
YELLOW     = (210, 153,  34)
GRAY       = (139, 148, 158)
GRAY_DIM   = ( 48,  54,  61)
WHITE      = (230, 237, 243)
OFF_WHITE  = (201, 209, 217)
CARD       = ( 22,  27,  34)
CARD2      = ( 28,  36,  54)
DARK_BG    = ( 13,  17,  23)

# ── Fonts (macOS Helvetica) ───────────────────────────────────────────────────
def font(size, bold=False):
    try:
        path = "/System/Library/Fonts/Helvetica.ttc"
        return ImageFont.truetype(path, size, index=1 if bold else 0)
    except Exception:
        return ImageFont.load_default()

F_TITLE    = font(54, bold=True)
F_SUBTITLE = font(28)
F_CLUSTER  = font(26, bold=True)
F_SVC_TITLE= font(24, bold=True)
F_SVC_SUB  = font(19)
F_LEGEND_H = font(22, bold=True)
F_LEGEND   = font(19)
F_STEP     = font(21, bold=True)
F_ARROW    = font(19)
F_ICON     = font(40)

# ─────────────────────────────────────────────────────────────────────────────
# Drawing primitives
# ─────────────────────────────────────────────────────────────────────────────
def rrect(x0, y0, x1, y1, r=18, fill=CARD2, outline=None, width=2):
    draw.rounded_rectangle([x0, y0, x1, y1], radius=r,
                           fill=fill, outline=outline, width=width)

def text_c(txt, cx, y, fnt, color=WHITE):
    """Draw text centred on cx."""
    bb  = draw.textbbox((0, 0), txt, font=fnt)
    tw  = bb[2] - bb[0]
    draw.text((cx - tw // 2, y), txt, font=fnt, fill=color)

def text_l(txt, x, y, fnt, color=WHITE):
    draw.text((x, y), txt, font=fnt, fill=color)

def cluster_box(x0, y0, x1, y1, label, color, r=22, lw=3):
    """Outer cluster rectangle with coloured border and label."""
    # semi-transparent fill via blending
    overlay = Image.new("RGB", (x1 - x0, y1 - y0), CARD)
    img.paste(overlay, (x0, y0))
    draw.rounded_rectangle([x0, y0, x1, y1], radius=r,
                           outline=color, width=lw)
    # label pill at top-left
    bb  = draw.textbbox((0, 0), label, font=F_CLUSTER)
    tw, th = bb[2] - bb[0], bb[3] - bb[1]
    px, py = 18, 10
    lx0, ly0 = x0 + 20, y0 - th - py * 2 - 2
    lx1, ly1 = lx0 + tw + px * 2, y0 - 2
    draw.rounded_rectangle([lx0, ly0, lx1, ly1], radius=10,
                           fill=color, outline=color, width=0)
    draw.text((lx0 + px, ly0 + py), label, font=F_CLUSTER, fill=DARK_BG)

def svc_card(x0, y0, x1, y1, icon, title, sub1, sub2="", accent=BLUE_LT):
    """Individual service card."""
    rrect(x0, y0, x1, y1, r=14, fill=CARD2, outline=GRAY_DIM, width=1)
    cx = (x0 + x1) // 2
    # accent top bar
    draw.rectangle([x0 + 1, y0 + 1, x1 - 1, y0 + 5], fill=accent)
    # icon
    text_c(icon, cx, y0 + 14, F_ICON)
    # title
    text_c(title, cx, y0 + 68, F_SVC_TITLE, WHITE)
    # sub1
    text_c(sub1, cx, y0 + 96, F_SVC_SUB, OFF_WHITE)
    if sub2:
        text_c(sub2, cx, y0 + 118, F_SVC_SUB, GRAY)

def mini_card(x0, y0, x1, y1, icon, title, sub, accent=BLUE_LT):
    """Smaller card for endpoint nodes."""
    rrect(x0, y0, x1, y1, r=12, fill=CARD2, outline=GRAY_DIM, width=1)
    cx = (x0 + x1) // 2
    draw.rectangle([x0 + 1, y0 + 1, x1 - 1, y0 + 4], fill=accent)
    text_c(icon, cx, y0 + 8,  font(28))
    text_c(title, cx, y0 + 46, font(18, bold=True), WHITE)
    text_c(sub,   cx, y0 + 68, font(16),            GRAY)

# ─────────────────────────────────────────────────────────────────────────────
# Arrow helpers
# ─────────────────────────────────────────────────────────────────────────────
def arrow(x0, y0, x1, y1, color=BLUE_LT, width=3, label="", step="",
          dashed=False, lx_off=0, ly_off=0):
    """Straight arrow with optional label. Points from (x0,y0) to (x1,y1)."""
    # dashed line
    if dashed:
        dx, dy  = x1 - x0, y1 - y0
        length  = max(math.hypot(dx, dy), 1)
        dash, gap = 18, 10
        steps   = int(length / (dash + gap))
        for i in range(steps + 1):
            t0 = i * (dash + gap) / length
            t1 = min((i * (dash + gap) + dash) / length, 1.0)
            draw.line([(x0 + dx * t0, y0 + dy * t0),
                       (x0 + dx * t1, y0 + dy * t1)],
                      fill=color, width=width)
    else:
        draw.line([(x0, y0), (x1, y1)], fill=color, width=width)

    # arrowhead
    angle = math.atan2(y1 - y0, x1 - x0)
    ah    = 16
    for sign in (+1, -1):
        ax = x1 - ah * math.cos(angle - sign * math.pi / 7)
        ay = y1 - ah * math.sin(angle - sign * math.pi / 7)
        draw.line([(x1, y1), (ax, ay)], fill=color, width=width + 1)

    # label
    if label or step:
        mx = (x0 + x1) // 2 + lx_off
        my = (y0 + y1) // 2 + ly_off - 14
        full = f"{step} {label}".strip() if step else label
        bb   = draw.textbbox((0, 0), full, font=F_STEP if step else F_ARROW)
        tw   = bb[2] - bb[0]
        # pill background
        pad = 7
        draw.rounded_rectangle(
            [mx - tw // 2 - pad, my - 2, mx + tw // 2 + pad, my + bb[3] - bb[1] + 4],
            radius=8, fill=DARK_BG
        )
        text_c(full, mx, my, F_STEP if step else F_ARROW, color)

def arrow_v(x, y0, y1, **kw):
    arrow(x, y0, x, y1, **kw)

def arrow_h(y, x0, x1, **kw):
    arrow(x0, y, x1, y, **kw)

def elbow(x0, y0, x1, y1, color=BLUE_LT, width=3, label="", step="",
          dashed=False, corner="right-down"):
    """Right-angle arrow: horizontal then vertical (or vice versa)."""
    if corner == "right-down":
        mid_x, mid_y = x1, y0
    else:  # down-right
        mid_x, mid_y = x0, y1

    if dashed:
        for seg in [(x0, y0, mid_x, mid_y), (mid_x, mid_y, x1, y1)]:
            arrow(*seg, color=color, width=width, dashed=True)
        # arrowhead only at final point
        angle = math.atan2(y1 - mid_y, x1 - mid_x)
        ah = 16
        for sign in (+1, -1):
            ax = x1 - ah * math.cos(angle - sign * math.pi / 7)
            ay = y1 - ah * math.sin(angle - sign * math.pi / 7)
            draw.line([(x1, y1), (ax, ay)], fill=color, width=width + 1)
    else:
        draw.line([(x0, y0), (mid_x, mid_y)], fill=color, width=width)
        arrow(mid_x, mid_y, x1, y1, color=color, width=width)

    if label or step:
        mx = (x0 + x1) // 2
        my = (y0 + y1) // 2 - 14
        full = f"{step} {label}".strip() if step else label
        bb   = draw.textbbox((0, 0), full, font=F_STEP if step else F_ARROW)
        tw   = bb[2] - bb[0]
        pad  = 7
        draw.rounded_rectangle(
            [mx - tw // 2 - pad, my - 2, mx + tw // 2 + pad, my + bb[3] - bb[1] + 4],
            radius=8, fill=DARK_BG
        )
        text_c(full, mx, my, F_STEP if step else F_ARROW, color)

# ─────────────────────────────────────────────────────────────────────────────
# LAYOUT  — all coordinates
# ─────────────────────────────────────────────────────────────────────────────
M   = 60          # outer margin
PAD = 50          # cluster inner padding
CW  = 280         # standard card width
CH  = 150         # standard card height
MCW = 200         # mini card width
MCH = 92          # mini card height

# ── HEADER ────────────────────────────────────────────────────────────────────
rrect(M, M, W - M, 170, r=16, fill=CARD, outline=ORANGE, width=3)
# orange accent line
draw.rectangle([M + 1, M + 1, W - M - 1, M + 7], fill=ORANGE)
text_c("Project 3 — CloudTrail Threat Hunting Copilot",
       W // 2, M + 22, F_TITLE, ORANGE)
text_c("AWS Architecture  |  Amazon Bedrock (Claude 3.5 Sonnet)  |  Amazon Athena  |  ECS Fargate  |  EventBridge Scheduler  |  WAF  |  CloudTrail",
       W // 2, M + 96, F_SUBTITLE, GRAY)

# ── ROW 1: ANALYST  +  PUBLIC UI LAYER ───────────────────────────────────────
ROW1_Y = 230   # top of row 1 content (cluster top)
ROW1_H = 220   # cluster height

# Analyst
AX0, AY0, AX1, AY1 = M, ROW1_Y, M + CW, ROW1_Y + ROW1_H
svc_card(AX0, AY0, AX1, AY1, "👤", "Security Analyst",
         "Threat Hunter / SOC Engineer", accent=TEAL_LT)

# Public UI Layer cluster
UI_X0, UI_Y0 = M + CW + 100, ROW1_Y - 48
UI_X1, UI_Y1 = W - M, ROW1_Y + ROW1_H + 20

cluster_box(UI_X0, UI_Y0, UI_X1, UI_Y1, "Public UI Layer", GREEN_LT, lw=2)

card_y0, card_y1 = ROW1_Y, ROW1_Y + ROW1_H
ui_gap = 30
igw_x0 = UI_X0 + PAD
igw_x1 = igw_x0 + CW
waf_x0 = igw_x1 + ui_gap;  waf_x1 = waf_x0 + CW
alb_x0 = waf_x1 + ui_gap;  alb_x1 = alb_x0 + CW
ui_x0  = alb_x1 + ui_gap;  ui_x1  = ui_x0  + CW
ecr_x0 = ui_x1  + ui_gap;  ecr_x1 = ecr_x0 + CW

svc_card(igw_x0, card_y0, igw_x1, card_y1, "🌐", "Internet Gateway",
         "VPC public entry point", accent=GREEN_LT)
svc_card(waf_x0, card_y0, waf_x1, card_y1, "🛡", "AWS WAF v2",
         "OWASP CRS + IP + Rate limit", "SQLi protection", accent=RED)
svc_card(alb_x0, card_y0, alb_x1, card_y1, "⚖", "App Load Balancer",
         "HTTPS :443  TLS 1.3", "WAF attached  access logs", accent=GREEN_LT)
svc_card(ui_x0,  card_y0, ui_x1,  card_y1, "💬", "Streamlit Chat UI",
         "ECS Fargate  port 8501", "Private subnet  auto-scaling", accent=TEAL_LT)
svc_card(ecr_x0, card_y0, ecr_x1, card_y1, "📦", "Amazon ECR",
         "Streamlit image", "Scan-on-push  KMS", accent=BLUE_LT)

# ── ROW 2: API GATEWAY ────────────────────────────────────────────────────────
ROW2_Y = ROW1_Y + ROW1_H + 90
api_cx = (alb_x0 + alb_x1) // 2
api_x0 = api_cx - CW // 2;  api_x1 = api_x0 + CW
api_y0 = ROW2_Y;             api_y1 = ROW2_Y + CH
svc_card(api_x0, api_y0, api_x1, api_y1, "🔗", "API Gateway REST",
         "POST /query  GET /health", "Usage plan  20 rps  X-Ray", accent=BLUE_LT)

# ── ROW 3: VPC ────────────────────────────────────────────────────────────────
ROW3_Y  = api_y1 + 90
VPC_X0  = M
VPC_Y0  = ROW3_Y - 52
VPC_X1  = W - M
VPC_Y1  = ROW3_Y + 480

cluster_box(VPC_X0, VPC_Y0, VPC_X1, VPC_Y1, "VPC  10.10.0.0/16  —  Private Subnets", ORANGE, lw=3)

# Lambda sub-cluster
LAM_X0, LAM_Y0 = VPC_X0 + PAD, ROW3_Y
LAM_X1, LAM_Y1 = LAM_X0 + 620, VPC_Y1 - PAD
cluster_box(LAM_X0, LAM_Y0, LAM_X1, LAM_Y1, "Lambda Functions  (Python 3.12)", YELLOW, lw=2)

cop_x0 = LAM_X0 + 20; cop_x1 = cop_x0 + CW
cop_y0 = ROW3_Y + 20; cop_y1 = cop_y0 + CH + 30
sched_x0 = cop_x1 + 20; sched_x1 = LAM_X1 - 20
sched_y0 = cop_y0;       sched_y1 = cop_y1

svc_card(cop_x0, cop_y0, cop_x1, cop_y1, "λ", "Copilot Lambda",
         "NL to SQL  Execute  Analyze", "512 MB  5 min  X-Ray  IAM role", accent=YELLOW)
svc_card(sched_x0, sched_y0, sched_x1, sched_y1, "λ", "Scheduled Hunt Lambda",
         "10 predefined threat hunt queries", "Nightly  SNS on HIGH/CRITICAL", accent=YELLOW)

# NAT Gateway
nat_x0 = LAM_X1 + 30;  nat_x1 = nat_x0 + CW
nat_y0 = ROW3_Y + (VPC_Y1 - PAD - ROW3_Y) // 2 - CH // 2
nat_y1 = nat_y0 + CH
svc_card(nat_x0, nat_y0, nat_x1, nat_y1, "🔀", "NAT Gateway",
         "Outbound internet", "HA per AZ", accent=ORANGE)

# VPC Endpoints sub-cluster
EP_X0 = nat_x1 + 30;  EP_X1 = VPC_X1 - PAD
EP_Y0 = ROW3_Y;       EP_Y1 = VPC_Y1 - PAD
cluster_box(EP_X0, EP_Y0, EP_X1, EP_Y1,
            "VPC Interface Endpoints  (PrivateLink — AI traffic stays private)", BLUE_LT, lw=2)

ep_gap = 16
ep_total_w = EP_X1 - EP_X0 - 40
ep_cw = (ep_total_w - ep_gap * 4) // 5
ep_y0 = EP_Y0 + 28;  ep_y1 = EP_Y1 - 20

endpoints = [
    ("🔐", "Bedrock", "PrivateLink"),
    ("🔐", "Athena",  "PrivateLink"),
    ("🔐", "S3 GW",   "Free gateway"),
    ("🔐", "SNS",     "PrivateLink"),
    ("🔐", "CW Logs", "PrivateLink"),
]
ep_positions = []
for i, (ico, t, s) in enumerate(endpoints):
    ex0 = EP_X0 + 20 + i * (ep_cw + ep_gap)
    ex1 = ex0 + ep_cw
    mini_card(ex0, ep_y0, ex1, ep_y1, ico, t, s, accent=BLUE_LT)
    ep_positions.append(((ex0 + ex1) // 2, (ep_y0 + ep_y1) // 2))

ep_bed_cx, ep_bed_cy  = ep_positions[0]
ep_ath_cx, ep_ath_cy  = ep_positions[1]
ep_s3_cx,  ep_s3_cy   = ep_positions[2]
ep_sns_cx, ep_sns_cy  = ep_positions[3]
ep_logs_cx, ep_logs_cy= ep_positions[4]

# ── ROW 4: BEDROCK  +  DATA LAYER ────────────────────────────────────────────
ROW4_Y = VPC_Y1 + 90

# Bedrock cluster
BR_X0 = M;           BR_X1 = M + CW * 2 + 60
BR_Y0 = ROW4_Y - 46; BR_Y1 = ROW4_Y + CH * 2 + 80
cluster_box(BR_X0, BR_Y0, BR_X1, BR_Y1, "Amazon Bedrock  (Managed Service)", PURPLE_LT, lw=2)

br1_x0 = BR_X0 + 20; br1_x1 = BR_X1 - 20
br1_y0 = ROW4_Y;     br1_y1 = ROW4_Y + CH + 20
br2_y0 = br1_y1 + 20; br2_y1 = BR_Y1 - 20

svc_card(br1_x0, br1_y0, br1_x1, br1_y1, "🤖", "Claude 3.5 Sonnet",
         "Stage (1)  NL to Athena SQL", "Schema-aware  context-injected", accent=PURPLE_LT)
svc_card(br1_x0, br2_y0, br1_x1, br2_y1, "🧠", "Claude 3.5 Sonnet",
         "Stage (3)  Threat Analysis", "MITRE ATT&CK  Risk Score 0-100", accent=PURPLE_LT)

br1_cx = (br1_x0 + br1_x1) // 2
br2_cx = br1_cx

# Data Layer cluster
DL_X0 = BR_X1 + 50;  DL_X1 = DL_X0 + 1400
DL_Y0 = ROW4_Y - 46; DL_Y1 = BR_Y1

cluster_box(DL_X0, DL_Y0, DL_X1, DL_Y1, "Data Layer", PURPLE_DIM, lw=2)

dl_gap = 20
dl_cw  = (DL_X1 - DL_X0 - PAD * 2 - dl_gap * 2) // 3

# Sub-section: Log Delivery
LD_X0 = DL_X0 + PAD;       LD_X1 = LD_X0 + dl_cw
LD_Y0 = ROW4_Y;             LD_Y1 = DL_Y1 - PAD
cluster_box(LD_X0, LD_Y0, LD_X1, LD_Y1, "Log Delivery", PURPLE_DIM, lw=1)
trail_y0 = LD_Y0 + 20; trail_y1 = trail_y0 + CH
logs_y0  = trail_y1 + 20; logs_y1 = LD_Y1 - 20
svc_card(LD_X0 + 10, trail_y0, LD_X1 - 10, trail_y1,
         "📋", "AWS CloudTrail", "Multi-region  all events", "S3 data events + validation", accent=PURPLE_LT)
svc_card(LD_X0 + 10, logs_y0, LD_X1 - 10, logs_y1,
         "🪣", "S3 CloudTrail Logs", "KMS encrypted  versioned", "IA 30d  Glacier 90d", accent=PURPLE_LT)

# Sub-section: Glue Catalog
GC_X0 = LD_X1 + dl_gap;    GC_X1 = GC_X0 + dl_cw
GC_Y0 = ROW4_Y;             GC_Y1 = DL_Y1 - PAD
cluster_box(GC_X0, GC_Y0, GC_X1, GC_Y1, "Glue Catalog", PURPLE_DIM, lw=1)
craw_y0 = GC_Y0 + 20; craw_y1 = craw_y0 + CH
cat_y0  = craw_y1 + 20; cat_y1 = GC_Y1 - 20
svc_card(GC_X0 + 10, craw_y0, GC_X1 - 10, craw_y1,
         "🕷", "Glue Crawler", "Daily 03:00 UTC", "Auto-partition discovery", accent=PURPLE_LT)
svc_card(GC_X0 + 10, cat_y0, GC_X1 - 10, cat_y1,
         "📂", "Glue Data Catalog", "CloudTrail schema  24 cols", "Partition projection", accent=PURPLE_LT)

# Sub-section: Query Engine
QE_X0 = GC_X1 + dl_gap;    QE_X1 = DL_X1 - PAD
QE_Y0 = ROW4_Y;             QE_Y1 = DL_Y1 - PAD
cluster_box(QE_X0, QE_Y0, QE_X1, QE_Y1, "Query Engine", PURPLE_DIM, lw=1)
ath_y0  = QE_Y0 + 20; ath_y1  = ath_y0 + CH
aus3_y0 = ath_y1 + 20; aus3_y1 = QE_Y1 - 20
svc_card(QE_X0 + 10, ath_y0,  QE_X1 - 10, ath_y1,
         "🔍", "Amazon Athena", "Workgroup  10 GB/query cap", "8 named hunt queries  pay/scan", accent=PURPLE_LT)
svc_card(QE_X0 + 10, aus3_y0, QE_X1 - 10, aus3_y1,
         "🪣", "S3 Audit Bucket", "Athena results  analyses", "WAF + ALB logs  SSL enforced", accent=PURPLE_LT)

# centre x-coords for data cards
trail_cx = (LD_X0 + LD_X1) // 2
logs_cx  = trail_cx
craw_cx  = (GC_X0 + GC_X1) // 2
cat_cx   = craw_cx
ath_cx   = (QE_X0 + QE_X1) // 2
aus3_cx  = ath_cx

# ── ROW 5: SCHEDULING  +  OBSERVABILITY ──────────────────────────────────────
ROW5_Y = DL_Y1 + 90

# Scheduling cluster
SC_X0 = M;             SC_X1 = M + CW * 2 + 60
SC_Y0 = ROW5_Y - 46;  SC_Y1 = ROW5_Y + CH * 2 + 80
cluster_box(SC_X0, SC_Y0, SC_X1, SC_Y1, "Scheduling & Alerting", ORANGE, lw=2)
sch_y0 = ROW5_Y;      sch_y1 = sch_y0 + CH + 20
sns_y0 = sch_y1 + 20; sns_y1 = SC_Y1 - 20
svc_card(SC_X0 + 20, sch_y0, SC_X1 - 20, sch_y1, "⏰", "EventBridge Scheduler",
         "cron(0 2 * * ? *)  UTC", "Flexible +/-15 min  IAM role", accent=ORANGE)
svc_card(SC_X0 + 20, sns_y0, SC_X1 - 20, sns_y1, "🔔", "Amazon SNS",
         "Hunt Alerts topic  KMS", "HIGH/CRITICAL  email subscription", accent=RED)

sc_cx = (SC_X0 + SC_X1) // 2
sch_cy = (sch_y0 + sch_y1) // 2
sns_cy = (sns_y0 + sns_y1) // 2

# Observability cluster
OB_X0 = SC_X1 + 50;  OB_X1 = W - M
OB_Y0 = ROW5_Y - 46; OB_Y1 = SC_Y1

cluster_box(OB_X0, OB_Y0, OB_X1, OB_Y1, "Observability", TEAL_LT, lw=2)

ob_gap = 20
ob_cw  = (OB_X1 - OB_X0 - PAD * 2 - ob_gap) // 4
ob_y0  = ROW5_Y; ob_y1 = OB_Y1 - PAD

for i, (ico, t, s1, s2) in enumerate([
    ("📊", "CloudWatch\nDashboard",   "8 widget panels",        "Threats  latency  cost"),
    ("🚨", "CloudWatch\nAlarms",      "4 alarms",               "Errors  throttles  risk  scan"),
    ("📝", "CloudWatch\nLogs",        "Lambda  API GW  Trail",  "90d retention  metric filters"),
    ("⚙",  "SSM Parameter\nStore",   "/security/ai/threat-*",  "8 params  SecureString  KMS"),
]):
    ox0 = OB_X0 + PAD + i * (ob_cw + ob_gap)
    ox1 = ox0 + ob_cw
    svc_card(ox0, ob_y0, ox1, ob_y1, ico, t, s1, s2, accent=TEAL_LT)

cw_log_cx = OB_X0 + PAD + 2 * (ob_cw + ob_gap) + ob_cw // 2
cop_obs_cx = (cop_x0 + cop_x1) // 2

# ── LEGEND ────────────────────────────────────────────────────────────────────
LEG_X0 = DL_X1 + 50;  LEG_X1 = W - M
LEG_Y0 = ROW4_Y - 20; LEG_Y1 = BR_Y1

rrect(LEG_X0, LEG_Y0, LEG_X1, LEG_Y1, r=16, fill=CARD2, outline=GRAY_DIM, width=2)
draw.rectangle([LEG_X0 + 1, LEG_Y0 + 1, LEG_X1 - 1, LEG_Y0 + 5], fill=ORANGE)
text_c("DATA FLOW LEGEND", (LEG_X0 + LEG_X1) // 2, LEG_Y0 + 16, F_LEGEND_H, ORANGE)

entries = [
    (GREEN_LT,   "──▶", "User HTTPS request"),
    (BLUE_LT,    "──▶", "API Gateway / Lambda invoke"),
    (PURPLE_LT,  "──▶", "Bedrock AI pipeline  (1)(2)(3)"),
    (PURPLE_DIM, "- -▶","Data query: Athena / Glue / S3"),
    (ORANGE,     "──▶", "Scheduled hunt trigger"),
    (RED,        "──▶", "HIGH/CRITICAL threat alert"),
    (TEAL_LT,    "- -▶","Observability / log shipping"),
    (BLUE_LT,    "🔐",  "PrivateLink (no public internet)"),
]
lx = LEG_X0 + 24
for i, (col, sym, desc) in enumerate(entries):
    ly = LEG_Y0 + 70 + i * 52
    draw.rounded_rectangle([lx, ly, lx + 60, ly + 36], radius=8,
                           fill=DARK_BG, outline=col, width=2)
    text_c(sym, lx + 30, ly + 4, F_LEGEND, col)
    text_l(desc, lx + 74, ly + 8, F_LEGEND, OFF_WHITE)

# ═════════════════════════════════════════════════════════════════════════════
# ALL FLOW ARROWS
# ═════════════════════════════════════════════════════════════════════════════
cop_cx = (cop_x0 + cop_x1) // 2
cop_cy = (cop_y0 + cop_y1) // 2
sch_fn_cx = (sched_x0 + sched_x1) // 2
sch_fn_cy = (sched_y0 + sched_y1) // 2

igw_cx = (igw_x0 + igw_x1) // 2;  igw_cy = (card_y0 + card_y1) // 2
waf_cx = (waf_x0 + waf_x1) // 2;  waf_cy = igw_cy
alb_cx = (alb_x0 + alb_x1) // 2;  alb_cy = igw_cy
ui_cx  = (ui_x0 + ui_x1)   // 2;  ui_cy  = igw_cy
ecr_cx = (ecr_x0 + ecr_x1) // 2;  ecr_cy = igw_cy
api_cx2= (api_x0 + api_x1) // 2;  api_cy = (api_y0 + api_y1) // 2

analyst_cx = (AX0 + AX1) // 2;    analyst_cy = (AY0 + AY1) // 2
analyst_r  = AY0 + AY1 // 2       # right edge y

# 1. Analyst → IGW
arrow(AX1, analyst_cy, igw_x0, igw_cy, GREEN_LT, 4, "HTTPS", ly_off=-22)

# 2. IGW → WAF → ALB → Streamlit (inside cluster, horizontal)
arrow_h(igw_cy, igw_x1, waf_x0, color=GREEN_LT, width=3)
arrow_h(waf_cy, waf_x1, alb_x0, color=GREEN_LT, width=3)
arrow_h(alb_cy, alb_x1, ui_x0,  color=GREEN_LT, width=3)

# ECR → Streamlit (dashed, down arrow)
arrow(ecr_cx, ecr_cy, ui_x1 + 20, ui_cy, GRAY, 2, "pull image", dashed=True, ly_off=20)

# 3. Streamlit → API GW
arrow(ui_cx, card_y1, api_cx2, api_y0, BLUE_LT, 4, "POST /query", ly_off=-22)

# 4. API GW → Copilot Lambda
arrow(api_cx2, api_y1, cop_cx, cop_y0, BLUE_LT, 4, "Lambda proxy", ly_off=-22)

# ── Copilot → VPC Endpoints ───────────────────────────────────────────────────
# (1) NL→SQL — Copilot to Bedrock endpoint
arrow(cop_x1, cop_cy - 25, EP_X0 + (ep_positions[0][0] - EP_X0),
      ep_y0, PURPLE_LT, 4, "(1) NL to SQL", step="", ly_off=-22)

# (2) Execute SQL — Copilot to Athena endpoint
arrow(cop_x1, cop_cy,
      ep_positions[1][0], ep_y0, "#C084FC", 4, "(2) Execute SQL", ly_off=-22)

# (3) Threat Analysis — Copilot to Bedrock endpoint (again)
arrow(cop_x1, cop_cy + 25,
      ep_positions[0][0] + 30, ep_y1,
      "#E879F9", 4, "(3) Threat Analysis", ly_off=22)

# S3 results write
arrow(cop_x1, cop_cy + 55, ep_s3_cx, ep_y0,
      GRAY, 2, "write results", dashed=True, ly_off=-22)

# ── VPC Endpoints → Services ──────────────────────────────────────────────────
# Bedrock EP → Claude (1)
arrow(ep_bed_cx, ep_y1, br1_cx, br1_y0, PURPLE_LT, 3, dashed=True, ly_off=-22)
# Bedrock EP → Claude (3)
arrow(ep_bed_cx + 40, ep_y1, br2_cx, br2_y0, "#E879F9", 3, dashed=True, ly_off=-22)

# Athena EP → Athena
arrow(ep_ath_cx, ep_y1, ath_cx, ath_y0, "#C084FC", 3, dashed=True)

# S3 EP → Audit S3
arrow(ep_s3_cx, ep_y1, aus3_cx, aus3_y0, GRAY, 2, dashed=True)

# CW Logs EP → CW Logs (row 5)
arrow(ep_logs_cx, ep_y1, cw_log_cx, ob_y0, TEAL_LT, 2, dashed=True)

# ── Data Layer internal arrows ────────────────────────────────────────────────
# CloudTrail → S3 Logs
arrow(trail_cx, trail_y1, logs_cx, logs_y0, PURPLE_DIM, 2, "delivers logs")
# S3 Logs → Glue Crawler
arrow((LD_X1 + GC_X0) // 2, logs_y0 + CH // 2,
      craw_cx, craw_y0, GRAY, 2, "crawls daily", dashed=True)
# Glue Crawler → Catalog
arrow(craw_cx, craw_y1, cat_cx, cat_y0, PURPLE_DIM, 2, "updates partitions")
# Glue Catalog → Athena
arrow((GC_X1 + QE_X0) // 2, cat_y0 + CH // 2,
      ath_cx - 20, ath_y0, GRAY, 2, "reads schema", dashed=True)
# Athena → S3 Audit
arrow(ath_cx, ath_y1, aus3_cx, aus3_y0, PURPLE_DIM, 2, "writes results")
# S3 Logs → Athena
arrow(logs_cx + 50, logs_y0 + 20, ath_cx - 40, ath_y0 + 30, GRAY, 2,
      "scans logs", dashed=True, ly_off=-30)

# ── Scheduled Hunt Lambda → Copilot ──────────────────────────────────────────
arrow(sched_x0, sch_fn_cy, cop_x1 + 20, cop_cy - 40, ORANGE, 3, "invokes")

# ── EventBridge Scheduler → Scheduled Hunt Lambda ────────────────────────────
elbow(sc_cx, sch_y1, sch_fn_cx, sched_y0,
      ORANGE, 4, "triggers nightly", corner="down-right")

# ── SNS alert flow ────────────────────────────────────────────────────────────
# Scheduled Hunt Lambda → SNS EP
arrow(sch_fn_cx, sched_y1, ep_sns_cx - 30, ep_y1 + 10,
      RED, 3, "HIGH/CRITICAL alert")
# SNS EP → SNS (row 5)
arrow(ep_sns_cx, ep_y1, sc_cx + 20, sns_y0, RED, 3, dashed=True)
# SNS → Analyst (back arrow, long dashed)
arrow(sc_cx, sns_y1, AX1 - 20, AY1 - 20, RED, 2, "email notification",
      dashed=True, ly_off=20)

# ── Copilot → SSM (config reads) ─────────────────────────────────────────────
ssm_cx = OB_X0 + PAD + 3 * (ob_cw + ob_gap) + ob_cw // 2
arrow(cop_cx, VPC_Y1, ssm_cx, ob_y0, GRAY, 2, "reads config", dashed=True, ly_off=-22)

# ── NAT → IGW ────────────────────────────────────────────────────────────────
arrow(nat_x0, nat_y0 + 30, igw_x1, igw_cy - 20, GRAY, 2,
      "outbound internet", dashed=True, ly_off=20)

# ─────────────────────────────────────────────────────────────────────────────
# SAVE
# ─────────────────────────────────────────────────────────────────────────────
# Crop to actual content (add small bottom margin)
actual_h = SC_Y1 + 60
img_crop = img.crop((0, 0, W, actual_h))

# Save at 200 DPI
img_crop.save("architecture.png", dpi=(200, 200), optimize=True)
print(f"architecture.png saved  ({W} x {actual_h} px  @200 DPI)")
