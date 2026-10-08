"""app.py (Member 4) - PII Detection web app (Streamlit).  Run: python -m streamlit run app.py

Pages:  home (heading + upload + info sections + footer)
        -> processing (live step-by-step timeline)
        -> result (redaction %, redacted file data, PII summary, audit access to the original)
"""
import re
import time
from html import escape
from pathlib import Path

import pandas as pd
import streamlit as st

import auth
import pipeline
from pipeline import SUPPORTED, detect_type, run_pipeline

st.set_page_config(page_title="PII Detection", page_icon="🛡️", layout="wide",
                   initial_sidebar_state="collapsed")

# ================================================================== THEME ===
# Change the colors in :root to re-theme the whole app.
CSS = """
<style>
:root{--cv:#7c3aed; --cp:#ec4899; --ca:#f59e0b; --cc:#22d3ee; --cg:#34d399; --cr:#fb7185;
  --txt:#f5f3ff; --mut:#b9b0dc; --line:rgba(255,255,255,.14); --glass:rgba(255,255,255,.06);
  --grad:linear-gradient(90deg,#7c3aed 0%,#ec4899 100%);}
@keyframes fadeUp{from{opacity:0;transform:translateY(22px);}to{opacity:1;transform:none;}}
@keyframes gradMove{to{background-position:200% center;}}
@keyframes blobA{from{transform:translate(0,0) scale(1);}to{transform:translate(160px,120px) scale(1.25);}}
@keyframes blobB{from{transform:translate(0,0) scale(1.1);}to{transform:translate(-180px,-100px) scale(.9);}}
@keyframes pulseDot{0%,100%{box-shadow:0 0 0 0 rgba(52,211,153,.6);}70%{box-shadow:0 0 0 9px rgba(52,211,153,0);}}
@keyframes borderGlow{0%,100%{box-shadow:0 0 0 rgba(236,72,153,0);}50%{box-shadow:0 0 34px rgba(236,72,153,.35);}}
@keyframes shine{to{left:140%;}}
@keyframes spin{to{transform:rotate(360deg);}}
@keyframes stripes{to{background-position:40px 0;}}
@keyframes float{0%,100%{transform:translateY(0);}50%{transform:translateY(-6px);}}

/* ----- page ----- */
.stApp{color:var(--txt); background:
  radial-gradient(900px 500px at 85% 0%, rgba(236,72,153,.16), transparent 60%),
  radial-gradient(900px 600px at 0% 20%, rgba(124,58,237,.22), transparent 60%), #090614;}
.stApp::before,.stApp::after{content:"";position:fixed;border-radius:50%;filter:blur(70px);opacity:.45;pointer-events:none;z-index:0;}
.stApp::before{width:560px;height:560px;left:-140px;top:-120px;background:#7c3aed;animation:blobA 16s ease-in-out infinite alternate;}
.stApp::after{width:520px;height:520px;right:-120px;bottom:-140px;background:#ec4899;animation:blobB 19s ease-in-out infinite alternate;}
[data-testid="stHeader"],[data-testid="stToolbar"],[data-testid="stDecoration"],footer,#MainMenu{display:none !important;}
[data-testid="stSidebar"],[data-testid="collapsedControl"],[data-testid="stSidebarCollapsedControl"]{display:none;}
[data-testid="stMain"],section.main{scroll-behavior:smooth;}
.block-container,[data-testid="stMainBlockContainer"]{max-width:1120px !important;padding-top:6.5rem !important;padding-bottom:3rem !important;position:relative;z-index:1;}
.stApp p,.stApp span,.stApp label,.stApp li,.stApp small,[data-testid="stMarkdownContainer"] p,[data-testid="stWidgetLabel"] p{color:var(--txt);}
a{color:inherit;}
.nav a,.footer a{text-decoration:none !important;}

/* ----- navbar ----- */
.nav{position:fixed;top:0;left:0;right:0;z-index:1000;display:flex;align-items:center;gap:28px;padding:14px max(24px,calc((100vw - 1120px)/2));
  background:rgba(9,6,20,.72);backdrop-filter:blur(14px);border-bottom:1px solid var(--line);}
.brand{display:flex;align-items:center;gap:10px;font-weight:800;font-size:1.15rem;color:#fff !important;text-decoration:none;letter-spacing:.01em;}
.logo{width:34px;height:34px;border-radius:10px;background:var(--grad);display:flex;align-items:center;justify-content:center;box-shadow:0 0 18px rgba(236,72,153,.5);}
.nav .links{margin-left:auto;display:flex;gap:6px;flex-wrap:wrap;}
.nav .links a{color:var(--mut) !important;text-decoration:none;padding:7px 14px;border-radius:999px;font-size:.92rem;transition:all .2s;}
.nav .links a:hover{color:#fff !important;background:rgba(255,255,255,.09);}
.nav .status{margin-left:auto;display:flex;align-items:center;gap:8px;color:var(--mut);font-size:.82rem;}
.dot{width:9px;height:9px;border-radius:50%;background:var(--cg);animation:pulseDot 2s infinite;}

/* ----- hero ----- */
.hero{padding:34px 0 8px;animation:fadeUp .7s both;}
.eyebrow{display:inline-block;border:1px solid var(--line);background:var(--glass);border-radius:999px;padding:6px 16px;color:#e9d5ff !important;
  font-size:.78rem;letter-spacing:.16em;text-transform:uppercase;}
.mega{font-size:5rem;font-weight:900;line-height:1.02;margin:18px 0 10px;color:#fff;letter-spacing:-.02em;}
.grad{background:linear-gradient(90deg,#a78bfa,#f472b6,#fbbf24,#a78bfa);background-size:200% auto;-webkit-background-clip:text;background-clip:text;
  color:transparent !important;-webkit-text-fill-color:transparent;animation:gradMove 7s linear infinite;}
.lead{color:var(--mut) !important;font-size:1.2rem;max-width:660px;margin:0 0 22px;line-height:1.55;}
.h2{font-size:2.3rem;font-weight:800;color:#fff;margin:6px 0 6px;}
.sub{color:var(--mut) !important;max-width:640px;margin-bottom:18px;}
.upl-title{font-weight:700;font-size:1.05rem;margin:24px 0 10px;color:#fff;}

/* ----- cards ----- */
.card{background:linear-gradient(160deg,rgba(255,255,255,.09),rgba(255,255,255,.03));border:1px solid var(--line);border-radius:18px;
  padding:18px 22px;backdrop-filter:blur(8px);box-shadow:0 10px 34px rgba(0,0,0,.35);animation:fadeUp .7s both;transition:transform .25s,border-color .25s,box-shadow .25s;}
.card:hover{transform:translateY(-4px);border-color:rgba(236,72,153,.6);box-shadow:0 14px 40px rgba(236,72,153,.18);}
.card .lbl{color:var(--mut) !important;font-size:.72rem;letter-spacing:.16em;text-transform:uppercase;}
.card .val{font-size:1.75rem;font-weight:800;color:#fff !important;margin-top:4px;}
.card.good .val{color:var(--cg) !important;}
.card.bad .val{color:var(--cr) !important;}
.card .t{font-weight:700;font-size:1.1rem;color:#fff !important;margin:8px 0 4px;}
.card .d{color:var(--mut) !important;font-size:.92rem;line-height:1.5;}
.card .n{display:inline-flex;width:34px;height:34px;border-radius:10px;align-items:center;justify-content:center;font-weight:800;background:var(--grad);color:#fff !important;}
.card .tag{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:8px;background:var(--c,#a78bfa);box-shadow:0 0 12px var(--c,#a78bfa);}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:16px;}
.chips{margin-top:14px;}
.chip{display:inline-block;border:1px solid var(--line);color:#e9d5ff !important;border-radius:999px;padding:5px 15px;margin:0 8px 8px 0;font-size:.82rem;background:var(--glass);}

.sec{display:flex;align-items:center;gap:12px;margin:34px 0 12px;font-weight:800;font-size:1.25rem;color:#fff;animation:fadeUp .6s both;}
.sec .num{background:var(--grad);border-radius:10px;padding:3px 11px;font-size:.9rem;}
.sec::after{content:"";flex:1;height:1px;background:linear-gradient(90deg,rgba(236,72,153,.6),transparent);}
.section{margin-top:96px;scroll-margin-top:90px;}
.banner-ok,.banner-bad{border-radius:14px;padding:13px 18px;margin-top:14px;animation:fadeUp .7s .2s both;}
.banner-ok{background:rgba(52,211,153,.12);border:1px solid rgba(52,211,153,.5);color:#bbf7d0 !important;}
.banner-bad{background:rgba(251,113,133,.12);border:1px solid rgba(251,113,133,.5);color:#fecdd3 !important;}
.locked{display:flex;gap:18px;align-items:center;background:linear-gradient(135deg,rgba(124,58,237,.18),rgba(236,72,153,.12));
  border:1px solid rgba(236,72,153,.45);border-radius:18px;padding:20px 24px;margin-bottom:16px;animation:fadeUp .7s both;}
.locked svg{flex:none;animation:float 3s ease-in-out infinite;}
.locked .big{font-weight:800;font-size:1.15rem;color:#fff !important;}
.locked .small{color:var(--mut) !important;font-size:.93rem;margin-top:3px;line-height:1.5;}

/* ----- live process timeline ----- */
.proc{background:linear-gradient(160deg,rgba(255,255,255,.09),rgba(255,255,255,.03));border:1px solid var(--line);border-radius:20px;padding:24px 28px;
  box-shadow:0 10px 40px rgba(0,0,0,.4);animation:fadeUp .6s both;}
.proc-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;font-weight:700;color:#fff;}
.proc-head span{color:var(--mut) !important;font-weight:500;font-size:.9rem;}
.pbar{height:10px;border-radius:99px;background:rgba(255,255,255,.1);overflow:hidden;margin-bottom:22px;}
.pbar div{height:100%;border-radius:99px;background:repeating-linear-gradient(45deg,#7c3aed 0 14px,#ec4899 14px 28px);background-size:40px 40px;
  animation:stripes .8s linear infinite;box-shadow:0 0 16px rgba(236,72,153,.6);transition:width .4s;}
.tl-item{display:flex;gap:16px;align-items:flex-start;padding:9px 0;position:relative;}
.tl-item:not(:last-child)::before{content:"";position:absolute;left:14px;top:40px;bottom:-9px;width:2px;background:rgba(255,255,255,.12);}
.tl-item.done:not(:last-child)::before{background:var(--cg);}
.tl-ic{flex:none;width:30px;height:30px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:.85rem;}
.tl-item.done .tl-ic{background:var(--cg);color:#052e1f !important;}
.tl-item.run .tl-ic{border:3px solid rgba(255,255,255,.18);border-top-color:#f472b6;animation:spin .8s linear infinite;}
.tl-item.wait .tl-ic{border:2px solid rgba(255,255,255,.2);}
.tl-t{font-weight:700;color:#fff !important;}
.tl-item.wait .tl-t{color:rgba(255,255,255,.4) !important;}
.tl-d{color:var(--mut) !important;font-size:.88rem;margin-top:2px;}
.tl-item.run .tl-d{color:#f9a8d4 !important;}

/* ----- redacted viewer + tables ----- */
.viewer{background:rgba(6,4,16,.8);border:1px solid var(--line);border-radius:16px;padding:18px 20px;max-height:520px;overflow:auto;white-space:pre-wrap;
  word-break:break-word;line-height:1.8;font-family:Consolas,'Courier New',monospace;font-size:.92rem;color:#ece8ff;animation:fadeUp .7s both;}
.ph{display:inline-block;border:1px solid var(--c);color:var(--c) !important;background:rgba(255,255,255,.05);border-radius:7px;padding:0 8px;margin:0 1px;font-weight:700;font-size:.84rem;}
.pgsep{display:block;color:#f9a8d4;letter-spacing:.18em;font-size:.72rem;margin:14px 0 6px;text-transform:uppercase;border-bottom:1px dashed rgba(249,168,212,.35);padding-bottom:4px;}
.tblwrap{max-height:400px;overflow:auto;border:1px solid var(--line);border-radius:16px;background:rgba(6,4,16,.8);animation:fadeUp .7s both;}
table.tbl{width:100%;border-collapse:collapse;font-size:.93rem;}
table.tbl th{background:rgba(124,58,237,.35);color:#fff !important;text-align:left;padding:11px 14px;letter-spacing:.06em;position:sticky;top:0;font-size:.76rem;text-transform:uppercase;}
table.tbl td{color:#ece8ff !important;padding:10px 14px;border-bottom:1px solid rgba(255,255,255,.07);}
table.tbl tr:hover td{background:rgba(255,255,255,.04);}

/* ----- buttons (always visible) ----- */
.stButton>button,.stDownloadButton>button,[data-testid="stFormSubmitButton"]>button{position:relative;overflow:hidden;background:var(--grad) !important;
  color:#fff !important;border:0 !important;border-radius:999px !important;padding:.7rem 2rem !important;font-weight:800 !important;font-size:1rem !important;
  box-shadow:0 8px 26px rgba(236,72,153,.4);transition:transform .2s,box-shadow .2s;}
.stButton>button p,.stDownloadButton>button p,[data-testid="stFormSubmitButton"]>button p{color:#fff !important;font-weight:800 !important;}
.stButton>button::after,.stDownloadButton>button::after,[data-testid="stFormSubmitButton"]>button::after{content:"";position:absolute;top:0;left:-60%;width:40%;height:100%;
  background:rgba(255,255,255,.4);transform:skewX(-20deg);}
.stButton>button:hover::after,.stDownloadButton>button:hover::after,[data-testid="stFormSubmitButton"]>button:hover::after{animation:shine .8s;}
.stButton>button:hover,.stDownloadButton>button:hover,[data-testid="stFormSubmitButton"]>button:hover{transform:translateY(-3px);box-shadow:0 12px 34px rgba(236,72,153,.6);color:#fff !important;}
[class*="st-key-newfile"] button,[class*="st-key-logout"] button,[class*="st-key-cancel"] button,[class*="st-key-retry"] button{background:rgba(255,255,255,.08) !important;
  border:1.5px solid rgba(255,255,255,.5) !important;box-shadow:none;}
[class*="st-key-newfile"] button:hover,[class*="st-key-logout"] button:hover,[class*="st-key-cancel"] button:hover,[class*="st-key-retry"] button:hover{
  background:rgba(255,255,255,.18) !important;box-shadow:0 0 22px rgba(255,255,255,.2);}

/* ----- uploader ----- */
[data-testid="stFileUploaderDropzone"],[data-testid="stFileUploader"] section{background:rgba(255,255,255,.05) !important;border:2px dashed rgba(244,114,182,.7) !important;
  border-radius:20px !important;padding:2.4rem !important;animation:borderGlow 3.2s infinite;}
[data-testid="stFileUploaderDropzone"]:hover{border-color:#f472b6 !important;background:rgba(255,255,255,.08) !important;}
[data-testid="stFileUploaderDropzone"] span,[data-testid="stFileUploaderDropzone"] small,[data-testid="stFileUploaderDropzone"] div{color:#ece8ff !important;}
[data-testid="stFileUploaderDropzone"] svg{fill:#f9a8d4 !important;color:#f9a8d4 !important;}
[data-testid="stFileUploaderDropzone"] button{background:var(--grad) !important;border:0 !important;border-radius:999px !important;box-shadow:0 6px 20px rgba(236,72,153,.4);}
[data-testid="stFileUploaderDropzone"] button,[data-testid="stFileUploaderDropzone"] button *{color:#fff !important;font-weight:800 !important;}
[data-testid="stFileUploaderFile"],[data-testid="stFileChip"]{background:rgba(255,255,255,.1) !important;border:1px solid var(--line) !important;border-radius:12px !important;}
[data-testid="stFileUploaderFile"] *,[data-testid="stFileChip"] *,[data-testid="stFileChipName"],[data-testid="stFileUploaderFileName"]{color:#fff !important;opacity:1 !important;}
[data-testid="stFileUploaderFile"] small,[data-testid="stFileChip"] small{color:#d8ccff !important;}
[data-testid="stFileUploaderFile"] svg,[data-testid="stFileChip"] svg{fill:#f9a8d4 !important;}

/* ----- inputs, expanders ----- */
[data-baseweb="input"],[data-baseweb="base-input"]{background:rgba(255,255,255,.08) !important;border:1px solid rgba(255,255,255,.3) !important;border-radius:12px;}
[data-baseweb="input"] input,[data-baseweb="base-input"] input,[data-testid="stTextInput"] input{color:#fff !important;-webkit-text-fill-color:#fff !important;caret-color:#f472b6;background:transparent !important;}
[data-testid="stTextInput"] label p,[data-testid="stTextInput"] label{color:#e9d5ff !important;font-weight:700;}
[data-testid="stTextInput"] button svg{fill:#e9d5ff !important;color:#e9d5ff !important;}
[data-testid="stForm"]{background:linear-gradient(160deg,rgba(255,255,255,.09),rgba(255,255,255,.03));border:1px solid var(--line);border-radius:18px;padding:1.3rem;animation:fadeUp .6s both;}
[data-testid="stText"],[data-testid="stText"] *{color:#ece8ff !important;}
[data-testid="stExpander"] details{background:rgba(255,255,255,.05) !important;border:1px solid var(--line);border-radius:14px;}
[data-testid="stExpander"] summary{background:rgba(255,255,255,.07) !important;border-radius:14px;}
[data-testid="stExpander"] summary:hover{background:rgba(255,255,255,.12) !important;}
[data-testid="stExpander"] summary p,[data-testid="stExpander"] summary span,[data-testid="stExpander"] summary svg{color:#fff !important;fill:#f9a8d4 !important;font-weight:700;}
[data-testid="stExpander"] details>div{background:transparent !important;}
[data-testid="stExpander"] details>div p{color:var(--mut) !important;}

/* ----- footer ----- */
.footer{margin-top:90px;border-top:1px solid var(--line);padding:34px 0 10px;display:grid;grid-template-columns:2fr 1fr 1fr;gap:30px;}
.footer .b{font-weight:800;font-size:1.1rem;color:#fff !important;margin-bottom:8px;}
.footer .m{color:var(--mut) !important;font-size:.9rem;line-height:1.6;max-width:360px;}
.footer h4{color:#fff !important;font-size:.85rem;letter-spacing:.14em;text-transform:uppercase;margin:0 0 10px;}
.footer a{display:block;color:var(--mut) !important;text-decoration:none;padding:3px 0;font-size:.92rem;}
.footer a:hover{color:#fff !important;}
.copy{border-top:1px solid var(--line);margin-top:26px;padding-top:16px;color:var(--mut) !important;font-size:.82rem;text-align:center;}
.slimfooter{margin-top:70px;border-top:1px solid var(--line);padding-top:16px;color:var(--mut) !important;font-size:.82rem;text-align:center;}

/* ----- animated gauge (pure CSS) ----- */
@property --p{syntax:'<percentage>';inherits:true;initial-value:0%;}
@property --w{syntax:'<integer>';inherits:true;initial-value:0;}
@property --d{syntax:'<integer>';inherits:true;initial-value:0;}
@keyframes fillArc{to{--p:var(--target);}}
@keyframes countW{to{--w:var(--tw);}}
@keyframes countD{to{--d:var(--td);}}
.gwrap{position:relative;width:220px;height:220px;margin:6px auto;animation:fillArc 1.8s cubic-bezier(.2,.8,.2,1) .25s forwards,countW 1.8s cubic-bezier(.2,.8,.2,1) .25s forwards,countD 1.8s cubic-bezier(.2,.8,.2,1) .25s forwards;}
.gwrap::before{content:"";position:absolute;inset:-12px;border-radius:50%;border:1.5px dashed var(--c1);opacity:.5;animation:spin 26s linear infinite;}
.garc{position:absolute;inset:0;border-radius:50%;background:conic-gradient(from 0deg,var(--c1) 0%,var(--c2) var(--p),transparent var(--p) 100%),rgba(255,255,255,.1);
  -webkit-mask:radial-gradient(farthest-side,transparent calc(100% - 17px),#000 calc(100% - 16px));mask:radial-gradient(farthest-side,transparent calc(100% - 17px),#000 calc(100% - 16px));filter:drop-shadow(0 0 10px var(--c1));}
.gnum{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;}
.gn{counter-reset:w var(--w) d var(--d);font-size:2.8rem;font-weight:900;color:#fff;}
.gn.int::after{content:counter(w) "%";}
.gn.dec::after{content:counter(w) "." counter(d) "%";}
.gnum small{color:var(--mut) !important;letter-spacing:.3em;font-size:.68rem;margin-top:2px;}
@media (max-width:800px){.mega{font-size:3rem;}.footer{grid-template-columns:1fr;}.nav .links{display:none;}}
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)

for _k, _v in {"page": "home", "result": None, "user": None, "show_login": False, "pending": None}.items():
    st.session_state.setdefault(_k, _v)

TYPE_COLORS = {"PERSON": "#c4b5fd", "EMAIL": "#22d3ee", "PHONE": "#fbbf24", "SSN": "#fb7185", "AADHAAR": "#fb7185",
               "PAN": "#fb923c", "CREDIT_CARD": "#f472b6", "EMPLOYEE_ID": "#34d399"}
PH_RE = re.compile(r"\[([A-Z][A-Z_]*?)_(\d+)(?:_R2)?\]")
LOGO = ('<svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2.2" stroke-linecap="round" '
        'stroke-linejoin="round"><path d="M12 3l8 3v6c0 4.5-3.2 7.8-8 9-4.8-1.2-8-4.5-8-9V6z"/><path d="M9 12l2 2 4-4"/></svg>')
LOCK_SVG = ('<svg width="50" height="50" viewBox="0 0 24 24" fill="none" stroke="#f9a8d4" stroke-width="1.6" stroke-linecap="round" '
            'stroke-linejoin="round"><rect x="4" y="10.5" width="16" height="10" rx="2.5"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/>'
            '<circle cx="12" cy="15.5" r="1.3" fill="#f9a8d4"/></svg>')


# ============================================================== HELPERS =====
def gauge_html(pct: float, ok: bool) -> str:
    c1, c2 = ("#22d3ee", "#34d399") if ok else ("#fb923c", "#fb7185")
    whole, dec = int(pct), int(round((pct - int(pct)) * 10))
    kind = "int" if dec == 0 else "dec"
    return (f'<div class="gwrap" style="--target:{pct}%;--tw:{whole};--td:{dec};--c1:{c1};--c2:{c2}">'
            f'<div class="garc"></div><div class="gnum"><span class="gn {kind}"></span><small>REDACTED</small></div></div>')


def card(label, value, cls="", delay=0.0):
    return (f'<div class="card {cls}" style="animation-delay:{delay}s"><div class="lbl">{escape(str(label))}</div>'
            f'<div class="val">{escape(str(value))}</div></div>')


def chip(ptype: str, text: str) -> str:
    return f'<span class="ph" style="--c:{TYPE_COLORS.get(ptype, "#f9a8d4")}">{escape(text)}</span>'


def highlight(text: str) -> str:
    out = []
    for line in text.split("\n"):
        if line.startswith("--- Page/Slide"):
            out.append(f'<span class="pgsep">{escape(line.strip("- "))}</span>')
            continue
        out.append(PH_RE.sub(lambda m: chip(m.group(1), m.group(0)), escape(line)))
    return "\n".join(out)


def html_table(df: pd.DataFrame, chip_col: str | None = None) -> None:
    head = "".join(f"<th>{escape(str(c))}</th>" for c in df.columns)
    rows = ""
    for _, row in df.iterrows():
        cells = ""
        for c in df.columns:
            v = str(row[c])
            if c == chip_col:
                m = PH_RE.fullmatch(v)
                ptype = m.group(1) if m else v
                cells += f"<td>{chip(ptype, v)}</td>"
            else:
                cells += f"<td>{escape(v)}</td>"
        rows += f"<tr>{cells}</tr>"
    st.markdown(f'<div class="tblwrap"><table class="tbl"><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table></div>',
                unsafe_allow_html=True)


def section_title(num: str, text: str) -> None:
    st.markdown(f'<div class="sec"><span class="num">{num}</span>{escape(text)}</div>', unsafe_allow_html=True)


def navbar(home: bool) -> None:
    right = ('<div class="links"><a href="#features">Features</a><a href="#how">How it works</a><a href="#security">Security</a>'
             '<a href="#faq">FAQ</a><a href="#about">About</a></div>') if home else \
            '<div class="status"><span class="dot"></span>System online</div>'
    st.markdown(f'<div class="nav"><a class="brand" href="#top"><span class="logo">{LOGO}</span>PII Detection</a>{right}</div>'
                '<div id="top"></div>', unsafe_allow_html=True)


def slim_footer() -> None:
    st.markdown('<div class="slimfooter">PII Detection &middot; Case Study 2 project &middot; Only the redacted version is meant '
                'for AI models.</div>', unsafe_allow_html=True)


# ================================================================= HOME =====
def info_sections() -> None:
    st.markdown('<div class="section" id="features"><div class="h2">What it <span class="grad">detects</span></div>'
                '<div class="sub">Personal data is found by pattern rules, checksum checks and a language model for names.</div></div>',
                unsafe_allow_html=True)
    feats = [("Full names", "PERSON", "First, middle and last names are hidden completely."),
             ("Email addresses", "EMAIL", "Work and personal emails."),
             ("Phone numbers", "PHONE", "Local and international formats."),
             ("Government IDs", "SSN", "SSN, Aadhaar and PAN numbers."),
             ("Card numbers", "CREDIT_CARD", "Checked with the Luhn test to avoid false alarms."),
             ("Employee IDs", "EMPLOYEE_ID", "IDs such as EMP-10234.")]
    cards = "".join(f'<div class="card" style="animation-delay:{i*0.06}s"><div class="t"><span class="tag" style="--c:{TYPE_COLORS[k]}"></span>{t}</div>'
                    f'<div class="d">{d}</div></div>' for i, (t, k, d) in enumerate(feats))
    st.markdown(f'<div class="grid">{cards}</div>', unsafe_allow_html=True)

    st.markdown('<div class="section" id="how"><div class="h2">How it <span class="grad">works</span></div>'
                '<div class="sub">Four steps from upload to a safe, AI-ready file.</div></div>', unsafe_allow_html=True)
    steps = [("1", "Upload", "Choose a PDF, Word, PowerPoint or text file. Scans are read with OCR."),
             ("2", "Detect", "The text is extracted page by page and scanned for personal data."),
             ("3", "Redact", "Every item is replaced with a tag like [PERSON_1] and checked again."),
             ("4", "Review", "See the redacted file, the redaction percentage and a PII summary.")]
    cards = "".join(f'<div class="card" style="animation-delay:{i*0.08}s"><span class="n">{n}</span><div class="t">{t}</div><div class="d">{d}</div></div>'
                    for i, (n, t, d) in enumerate(steps))
    st.markdown(f'<div class="grid">{cards}</div>', unsafe_allow_html=True)

    st.markdown('<div class="section" id="security"><div class="h2">Security &amp; <span class="grad">privacy</span></div>'
                '<div class="sub">What happens to your file in this application.</div></div>', unsafe_allow_html=True)
    sec = [("Redacted before AI", "Only the redacted text is meant to go to an AI model. The original is never sent."),
           ("Runs locally", "In this demo the file is processed on this computer. Nothing is sent to an outside service."),
           ("Separate storage", "The original and the redacted copy are saved in different folders."),
           ("Protected original", "Opening the original needs a username and password. Passwords are stored as hashes.")]
    cards = "".join(f'<div class="card" style="animation-delay:{i*0.08}s"><div class="t">{t}</div><div class="d">{d}</div></div>'
                    for i, (t, d) in enumerate(sec))
    st.markdown(f'<div class="grid">{cards}</div>', unsafe_allow_html=True)

    st.markdown('<div class="section" id="faq"><div class="h2">Frequently asked <span class="grad">questions</span></div></div>',
                unsafe_allow_html=True)
    faqs = [("What is PII?", "Personally identifiable information: data that can identify a person, such as a name, email, phone number or government ID."),
            ("Which files can I upload?", "PDF, DOCX, PPTX and TXT. Scanned PDFs are read with OCR, which needs the Tesseract program installed."),
            ("What does the redaction percentage mean?", "It is the share of detected PII that was replaced. After redacting, the app checks the output again and "
             "shows how many items remain. Detection itself can still miss things, so coverage is measured on test files."),
            ("Can this miss PII?", "No automatic detector is perfect. That is why the result shows a re-check and why the team measures coverage on sample files."),
            ("Why is there a login for the original file?", "You already have your own file. The login protects the copy stored by the system and the table that links "
             "tags back to real values, for authorised reviewers such as audit or compliance.")]
    for q, a in faqs:
        with st.expander(q):
            st.write(a)

    st.markdown('<div class="section" id="about"><div class="h2">About <span class="grad">this project</span></div>'
                '<div class="sub">PII Detection was built by a team of four for Case Study 2 (Text Analysis and PII Detection). '
                'It extracts text from varied documents, finds personal data, redacts it before AI processing and reports what was found.</div></div>',
                unsafe_allow_html=True)
    st.markdown('<div class="footer"><div><div class="b">PII Detection</div><div class="m">Find and remove personal data from documents '
                'before they reach an AI model.</div></div>'
                '<div><h4>Product</h4><a href="#features">Features</a><a href="#how">How it works</a><a href="#top">Upload a file</a></div>'
                '<div><h4>Info</h4><a href="#security">Security &amp; privacy</a><a href="#faq">Help &amp; FAQ</a><a href="#about">About</a></div></div>'
                '<div class="copy">&copy; 2026 PII Detection &middot; Case Study 2 project</div>', unsafe_allow_html=True)


def home_page() -> None:
    navbar(True)
    st.markdown('<div class="hero"><span class="eyebrow">Data privacy &middot; Redaction</span>'
                '<div class="mega">PII <span class="grad">Detection</span></div>'
                '<p class="lead">Find personal data in your documents and remove it before it reaches an AI model.</p></div>',
                unsafe_allow_html=True)
    st.markdown('<div class="upl-title">Upload a file to begin</div>', unsafe_allow_html=True)
    up = st.file_uploader("Upload a file", type=[e.strip(".") for e in SUPPORTED], label_visibility="collapsed")
    st.markdown('<div class="chips"><span class="chip">PDF</span><span class="chip">DOCX</span><span class="chip">PPTX</span>'
                '<span class="chip">TXT</span><span class="chip">Scanned files (OCR)</span></div>', unsafe_allow_html=True)
    if up is not None:
        st.write("")
        if st.button("Start redaction", type="primary", key="start"):
            st.session_state.update(pending={"name": up.name, "bytes": up.getvalue()}, page="processing")
            st.rerun()
    info_sections()


# ============================================================ PROCESSING ====
STAGES = [("receive", "File received"), ("type", "File type identified"), ("extract", "Extracting text"),
          ("detect", "Detecting PII"), ("redact", "Redacting PII"), ("verify", "Checking the redacted output"),
          ("done", "Output ready")]


def timeline_html(cur: str, frac: float, details: dict, elapsed: float) -> str:
    order = [k for k, _ in STAGES]
    idx = order.index(cur)
    items = ""
    for i, (k, label) in enumerate(STAGES):
        state = "done" if (i < idx or cur == "done") else ("run" if i == idx else "wait")
        icon = "&#10003;" if state == "done" else ""
        d = escape(details.get(k, ""))
        items += (f'<div class="tl-item {state}"><span class="tl-ic">{icon}</span>'
                  f'<div><div class="tl-t">{label}</div><div class="tl-d">{d}</div></div></div>')
    return (f'<div class="proc"><div class="proc-head">Processing your file<span>{elapsed:.1f} s &middot; {int(frac*100)}%</span></div>'
            f'<div class="pbar"><div style="width:{max(frac*100, 3):.0f}%"></div></div>{items}</div>')


def processing_page() -> None:
    p = st.session_state.pending
    if not p:
        st.session_state.page = "home"
        st.rerun()
    navbar(False)
    st.markdown(f'<div class="hero"><div class="mega" style="font-size:3.2rem">Redacting <span class="grad">your file</span></div>'
                f'<p class="lead">{escape(p["name"])}</p></div>', unsafe_allow_html=True)
    holder = st.empty()
    t0 = time.time()
    state = {"stage": "type", "frac": 0.02, "last": 0.0,
             "details": {"receive": f'{p["name"]} ({len(p["bytes"]) / 1024:.0f} KB)',
                         "type": detect_type(p["name"]) or "Unknown"}}

    def render():
        holder.markdown(timeline_html(state["stage"], state["frac"], state["details"], time.time() - t0), unsafe_allow_html=True)

    def on_progress(frac, msg, stage=None):
        changed = stage is not None and stage != state["stage"]
        if stage:
            state["stage"] = stage
            state["details"][stage] = msg
        state["frac"] = frac
        if changed or time.time() - state["last"] > 0.15:
            state["last"] = time.time()
            render()

    render()
    try:
        res = run_pipeline(p["bytes"], p["name"], progress=on_progress)
    except Exception as e:
        holder.empty()
        st.error(str(e))
        if st.button("Try another file", key="retry"):
            st.session_state.update(page="home", pending=None)
            st.rerun()
        return
    state.update(stage="done", frac=1.0)
    state["details"]["done"] = f'{res["total"]} PII item(s) redacted in {time.time() - t0:.1f} s'
    render()
    time.sleep(0.7)
    st.session_state.update(result=res, page="result", pending=None, show_login=False)
    st.rerun()


# ================================================================ RESULT ====
def result_page() -> None:
    r = st.session_state.result
    navbar(False)
    top, btn = st.columns([5, 1])
    with top:
        st.markdown(f'<div class="hero" style="padding-top:6px"><div class="mega" style="font-size:3.2rem">Redaction <span class="grad">complete</span></div>'
                    f'<p class="lead" style="margin-bottom:6px">{escape(r["name"])}</p></div>', unsafe_allow_html=True)
    with btn:
        st.write("")
        if st.button("New file", key="newfile"):
            st.session_state.update(page="home", result=None, show_login=False)
            st.rerun()

    ok = r["remaining"] == 0
    g, stats = st.columns([1, 2])
    with g:
        st.markdown(gauge_html(r["redaction_pct"], ok), unsafe_allow_html=True)
    with stats:
        a, b, c = st.columns(3)
        a.markdown(card("File type", r["file_type"], delay=0.0), unsafe_allow_html=True)
        b.markdown(card("PII found", r["total"], delay=0.1), unsafe_allow_html=True)
        c.markdown(card("PII remaining", r["remaining"], "good" if ok else "bad", delay=0.2), unsafe_allow_html=True)
        if ok:
            st.markdown('<div class="banner-ok">All detected PII was redacted. A second check of the redacted output found 0 remaining items.</div>',
                        unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="banner-bad">{r["remaining"]} item(s) are still detected after redaction. Review before sending to an AI model.</div>',
                        unsafe_allow_html=True)

    section_title("1", "Redacted file")
    left, right = st.columns([3, 2])
    with left:
        st.markdown(f'<div class="viewer">{highlight(r["redacted_text"])}</div>', unsafe_allow_html=True)
        st.write("")
        st.download_button("Download redacted file", r["redacted_text"], file_name=f"redacted_{Path(r['name']).stem}.txt", type="primary")
    with right:
        st.markdown('<div style="color:#b9b0dc;margin-bottom:8px">PII found (real values are not shown)</div>', unsafe_allow_html=True)
        if r["findings"]:
            df = pd.DataFrame(r["findings"])
            summary = (df.groupby("type").agg(Count=("value", "count"), Pages=("page", lambda s: ", ".join(map(str, sorted(set(s))))))
                         .reset_index().rename(columns={"type": "PII type"}))
            html_table(summary, chip_col="PII type")
        else:
            st.info("No PII found in this file.")

    section_title("2", "Need the original file?")
    if st.session_state.user:
        a, b = st.columns([5, 1])
        a.markdown(f'<div class="banner-ok" style="margin-top:0">Audit access granted: {escape(st.session_state.user)}</div>', unsafe_allow_html=True)
        with b:
            if st.button("Logout", key="logout"):
                st.session_state.update(user=None, show_login=False)
                st.rerun()
        st.write("")
        st.markdown('<div style="color:#b9b0dc;margin-bottom:6px">Original file content</div>', unsafe_allow_html=True)
        for pg in r["pages"]:
            with st.expander(f"Page / Slide {pg['page']}", expanded=(pg["page"] == 1)):
                st.text(pg["text"])
        st.download_button("Download original file", Path(r["orig_path"]).read_bytes(), file_name=r["name"], type="primary")
        st.markdown('<div style="color:#b9b0dc;margin:22px 0 8px">Matching table (tag to original value)</div>', unsafe_allow_html=True)
        if r["mapping"]:
            html_table(pd.DataFrame([{"Placeholder": k, "Original value": v} for k, v in r["mapping"].items()]), chip_col="Placeholder")
        else:
            st.info("No matching table available (no PII found, or the redactor did not return one).")
    else:
        st.markdown(f'<div class="locked">{LOCK_SVG}<div><div class="big">Authorised audit access</div>'
                    '<div class="small">You already have your own file. This area is for authorised reviewers, such as audit or compliance, '
                    'who need to compare the original with the redacted version. The AI model never receives the original.</div></div></div>',
                    unsafe_allow_html=True)
        if not st.session_state.show_login:
            if st.button("Request access to the original", type="primary", key="reqaccess"):
                st.session_state.show_login = True
                st.rerun()
        else:
            _, mid, _ = st.columns([1, 2, 1])
            with mid:
                with st.form("login_form"):
                    u = st.text_input("Username")
                    p = st.text_input("Password", type="password")
                    if st.form_submit_button("Login", type="primary"):
                        if auth.verify_login(u, p):
                            st.session_state.user = u
                            st.rerun()
                        else:
                            st.error("Access denied: wrong username or password.")
                if st.button("Cancel", key="cancel"):
                    st.session_state.show_login = False
                    st.rerun()

    with st.expander("Pipeline status (team use)"):
        for step, src in r["modules"].items():
            st.write(f"{step}: {src}")
        st.write(f"Pages / slides: {r.get('page_count', '-')}")
        st.write("Time (seconds): " + ", ".join(f"{k} {v}" for k, v in r.get("timings", {}).items()))
    slim_footer()


# Everything is drawn inside one slot, so switching pages replaces the old page instantly (no leftovers).
slot = st.empty()
with slot.container():
    page = st.session_state.page
    if page == "processing" and st.session_state.pending:
        processing_page()
    elif page == "result" and st.session_state.result:
        result_page()
    else:
        home_page()

pipeline.warmup()   # load the name model in the background AFTER the page is drawn, so the first upload is fast