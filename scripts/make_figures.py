#!/usr/bin/env python3
"""make_figures.py — regenerate docs/figures/*.png from data/wallet_vulns.parquet.
Run from repo root:  uv run --with matplotlib python scripts/make_figures.py"""
import pandas as pd, numpy as np, json
import matplotlib as mpl; mpl.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter

# ---- style (clean, report-quality) -----------------------------------------
plt.rcParams.update({
    "figure.dpi":150,"savefig.dpi":150,"font.size":10.5,
    "font.family":"DejaVu Sans","axes.spines.top":False,"axes.spines.right":False,
    "axes.grid":True,"grid.color":"#e6e6e6","grid.linewidth":0.8,"axes.axisbelow":True,
    "axes.edgecolor":"#666","xtick.color":"#444","ytick.color":"#444","axes.labelcolor":"#222",
})
INK="#1a1a2e"; BLUE="#2b6cb0"; ORANGE="#dd6b20"; TEAL="#2c7a7b"; GRAY="#a0aec0"; RED="#c53030"
FG="docs/figures"
d=pd.read_parquet("data/wallet_vulns.parquet"); n=len(d)
LANG={'geth':'Go','erigon':'Go','prysm':'Go','nethermind':'C#','besu':'Java','teku':'Java',
      'reth':'Rust','lighthouse':'Rust','grandine':'Rust','nimbus':'Nim','lodestar':'TypeScript'}
d['lang']=d.source_platform.map(LANG)
def hbar(ax, labels, vals, color=BLUE, pct=False, ann=True):
    y=np.arange(len(labels))[::-1]
    ax.barh(y, vals, color=color, height=0.72)
    ax.set_yticks(y); ax.set_yticklabels(labels)
    ax.grid(axis="y",visible=False)
    if ann:
        for yi,v in zip(y,vals):
            ax.text(v+max(vals)*0.01, yi, (f"{v:.0f}%" if pct else f"{int(v)}"),
                    va="center", ha="left", fontsize=9, color="#333")
    ax.margins(x=0.14)

# ---- FIG 1: silent-fix prevalence ------------------------------------------
rated=(d.severity.str.lower().isin(['critical','high','medium','low'])).mean()*100
cveid=(d.title.fillna('')+' '+d.description.fillna('')).str.contains(r'CVE-|GHSA-',regex=True).mean()*100
fig,ax=plt.subplots(figsize=(7.2,2.2))
segs=[("carries CVE/GHSA id",cveid,ORANGE),
      ("rated severity only (no id)",rated-cveid if rated>cveid else 0,"#e8a87c"),
      ("silent (no advisory, no rating)",100-rated,GRAY)]
left=0
for lbl,w,c in segs:
    ax.barh(0,w,left=left,color=c,height=0.5,label=f"{lbl}  ({w:.1f}%)")
    if w>4: ax.text(left+w/2,0,f"{w:.1f}%",ha="center",va="center",color="white",fontsize=10,fontweight="bold")
    left+=w
ax.set_xlim(0,100); ax.set_ylim(-.5,.5); ax.set_yticks([])
ax.xaxis.set_major_formatter(PercentFormatter()); ax.grid(axis="y",visible=False)
ax.legend(loc="upper center",bbox_to_anchor=(0.5,-0.35),ncol=1,frameon=False,fontsize=9,handlelength=1.1)
ax.set_title("How Ethereum-wallet fixes reach the public",loc="left",fontsize=12,color=INK,fontweight="bold",pad=8)
plt.tight_layout(); plt.savefig(f"{FG}/fig1_silent_prevalence.png",bbox_inches="tight"); plt.close()

# ---- FIG 2: root cause + attack path (2 panels) ----------------------------
rc=d.root_cause.value_counts().drop(labels=["other"],errors="ignore").head(9)
ap=d.attack_path.value_counts().head(8)
fig,(a1,a2)=plt.subplots(1,2,figsize=(11,4.2))
hbar(a1, [x.replace('_',' ') for x in rc.index], rc.values, BLUE)
a1.set_title("(a) Root cause",loc="left",fontsize=12,color=INK,fontweight="bold")
hbar(a2, [x.replace('_',' ') for x in ap.index], ap.values, TEAL)
a2.set_title("(b) Attack path (trigger)",loc="left",fontsize=12,color=INK,fontweight="bold")
plt.tight_layout(); plt.savefig(f"{FG}/fig2_rootcause_attack.png",bbox_inches="tight"); plt.close()

# ---- FIG 3: vulnerability area (label), grouped -----------------------------
lab=d.label.fillna('other').replace('nan','other')
def area_group(l):
    if l.startswith('beacon-chain'): return 'beacon-chain:* (consensus STF)'
    return l
g=lab.map(area_group).value_counts().drop(labels=['other'],errors='ignore').head(14)
fig,ax=plt.subplots(figsize=(8.2,5))
cols=[ORANGE if 'beacon-chain' in x or x in ('fork-choice','p2p-interface','validator','attestation') else BLUE for x in g.index]
hbar(ax, g.index, g.values, BLUE)
ax.set_title("Vulnerability area  (protocol subsystem the fix touches)",loc="left",fontsize=12,color=INK,fontweight="bold")
plt.tight_layout(); plt.savefig(f"{FG}/fig3_area.png",bbox_inches="tight"); plt.close()

# ---- FIG 4: fix size (LOC hist + files) ------------------------------------
def loc(s):
    try:
        a=json.loads(s); return sum(h['code'].count(chr(10))+1 for f in a for h in f['hunks'])
    except: return 0
d['locc']=d.post_fix_code.fillna('[]').map(loc)
d['nf']=d.files_changed.fillna('[]').map(lambda s: len(json.loads(s)) if s and str(s)!='nan' else 0)
cd=d[d.locc>0]
fig,(a1,a2)=plt.subplots(1,2,figsize=(11,3.8),gridspec_kw={'width_ratios':[2,1]})
bins=[0,5,10,20,30,50,100,200,500,5000]
a1.hist(cd.locc.clip(upper=4999),bins=bins,color=BLUE,edgecolor="white")
a1.set_xscale("log"); a1.set_xlabel("lines changed (post-fix, log scale)"); a1.set_ylabel("fixes")
med=int(cd.locc.median()); a1.axvline(med,color=RED,ls="--",lw=1.5); a1.text(med*1.1,a1.get_ylim()[1]*0.9,f"median {med} LOC",color=RED,fontsize=9)
a1.set_title("(a) Fix size — surgical",loc="left",fontsize=12,color=INK,fontweight="bold")
nf=d[d.nf>0].nf.clip(upper=8).value_counts().sort_index()
a2.bar(nf.index.astype(str),nf.values,color=TEAL,edgecolor="white")
a2.set_xlabel("files changed  (8 = 8+)"); a2.set_ylabel("fixes")
a2.set_title("(b) Files touched",loc="left",fontsize=12,color=INK,fontweight="bold"); a2.grid(axis="x",visible=False)
plt.tight_layout(); plt.savefig(f"{FG}/fig4_fixsize.png",bbox_inches="tight"); plt.close()

# ---- FIG 5: diversity (language + wallet x layer) --------------------------
fig,(a1,a2)=plt.subplots(1,2,figsize=(11,4))
lc=d.lang.value_counts()
a1.bar(lc.index,lc.values,color=[BLUE,TEAL,ORANGE,"#805ad5","#38a169","#d53f8c"][:len(lc)],edgecolor="white")
a1.set_ylabel("fixes"); a1.set_title("(a) By language (6)",loc="left",fontsize=12,color=INK,fontweight="bold"); a1.grid(axis="x",visible=False)
for i,v in enumerate(lc.values): a1.text(i,v+8,str(v),ha="center",fontsize=9,color="#333")
cl=d.groupby(['source_platform','layer']).size().unstack(fill_value=0)
cl=cl.loc[d.source_platform.value_counts().index]
cl=cl[cl.sum(axis=1)>5]
y=np.arange(len(cl))[::-1]
a2.barh(y,cl.get('execution',0),color=BLUE,height=0.75,label='execution')
a2.barh(y,cl.get('consensus',0),left=cl.get('execution',0),color=ORANGE,height=0.75,label='consensus')
a2.set_yticks(y); a2.set_yticklabels(cl.index); a2.grid(axis="y",visible=False)
a2.set_title("(b) By wallet × layer (11 wallets)",loc="left",fontsize=12,color=INK,fontweight="bold")
a2.legend(frameon=False,fontsize=9,loc="lower right")
plt.tight_layout(); plt.savefig(f"{FG}/fig5_diversity.png",bbox_inches="tight"); plt.close()

# ---- FIG 6: column coverage ------------------------------------------------
cov=[("source_url / title / attack_path",100.0),("label",100*(~lab.isin(['other'])).mean()),
     ("fix_commit / introduced",100*(d.fix_commit.fillna('').str.len()>0).mean()),
     ("root_cause",100*(~d.root_cause.fillna('other').isin(['other'])).mean()),
     ("pre/post code (inline)",100*(d.post_fix_code.fillna('[]').astype(str)!='[]').mean()),
     ("cwe_top25",100*(~d.cwe_top25.fillna('N/A').isin(['N/A'])).mean()),
     ("silent_fix_prob",100*d.silent_fix_prob.notna().mean()),
     ("severity (rated)",rated)]
labels=[x[0] for x in cov]; vals=[x[1] for x in cov]
fig,ax=plt.subplots(figsize=(7.6,4))
y=np.arange(len(labels))[::-1]
cols=[BLUE if v>=70 else (ORANGE if v>=30 else GRAY) for v in vals]
ax.barh(y,vals,color=cols,height=0.7)
ax.set_yticks(y); ax.set_yticklabels(labels); ax.set_xlim(0,105)
ax.xaxis.set_major_formatter(PercentFormatter()); ax.grid(axis="y",visible=False)
for yi,v in zip(y,vals): ax.text(v+1,yi,f"{v:.0f}%",va="center",fontsize=9,color="#333")
ax.set_title("Per-column coverage  (n=2,225)",loc="left",fontsize=12,color=INK,fontweight="bold")
ax.axvline(100,color="#ccc",lw=0.8)
plt.tight_layout(); plt.savefig(f"{FG}/fig6_coverage.png",bbox_inches="tight"); plt.close()

print("figures written to",FG)
import os
for f in sorted(os.listdir(FG)): print("  ",f, round(os.path.getsize(FG+"/"+f)/1024),"KB")

# ---- FIG 8: attack surface — where the adversary's single packet/tx enters --
# EF bounty severity requires a *remotely reachable* trigger ("single network
# packet or onchain transaction"). Group attack_path by entry channel.
CH={'malicious_p2p_message':'network: p2p / gossip','malicious_attestation':'network: p2p / gossip',
    'peer':'network: p2p / gossip','malicious_block':'network: block gossip',
    'malicious_tx':'on-chain: transaction / EVM','malformed_input':'parsing untrusted input',
    'large_input':'parsing untrusted input','crafted_state':'crafted chain state',
    'internal_only':'internal (not attacker-reachable)'}
ch=d.attack_path.map(CH).fillna('other').value_counts()
ch=ch[ch.index!='other']
order=['network: p2p / gossip','network: block gossip','on-chain: transaction / EVM',
       'parsing untrusted input','crafted chain state','internal (not attacker-reachable)']
ch=ch.reindex([o for o in order if o in ch.index])
fig,ax=plt.subplots(figsize=(8.4,3.6))
cols=[RED if 'network' in c else (ORANGE if ('on-chain' in c or 'parsing' in c or 'crafted' in c) else GRAY) for c in ch.index]
y=np.arange(len(ch))[::-1]
ax.barh(y,ch.values,color=cols,height=0.7)
ax.set_yticks(y); ax.set_yticklabels(ch.index)
for yi,v in zip(y,ch.values): ax.text(v+8,yi,str(int(v)),va="center",fontsize=9,color="#333")
ax.margins(x=0.13); ax.grid(axis="y",visible=False)
ax.set_title("Attack surface — where the adversary's input enters the node",loc="left",fontsize=12,color=INK,fontweight="bold")
ax.text(ch.max()*0.55,0.1,"red/orange = remotely reachable\n(attacker-controlled input)",fontsize=8.5,color="#555")
plt.tight_layout(); plt.savefig(f"{FG}/fig8_attack_surface.png",bbox_inches="tight"); plt.close()
print("fig8 written")

# ---- FIG 9: audit priority map — where the severe bugs concentrate ----------
# Honest "where to look": VOLUME (observed) per subsystem, coloured by the impact
# class each maps to BY THE BOUNTY DEFINITION (consensus/value = split/invalid-
# state = critical-if-exploitable; availability = DoS). No estimated-severity axis.
skip={'other','build-ci','test','cli','metrics-observability'}
areas=[a for a in d.label.value_counts().index if a not in skip][:14]
CONSENSUS_VALUE={'evm','opcodes','precompiles','fork-choice','transactions','crypto',
                 'kzg-commitments','serialization','state-trie'}
def impact_class(a):
    if a.startswith('beacon-chain') or a in CONSENSUS_VALUE: return ('consensus / value  (→ chain split or invalid state)',RED)
    if a in {'p2p','p2p-interface','sync','rpc','txpool','database','engine-api'}: return ('availability  (→ DoS)',BLUE)
    return ('other',GRAY)
vol=[len(d[d.label==a]) for a in areas]
cls=[impact_class(a) for a in areas]
o=np.argsort(vol)
areas=[areas[i] for i in o]; vol=[vol[i] for i in o]; cls=[cls[i] for i in o]
fig,ax=plt.subplots(figsize=(9.2,5.6))
y=np.arange(len(areas))
ax.barh(y,vol,color=[c for _,c in cls],height=0.72)
ax.set_yticks(y); ax.set_yticklabels(areas)
for yi,v in zip(y,vol): ax.text(v+2,yi,str(v),va="center",fontsize=9,color="#333")
ax.margins(x=0.13); ax.grid(axis="y",visible=False)
ax.set_xlabel("number of fixes  (audit volume — observed)")
ax.set_title("Where to look — fixes per subsystem, by impact class",loc="left",fontsize=13,color=INK,fontweight="bold")
from matplotlib.patches import Patch
ax.legend(handles=[Patch(color=RED,label='consensus / value → chain split or invalid state (critical if exploitable)'),
                   Patch(color=BLUE,label='availability → denial of service')],
          loc="lower right",frameon=False,fontsize=8.5)
plt.tight_layout(); plt.savefig(f"{FG}/fig9_priority_map.png",bbox_inches="tight"); plt.close()
print("fig9 written")

# ---- FIG 10: 3D — subsystem × severity × count -----------------------------
from mpl_toolkits.mplot3d import Axes3D  # noqa
se=d.severity_estimated.fillna("")
d['_tier']=se.where(se.isin(['Critical','High','Medium','Low']),'—')
TIERS=['Low','Medium','High','Critical']
TCOL={'Low':TEAL,'Medium':ORANGE,'High':RED,'Critical':'#7b1fa2'}
skip={'other','build-ci','test','cli','metrics-observability','docs'}
subs=[a for a in d.label.value_counts().index if a not in skip][:12][::-1]
fig=plt.figure(figsize=(11,6.6)); ax=fig.add_subplot(111,projection='3d')
for yi,t in enumerate(TIERS):
    zs=[int(((d.label==s)&(d._tier==t)).sum()) for s in subs]
    xs=np.arange(len(subs))
    ax.bar3d(xs, np.full(len(subs),yi), np.zeros(len(subs)), 0.7, 0.55, zs,
             color=TCOL[t], shade=True, alpha=0.92)
ax.set_xticks(np.arange(len(subs))+0.35); ax.set_xticklabels(subs,rotation=40,ha='right',fontsize=7.5)
ax.set_yticks(np.arange(len(TIERS))+0.25); ax.set_yticklabels(TIERS,fontsize=8.5)
ax.set_zlabel("fixes",fontsize=9)
ax.set_title("Fixes by subsystem × severity  (severity incl. estimated)",fontsize=12.5,color=INK,fontweight="bold")
ax.view_init(elev=22,azim=-58); ax.set_box_aspect((2.0,1.0,0.8))
plt.tight_layout(); plt.savefig(f"{FG}/fig10_severity_3d.png",bbox_inches="tight"); plt.close()

# ---- FIG 11: heatmaps — subsystem×severity and root_cause×severity ---------
def heat(ax,rows,rowlab,title):
    M=np.array([[int(((idx==r)&(d._tier==t)).sum()) for t in TIERS] for r in rows])
    im=ax.imshow(M,cmap="YlOrRd",aspect="auto")
    ax.set_xticks(range(len(TIERS))); ax.set_xticklabels(TIERS,fontsize=9)
    ax.set_yticks(range(len(rows))); ax.set_yticklabels(rowlab,fontsize=9)
    for i in range(len(rows)):
        for j in range(len(TIERS)):
            v=M[i,j]
            if v: ax.text(j,i,v,ha="center",va="center",fontsize=8,
                          color="white" if v>M.max()*0.55 else "#333")
    ax.set_title(title,loc="left",fontsize=12,color=INK,fontweight="bold")
    ax.grid(False)
    return im
subs2=[a for a in d.label.value_counts().index if a not in skip][:12]
rcs=[c for c in d.root_cause.value_counts().head(9).index if c!='other'][:8]
fig,(a1,a2)=plt.subplots(1,2,figsize=(12,5.2))
idx=d.label; heat(a1,subs2,subs2,"(a) subsystem × severity")
idx=d.root_cause; im=heat(a2,rcs,[r.replace('_',' ') for r in rcs],"(b) root cause × severity")
fig.colorbar(im,ax=a2,fraction=0.046,pad=0.04,label="fixes")
plt.tight_layout(); plt.savefig(f"{FG}/fig11_severity_heatmap.png",bbox_inches="tight"); plt.close()
print("fig10, fig11 written")
