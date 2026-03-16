<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Alex Garcia | Cybersecurity Portfolio</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Syne:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #0a0e1a;
    --bg2: #0f1628;
    --bg3: #141c35;
    --accent: #00f5a0;
    --accent2: #00c3ff;
    --accent3: #ff6b35;
    --accent4: #c084fc;
    --text: #e8eaf6;
    --muted: #7986cb;
    --border: rgba(0,245,160,0.15);
    --mono: 'Share Tech Mono', monospace;
    --sans: 'Syne', sans-serif;
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { background:var(--bg); color:var(--text); font-family:'Syne', sans-serif; overflow-x:hidden; }
  body::before {
    content:''; position:fixed; inset:0; z-index:0;
    background-image: linear-gradient(rgba(0,245,160,0.03) 1px, transparent 1px),
                      linear-gradient(90deg, rgba(0,245,160,0.03) 1px, transparent 1px);
    background-size: 40px 40px; pointer-events:none;
  }
  nav {
    position:fixed; top:0; left:0; right:0; z-index:100;
    background:rgba(10,14,26,0.92); backdrop-filter:blur(12px);
    border-bottom:1px solid var(--border);
    display:flex; align-items:center; justify-content:space-between;
    padding:0 2rem; height:60px;
  }
  .nav-logo { font-family:var(--mono); color:var(--accent); font-size:14px; letter-spacing:2px; }
  .nav-links { display:flex; gap:1.5rem; }
  .nav-links a { font-family:var(--mono); font-size:11px; color:var(--muted); text-decoration:none; letter-spacing:1px; cursor:pointer; transition:color 0.2s; }
  .nav-links a:hover { color:var(--accent); }
  section { position:relative; z-index:1; padding:5rem 2rem; max-width:1100px; margin:0 auto; }
  #about { min-height:100vh; display:flex; flex-direction:column; justify-content:center; padding-top:80px; }
  .hero-tag { font-family:var(--mono); font-size:14px; color:var(--accent); letter-spacing:3px; margin-bottom:1.5rem; display:flex; align-items:center; gap:8px; }
  .hero-tag::before { content:''; display:inline-block; width:40px; height:1px; background:var(--accent); }
  h1, h2, h3 { color:var(--text); font-family:'Syne', sans-serif; font-weight:800; }
  h1 { font-size:clamp(2.5rem,6vw,5.5rem); line-height:0.95; letter-spacing:-2px; margin-bottom:1rem; }
  .h1-name { color:var(--text); display:block; font-family:'Syne', sans-serif; }
  .h1-role { color:var(--accent); display:block; font-family:'Syne', sans-serif; }
  .hero-sub { font-family:var(--mono); font-size:17px; color:var(--muted); max-width:560px; line-height:1.8; margin:1.5rem 0 2rem; }
  .link-group { display:flex; flex-direction:column; gap:0.75rem; }
  .link-row { display:flex; flex-wrap:wrap; gap:0.75rem; align-items:center; }
  .link-row-label { font-family:var(--mono); font-size:14px; color:var(--muted); letter-spacing:2px; width:90px; flex-shrink:0; }
  .btn { font-family:var(--mono); font-size:16px; letter-spacing:1px; padding:10px 24px; border:1px solid; text-decoration:none; cursor:pointer; transition:all 0.2s; display:inline-flex; align-items:center; gap:6px; }
  .btn-primary { border-color:var(--accent); color:var(--accent); background:transparent; }
  .btn-primary:hover { background:var(--accent); color:var(--bg); }
  .btn-secondary { border-color:var(--muted); color:var(--muted); background:transparent; }
  .btn-secondary:hover { border-color:var(--text); color:var(--text); }
  .btn-devsec { border-color:var(--accent3); color:var(--accent3); background:transparent; }
  .btn-devsec:hover { background:var(--accent3); color:var(--bg); }
  .btn-thlabs { border-color:var(--accent4); color:var(--accent4); background:transparent; }
  .btn-thlabs:hover { background:var(--accent4); color:var(--bg); }
  .whoami-block {
    margin-top:2rem; border:1px solid var(--border); background:var(--bg2);
    font-family:var(--mono);
  }
  .whoami-trigger {
    display:flex; align-items:center; gap:10px; padding:0.85rem 1.25rem;
    cursor:pointer; border:none; background:transparent; width:100%; text-align:left;
    transition:background 0.2s;
  }
  .whoami-trigger:hover { background:var(--bg3); }
  .whoami-prompt { font-size:13px; color:var(--accent); }
  .whoami-cmd { font-size:13px; color:var(--text); }
  .whoami-arrow { font-size:11px; color:var(--accent); margin-left:auto; transition:transform 0.3s; }
  .whoami-arrow.open { transform:rotate(90deg); }
  .whoami-body { display:none; border-top:1px solid var(--border); padding:1.5rem; }
  .whoami-body.open { display:block; }
  .whoami-photos {
    display:grid; grid-template-columns:1fr 1fr; gap:1px;
    background:var(--border); margin-bottom:1.25rem;
  }
  .whoami-photo-wrap { background:var(--bg2); position:relative; overflow:hidden; }
  .whoami-photo-wrap img {
    width:100%; display:block; object-fit:cover;
    max-height:380px; filter:brightness(0.92) contrast(1.05);
    transition:filter 0.3s;
  }
  .whoami-photo-wrap:hover img { filter:brightness(1) contrast(1.1); }
  .whoami-photo-label {
    position:absolute; bottom:0; left:0; right:0;
    font-family:var(--mono); font-size:11px; color:var(--accent);
    background:rgba(10,14,26,0.82); padding:6px 12px; letter-spacing:1px;
  }
  .whoami-output { font-size:15px; line-height:1.9; color:rgba(232,234,246,0.75); }
  .whoami-output .whoami-key { color:var(--accent2); margin-right:8px; }
  .whoami-output div { margin-bottom:0.35rem; }
  .thm-badge-label { font-family:var(--mono); font-size:14px; color:var(--accent); letter-spacing:2px; display:flex; align-items:center; gap:8px; }
  .thm-badge-label::before { content:''; display:inline-block; width:20px; height:1px; background:var(--accent); }
  .thm-badge-label::after { content:''; flex:1; height:1px; background:var(--border); }
  .thm-badge-frame { border:1px solid var(--border); background:var(--bg2); padding:12px 16px; display:inline-flex; align-items:center; width:fit-content; margin-top:0.75rem; }
  .thm-badge-frame iframe { border:none; display:block; width:320px; height:80px; }
  .hero-stats { display:grid; grid-template-columns:repeat(3,1fr); gap:1px; margin-top:2rem; border:1px solid var(--border); background:var(--border); }
  .stat-box { background:var(--bg2); padding:1.5rem; text-align:center; }
  .stat-num { font-size:2.5rem; font-weight:800; color:var(--accent); display:block; }
  .stat-label { font-family:var(--mono); font-size:15px; color:var(--muted); letter-spacing:1px; }
  .sec-header { margin-bottom:3rem; }
  .sec-tag { font-family:var(--mono); font-size:13px; color:var(--accent); letter-spacing:3px; margin-bottom:0.75rem; display:block; }
  .sec-title { font-size:2.5rem; font-weight:800; letter-spacing:-1px; color:var(--text); font-family:var(--sans); }
  .timeline { position:relative; }
  .timeline::before { content:''; position:absolute; left:0; top:0; bottom:0; width:1px; background:linear-gradient(to bottom, var(--accent), transparent); }
  .tl-item { padding-left:2.5rem; margin-bottom:1.75rem; position:relative; }
  .tl-dot { position:absolute; left:-5px; top:14px; width:11px; height:11px; background:var(--accent); border:2px solid var(--bg); transform:rotate(45deg); transition:background 0.2s; }
  .tl-date { font-family:var(--mono); font-size:13px; color:var(--accent); letter-spacing:1px; margin-bottom:0.25rem; }
  .tl-company { font-size:1.2rem; font-weight:700; margin-bottom:0.15rem; color:var(--text); font-family:var(--sans); }
  .tl-role { font-family:var(--mono); font-size:14px; color:var(--muted); margin-bottom:0; }
  .tl-toggle {
    display:flex; align-items:center; justify-content:space-between;
    cursor:pointer; padding:0.6rem 0; border:none; background:transparent;
    width:100%; text-align:left; gap:1rem;
  }
  .tl-toggle:hover .tl-company { color:var(--accent); }
  .tl-toggle-icon {
    font-family:var(--mono); font-size:13px; color:var(--accent);
    flex-shrink:0; transition:transform 0.25s; user-select:none;
  }
  .tl-toggle-icon.open { transform:rotate(90deg); }
  .tl-body {
    display:none; padding-top:0.75rem;
    border-left:1px solid var(--border); margin-left:0.25rem; padding-left:1rem;
  }
  .tl-body.open { display:block; }
  .tl-impact {
    font-family:var(--mono); font-size:13px; color:var(--accent2);
    line-height:1.7; margin-bottom:0.75rem; padding:0.6rem 0.75rem;
    border-left:2px solid var(--accent2); background:rgba(0,195,255,0.05);
  }
  .tl-bullets { list-style:none; margin-bottom:0.5rem; }
  .tl-bullets li { font-family:var(--mono); font-size:13px; color:rgba(232,234,246,0.7); line-height:1.7; padding-left:1rem; position:relative; margin-bottom:0.25rem; }
  .tl-bullets li::before { content:'›'; position:absolute; left:0; color:var(--accent2); }
  .skills-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:1px; background:var(--border); }
  .skill-cat { background:var(--bg2); padding:1.5rem; }
  .skill-cat-title { font-family:var(--mono); font-size:13px; color:var(--accent); letter-spacing:2px; margin-bottom:1rem; display:flex; align-items:center; gap:8px; }
  .skill-cat-title::after { content:''; flex:1; height:1px; background:var(--border); }
  .skill-tags { display:flex; flex-wrap:wrap; gap:6px; }
  .tag { font-family:var(--mono); font-size:12px; padding:4px 10px; border:1px solid rgba(0,245,160,0.2); color:rgba(232,234,246,0.6); letter-spacing:0.5px; }
  .tag.hot { border-color:rgba(0,195,255,0.4); color:var(--accent2); }
  .projects-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(300px,1fr)); gap:1px; background:var(--border); }
  .proj-card { background:var(--bg2); padding:2rem; position:relative; overflow:hidden; cursor:pointer; transition:background 0.2s; }
  .proj-card:hover { background:var(--bg3); }
  .proj-card::before { content:''; position:absolute; top:0; left:0; right:0; height:2px; background:linear-gradient(90deg, var(--accent), var(--accent2)); transform:scaleX(0); transform-origin:left; transition:transform 0.3s; }
  .proj-card:hover::before { transform:scaleX(1); }
  .proj-type { font-family:var(--mono); font-size:12px; color:var(--accent); letter-spacing:2px; margin-bottom:0.75rem; }
  .proj-title { font-size:1.2rem; font-weight:700; margin-bottom:1rem; color:var(--text); font-family:var(--sans); }
  .proj-star { list-style:none; margin-bottom:1.25rem; display:flex; flex-direction:column; gap:0.5rem; }
  .proj-star li { font-family:var(--mono); font-size:13px; color:rgba(232,234,246,0.7); line-height:1.6; display:grid; grid-template-columns:70px 1fr; gap:8px; }
  .proj-star li span.star-label { color:var(--accent); font-size:12px; letter-spacing:1px; padding-top:1px; }
  .proj-meta { display:flex; gap:6px; flex-wrap:wrap; }
  .proj-tag { font-family:var(--mono); font-size:11px; padding:3px 8px; background:rgba(0,245,160,0.08); border:1px solid rgba(0,245,160,0.15); color:var(--accent); letter-spacing:0.5px; }
  .certs-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(200px,1fr)); gap:1px; background:var(--border); }
  .cert-card { background:var(--bg2); padding:1.25rem; display:flex; flex-direction:column; gap:6px; transition:background 0.2s; }
  .cert-card:hover { background:var(--bg3); }
  .cert-issuer { font-family:var(--mono); font-size:11px; color:var(--accent2); letter-spacing:1px; }
  .cert-name { font-size:14px; font-weight:700; line-height:1.3; color:var(--text); font-family:var(--sans); }
  .cert-dot { width:6px; height:6px; background:var(--accent); transform:rotate(45deg); margin-top:auto; }
  #contact { text-align:center; }
  .contact-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:1px; background:var(--border); margin:3rem 0; }
  .contact-item { background:var(--bg2); padding:1.5rem; text-align:center; }
  .contact-label { font-family:var(--mono); font-size:12px; color:var(--muted); letter-spacing:1px; margin-bottom:0.5rem; }
  .contact-val { font-family:var(--mono); font-size:14px; color:var(--accent); word-break:break-all; }
  .resume-section { margin-top:3rem; }
  .resume-label { font-family:var(--mono); font-size:12px; color:var(--accent); letter-spacing:3px; margin-bottom:1rem; display:flex; align-items:center; gap:8px; }
  .resume-label::before, .resume-label::after { content:''; flex:1; height:1px; background:var(--border); }
  .resume-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:1px; background:var(--border); }
  .resume-card { background:var(--bg2); padding:1.75rem; display:flex; flex-direction:column; gap:12px; transition:background 0.2s; position:relative; overflow:hidden; }
  .resume-card:hover { background:var(--bg3); }
  .resume-card::before { content:''; position:absolute; top:0; left:0; right:0; height:2px; background:linear-gradient(90deg, var(--accent), var(--accent2)); transform:scaleX(0); transform-origin:left; transition:transform 0.3s; }
  .resume-card:hover::before { transform:scaleX(1); }
  .resume-role { font-family:var(--mono); font-size:12px; color:var(--accent); letter-spacing:2px; }
  .resume-title { font-size:1.1rem; font-weight:700; line-height:1.3; color:var(--text); font-family:var(--sans); }
  .resume-desc { font-family:var(--mono); font-size:13px; color:rgba(232,234,246,0.55); line-height:1.7; }
  .resume-dl-btn { font-family:var(--mono); font-size:13px; letter-spacing:1px; padding:9px 18px; border:1px solid var(--accent); color:var(--accent); background:transparent; text-decoration:none; cursor:pointer; transition:all 0.2s; display:inline-flex; align-items:center; gap:8px; margin-top:auto; width:fit-content; }
  .resume-dl-btn:hover { background:var(--accent); color:var(--bg); }
  .resume-dl-btn svg { width:13px; height:13px; flex-shrink:0; }
  footer { border-top:1px solid var(--border); padding:2rem; text-align:center; font-family:var(--mono); font-size:13px; color:var(--muted); position:relative; z-index:1; }
  .tab-bar { display:flex; gap:0; margin-bottom:2rem; border:1px solid var(--border); }
  .tab-btn { font-family:var(--mono); font-size:13px; letter-spacing:1px; padding:10px 20px; background:transparent; border:none; color:var(--muted); cursor:pointer; transition:all 0.2s; flex:1; }
  .tab-btn.active { background:var(--accent); color:var(--bg); }
  .tab-btn:hover:not(.active) { color:var(--text); background:rgba(255,255,255,0.04); }
  .reveal { opacity:1; transform:translateY(0); transition:all 0.6s ease; }
  .reveal.visible { opacity:1; transform:translateY(0); }
  .blink { animation:blink 1s step-end infinite; }
  @keyframes blink { 50% { opacity:0; } }
  .divider { border:none; border-top:1px solid var(--border); margin:0; position:relative; z-index:1; }
</style>
</head>
<body>

<nav>
  <span class="nav-logo"><span id="typewriter"></span><span class="blink">&#9646;</span></span>
  <div class="nav-links">
    <a onclick="scrollToSection('about')">about</a>
    <a onclick="scrollToSection('experience')">experience</a>
    <a onclick="scrollToSection('skills')">skills</a>
    <a onclick="scrollToSection('projects')">projects</a>
    <a onclick="scrollToSection('certs')">certs</a>
    <a onclick="scrollToSection('contact')">contact</a>
  </div>
</nav>

<!-- HERO -->
<div style="position:relative;z-index:1;padding:0 2rem;">
<section id="about">
  <div class="hero-tag">threat intelligence &middot; threat hunting &middot; detection</div>
  <h1>
    <span class="h1-name">Alex Garcia</span>
    <span class="h1-role">Cyber Analyst</span>
  </h1>
  <p class="hero-sub"><span id="hero-typewriter"></span><span class="blink" id="hero-cursor">&#9646;</span></p>

  <div class="whoami-block">
    <button class="whoami-trigger" onclick="toggleWhoami(this)">
      <span class="whoami-prompt">root@cyberjudosec:~$</span>
      <span class="whoami-cmd">whoami</span>
      <span class="whoami-arrow">&#9658;</span>
    </button>
    <div class="whoami-body">
      <div class="whoami-photos">
        <div class="whoami-photo-wrap">
          <img src="images/hacker.jpeg" alt="Alex Garcia — Cyber persona">
          <div class="whoami-photo-label">// in the shadows</div>
        </div>
        <div class="whoami-photo-wrap">
          <img src="images/professional.jpeg" alt="Alex Garcia — Professional">
          <div class="whoami-photo-label">// in the boardroom</div>
        </div>
      </div>
      <div class="whoami-output">
        <div><span class="whoami-key">name</span>Alejandro Garcia</div>
        <div><span class="whoami-key">alias</span>CyberJudoSec &middot; Hackth3br0nx</div>
        <div><span class="whoami-key">role</span>Threat Hunting &amp; Forensics Analyst</div>
        <div><span class="whoami-key">origin</span>The Bronx, New York</div>
        <div><span class="whoami-key">base</span>Forsyth, Georgia</div>
        <div><span class="whoami-key">background</span>US Navy &rarr; QA Engineering &rarr; Network &rarr; IT Ops &rarr; Cloud &rarr; SOC &rarr; Threat Hunting</div>
        <div><span class="whoami-key">philosophy</span>Observe. Hypothesize. Validate. Never guess.</div>
        <div><span class="whoami-key">status</span><span style="color:var(--accent);"><span class="blink">&#9646;</span> actively hunting</span></div>
      </div>
    </div>
  </div>

  <div class="link-group" style="margin-top:2.5rem;">
    <div class="link-row">
      <span class="link-row-label">connect</span>
      <a class="btn btn-primary" href="https://linkedin.com/in/mralejandrogarcia85" target="_blank" rel="noopener">LinkedIn &#8599;</a>
    </div>
    <div class="link-row">
      <span class="link-row-label">cyber</span>
      <a class="btn btn-secondary" href="https://tryhackme.com/p/Hackth3br0nx" target="_blank" rel="noopener">TryHackMe &middot; Hackth3br0nx &#8599;</a>
      <a class="btn btn-thlabs" href="https://www.threathuntinglabs.com/u/hackth3br0nx" target="_blank" rel="noopener">Threat Hunting Labs &middot; hackth3br0nx &#8599;</a>
    </div>
    <div class="link-row">
      <span class="link-row-label">devsecops</span>
      <a class="btn btn-secondary" href="https://github.com/Hackth3br0nx" target="_blank" rel="noopener">GitHub &middot; Hackth3br0nx &#8599;</a>
      <a class="btn btn-devsec" href="https://codefinity.com/cv/35ba2da4-c3c9-459d-8d83-78a67c4f45fd" target="_blank" rel="noopener">Codefinity &middot; Coding &amp; DevSecOps Practice &#8599;</a>
    </div>
  </div>

  <div class="thm-badge-wrapper reveal" style="margin-top:3rem;">
    <div class="thm-badge-label">live tryhackme rank</div>
    <div class="thm-badge-frame">
      <iframe src="https://tryhackme.com/api/v2/badges/public-profile?userPublicId=3223714" scrolling="no" title="TryHackMe Badge"></iframe>
    </div>
  </div>

  <div class="hero-stats reveal">
    <div class="stat-box"><span class="stat-num">20+</span><span class="stat-label">years experience</span></div>
    <div class="stat-box"><span class="stat-num">14</span><span class="stat-label">certifications</span></div>
    <div class="stat-box"><span class="stat-num">3</span><span class="stat-label">lab projects</span></div>
  </div>
</section>
</div>

<hr class="divider">

<!-- EXPERIENCE -->
<div style="position:relative;z-index:1;padding:0 2rem;">
<section id="experience">
  <div class="sec-header reveal">
    <span class="sec-tag">// 01 &mdash; experience</span>
    <h2 class="sec-title">Career Timeline</h2>
  </div>
  <div style="font-family:var(--mono);font-size:11px;color:var(--accent);margin-bottom:2rem;display:inline-flex;align-items:center;gap:8px;border:1px solid rgba(0,245,160,0.25);padding:6px 14px;">
    <span style="font-size:10px;">&#9658;</span> click any role to expand details
  </div>
  <div class="timeline reveal">

    <div class="tl-item">
      <div class="tl-dot"></div>
      <div class="tl-date">2026 &mdash; PRESENT</div>
      <button class="tl-toggle" onclick="toggleTL(this)">
        <div><div class="tl-company">Business Operational Concepts</div><div class="tl-role">Threat Hunting &amp; Forensics Analyst &middot; Remote</div></div>
        <span class="tl-toggle-icon">&#9658;</span>
      </button>
      <div class="tl-body">
        <div class="tl-impact">Contributing to proactive threat detection by building hypothesis-driven hunt workflows and forensic investigation procedures that reduce attacker dwell time and improve detection coverage.</div>
        <ul class="tl-bullets">
          <li>Conduct hypothesis-driven threat hunts across enterprise telemetry</li>
          <li>Investigate suspicious identity, endpoint, and network activity</li>
          <li>Analyze attacker behavior aligned with MITRE ATT&amp;CK framework</li>
          <li>Perform forensic investigation to reconstruct incident timelines</li>
          <li>Develop detection queries and improve monitoring coverage</li>
        </ul>
      </div>
    </div>

    <div class="tl-item">
      <div class="tl-dot"></div>
      <div class="tl-date">2024 &mdash; 2026</div>
      <button class="tl-toggle" onclick="toggleTL(this)">
        <div><div class="tl-company">SAIC</div><div class="tl-role">Cyber Defense Analyst II &middot; Remote</div></div>
        <span class="tl-toggle-icon">&#9658;</span>
      </button>
      <div class="tl-body">
        <div class="tl-impact">Supported enterprise-level threat detection operations by monitoring and investigating security alerts across SIEM platforms, helping maintain visibility into adversary activity across a large-scale environment.</div>
        <ul class="tl-bullets">
          <li>Investigated security alerts within Microsoft Sentinel SIEM</li>
          <li>Conducted log analysis using KQL queries</li>
          <li>Monitored authentication events and endpoint telemetry</li>
          <li>Applied MITRE ATT&amp;CK techniques to analyze adversary activity</li>
          <li>Escalated security incidents and supported incident response operations</li>
        </ul>
      </div>
    </div>

    <div class="tl-item">
      <div class="tl-dot"></div>
      <div class="tl-date">2024 &mdash; 2025</div>
      <button class="tl-toggle" onclick="toggleTL(this)">
        <div><div class="tl-company">MassMutual</div><div class="tl-role">Cloud Migration Consultant &middot; Remote</div></div>
        <span class="tl-toggle-icon">&#9658;</span>
      </button>
      <div class="tl-body">
        <div class="tl-impact">Helped ensure cloud migrations were completed with security in mind, reviewing IAM configurations and documenting security considerations that reduced risk exposure during infrastructure transitions.</div>
        <ul class="tl-bullets">
          <li>Supported enterprise cloud migration initiatives across AWS and Azure environments</li>
          <li>Reviewed IAM configurations and access control policies</li>
          <li>Validated logging and monitoring for cloud workloads</li>
          <li>Documented security considerations for migrated systems</li>
        </ul>
      </div>
    </div>

    <div class="tl-item">
      <div class="tl-dot"></div>
      <div class="tl-date">2021 &mdash; 2023</div>
      <button class="tl-toggle" onclick="toggleTL(this)">
        <div><div class="tl-company">Chewy</div><div class="tl-role">IT Operations Center Analyst I &middot; Service Desk Analyst II &middot; Plantation, FL</div></div>
        <span class="tl-toggle-icon">&#9658;</span>
      </button>
      <div class="tl-body">
        <div class="tl-impact">Maintained operational continuity for enterprise IT systems while building foundational security skills in identity and access management, authentication monitoring, and security incident escalation.</div>
        <ul class="tl-bullets">
          <li>Monitored enterprise systems and IT infrastructure health</li>
          <li>Supported authentication systems and MFA troubleshooting</li>
          <li>Escalated security-related incidents to appropriate teams</li>
          <li>Managed identity and access management across enterprise platforms</li>
        </ul>
      </div>
    </div>

    <div class="tl-item">
      <div class="tl-dot"></div>
      <div class="tl-date">2020 &mdash; 2021</div>
      <button class="tl-toggle" onclick="toggleTL(this)">
        <div><div class="tl-company">Point Blank Enterprises</div><div class="tl-role">Systems Support Technician Level II</div></div>
        <span class="tl-toggle-icon">&#9658;</span>
      </button>
      <div class="tl-body">
        <div class="tl-impact">Consistently exceeded performance benchmarks by resolving over 258 escalated incidents with a 98% first-call resolution rate, cutting average resolution time by 35% through systematic troubleshooting.</div>
        <ul class="tl-bullets">
          <li>Managed and resolved over 258 Tier 2 escalated support incidents</li>
          <li>Reduced average resolution time by 35% through efficient troubleshooting</li>
          <li>Achieved 98% first call resolution rate for end-user technical issues</li>
          <li>Provided system support for enterprise hardware, software, and network issues</li>
        </ul>
      </div>
    </div>

    <div class="tl-item">
      <div class="tl-dot"></div>
      <div class="tl-date">2019 &mdash; 2020</div>
      <button class="tl-toggle" onclick="toggleTL(this)">
        <div><div class="tl-company">BetterNOI</div><div class="tl-role">Junior Network Engineer</div></div>
        <span class="tl-toggle-icon">&#9658;</span>
      </button>
      <div class="tl-body">
        <div class="tl-impact">Built hands-on experience with network security fundamentals by implementing firewall configurations and VLAN segmentation, directly contributing to a more segmented and secure network architecture.</div>
        <ul class="tl-bullets">
          <li>Monitored network performance and infrastructure health metrics</li>
          <li>Configured and maintained LAN and WAN networking equipment</li>
          <li>Implemented firewall configurations and VLAN segmentation</li>
          <li>Diagnosed connectivity issues and optimized network performance</li>
        </ul>
      </div>
    </div>

    <div class="tl-item">
      <div class="tl-dot"></div>
      <div class="tl-date">2018 &mdash; 2020</div>
      <button class="tl-toggle" onclick="toggleTL(this)">
        <div><div class="tl-company">Omnicomm Systems</div><div class="tl-role">QA Analyst II</div></div>
        <span class="tl-toggle-icon">&#9658;</span>
      </button>
      <div class="tl-body">
        <div class="tl-impact">Ensured the reliability and compliance of clinical trial software used by government agencies and private healthcare and pharmaceutical companies, where software defects carried real-world patient safety implications.</div>
        <ul class="tl-bullets">
          <li>Performed manual testing of clinical trial management software used by government and pharmaceutical clients</li>
          <li>Validated regulatory compliance requirements for healthcare and clinical data platforms</li>
          <li>Designed and executed test cases to validate software functionality and data integrity</li>
          <li>Investigated defects and collaborated with engineering teams on root cause analysis</li>
          <li>Supported regression testing and release validation cycles for mission-critical systems</li>
        </ul>
      </div>
    </div>

    <div class="tl-item">
      <div class="tl-dot"></div>
      <div class="tl-date">2017 &mdash; 2018</div>
      <button class="tl-toggle" onclick="toggleTL(this)">
        <div><div class="tl-company">Spirit Airlines</div><div class="tl-role">QA Analyst I</div></div>
        <span class="tl-toggle-icon">&#9658;</span>
      </button>
      <div class="tl-body">
        <div class="tl-impact">Helped maintain the quality and reliability of airline reservation and operations software used daily by thousands of customers and airline staff, catching defects before they reached production.</div>
        <ul class="tl-bullets">
          <li>Performed manual testing of airline reservation and operational software systems</li>
          <li>Tested hardware and software integrations used by airline operations teams</li>
          <li>Documented defects and tracked bug reports within issue tracking systems</li>
          <li>Worked with development teams to validate software fixes and releases</li>
        </ul>
      </div>
    </div>

    <div class="tl-item">
      <div class="tl-dot"></div>
      <div class="tl-date">2014 &mdash; 2016</div>
      <button class="tl-toggle" onclick="toggleTL(this)">
        <div><div class="tl-company">United Healthcare</div><div class="tl-role">Enrollment Team Coordinator</div></div>
        <span class="tl-toggle-icon">&#9658;</span>
      </button>
      <div class="tl-body">
        <div class="tl-impact">Stepped into leadership during operational gaps and system outages, keeping enrollment teams functional and reducing disruption to healthcare services for customers depending on timely enrollment support.</div>
        <ul class="tl-bullets">
          <li>Served as liaison between healthcare enrollment teams and IT support</li>
          <li>Coordinated issue resolution for system outages affecting phones and account access</li>
          <li>Acted as interim supervisor during operational escalations or staffing gaps</li>
          <li>Assisted agents with troubleshooting enrollment system issues</li>
        </ul>
      </div>
    </div>

    <div class="tl-item">
      <div class="tl-dot"></div>
      <div class="tl-date">2012 &mdash; 2014</div>
      <button class="tl-toggle" onclick="toggleTL(this)">
        <div><div class="tl-company">United Healthcare</div><div class="tl-role">Enrollment Agent</div></div>
        <span class="tl-toggle-icon">&#9658;</span>
      </button>
      <div class="tl-body">
        <div class="tl-impact">Helped customers navigate complex healthcare enrollment processes with accuracy and empathy, supporting program access for vulnerable populations including prenatal care and smoking cessation participants.</div>
        <ul class="tl-bullets">
          <li>Provided inbound customer support for healthcare enrollment programs</li>
          <li>Conducted health surveys and intake assessments for pre-existing conditions</li>
          <li>Assisted with prenatal care and smoking cessation program enrollment</li>
          <li>Documented patient information and coordinated with healthcare support teams</li>
        </ul>
      </div>
    </div>

    <div class="tl-item">
      <div class="tl-dot"></div>
      <div class="tl-date">2010 &mdash; 2012</div>
      <button class="tl-toggle" onclick="toggleTL(this)">
        <div><div class="tl-company">Secured Health Plans</div><div class="tl-role">Licensed Health Insurance Agent</div></div>
        <span class="tl-toggle-icon">&#9658;</span>
      </button>
      <div class="tl-body">
        <div class="tl-impact">Built a client book through consultative selling and compliance-focused advising, helping individuals and families find appropriate healthcare and financial coverage while maintaining full regulatory standards.</div>
        <ul class="tl-bullets">
          <li>Sold health insurance policies, life insurance products, and annuities</li>
          <li>Maintained compliance with insurance regulations and licensing standards</li>
          <li>Built long-term client relationships through consultative sales approaches</li>
        </ul>
      </div>
    </div>

    <div class="tl-item">
      <div class="tl-dot"></div>
      <div class="tl-date">2008 &mdash; 2010</div>
      <button class="tl-toggle" onclick="toggleTL(this)">
        <div><div class="tl-company">Foot Locker</div><div class="tl-role">Assistant Store Manager</div></div>
        <span class="tl-toggle-icon">&#9658;</span>
      </button>
      <div class="tl-body">
        <div class="tl-impact">Led day-to-day store operations and team development, maintaining strong sales performance and customer satisfaction through consistent staff coaching and operational discipline.</div>
        <ul class="tl-bullets">
          <li>Managed retail sales operations and daily store performance metrics</li>
          <li>Supervised staff scheduling, training, and performance coaching</li>
          <li>Oversaw cash management, inventory control, and loss prevention procedures</li>
        </ul>
      </div>
    </div>

    <div class="tl-item">
      <div class="tl-dot"></div>
      <div class="tl-date">2003 &mdash; 2007</div>
      <button class="tl-toggle" onclick="toggleTL(this)">
        <div><div class="tl-company">United States Navy</div><div class="tl-role">Aviation Ordnance Airman &middot; USS George Washington</div></div>
        <span class="tl-toggle-icon">&#9658;</span>
      </button>
      <div class="tl-body">
        <div class="tl-impact">Served honorably in a high-stakes, zero-tolerance environment managing explosive ordnance systems, developing the discipline, attention to detail, and accountability under pressure that defines the foundation of a strong security professional.</div>
        <ul class="tl-bullets">
          <li>Managed and maintained explosive ordnance systems following strict safety protocols</li>
          <li>Conducted inspections and maintenance of weapons support equipment</li>
          <li>Coordinated logistics, supply chain operations, and mission readiness activities</li>
          <li>Assisted with operational planning and resource allocation for aviation missions</li>
        </ul>
      </div>
    </div>

  </div>
</section>
</div>

<hr class="divider">

<!-- SKILLS -->
<div style="position:relative;z-index:1;padding:0 2rem;">
<section id="skills">
  <div class="sec-header reveal">
    <span class="sec-tag">// 02 &mdash; capabilities</span>
    <h2 class="sec-title">Skills &amp; Tools</h2>
  </div>
  <div class="skills-grid reveal">

    <div class="skill-cat">
      <div class="skill-cat-title">SIEM &amp; Detection</div>
      <div class="skill-tags">
        <span class="tag hot">Microsoft Sentinel</span>
        <span class="tag hot">Splunk</span>
        <span class="tag hot">Elastic SIEM</span>
        <span class="tag">KQL</span>
        <span class="tag">Splunk SPL</span>
        <span class="tag">ES|QL</span>
        <span class="tag">Log Correlation</span>
        <span class="tag">Detection Engineering</span>
        <span class="tag">Alert Triage</span>
        <span class="tag">UEBA</span>
        <span class="tag">Security Monitoring</span>
      </div>
    </div>

    <div class="skill-cat">
      <div class="skill-cat-title">Threat Intel &amp; OSINT</div>
      <div class="skill-tags">
        <span class="tag hot">Maltego</span>
        <span class="tag hot">Shodan</span>
        <span class="tag hot">VirusTotal</span>
        <span class="tag hot">ZeroFox</span>
        <span class="tag">SpiderFoot</span>
        <span class="tag">Censys</span>
        <span class="tag">SecurityTrails</span>
        <span class="tag">MITRE ATT&amp;CK</span>
        <span class="tag">IOC Analysis</span>
        <span class="tag">Threat Actor Profiling</span>
        <span class="tag">Dark Web Monitoring</span>
        <span class="tag">Intel Report Writing</span>
      </div>
    </div>

    <div class="skill-cat">
      <div class="skill-cat-title">Endpoint &amp; Identity</div>
      <div class="skill-tags">
        <span class="tag hot">Defender XDR</span>
        <span class="tag hot">Okta</span>
        <span class="tag hot">Wiz</span>
        <span class="tag hot">Forcepoint</span>
        <span class="tag">Defender for Endpoint</span>
        <span class="tag">Defender for Identity</span>
        <span class="tag">Defender for Office 365</span>
        <span class="tag">Microsoft Entra ID</span>
        <span class="tag">Active Directory</span>
        <span class="tag">SAML</span>
        <span class="tag">OAuth 2.0</span>
        <span class="tag">MFA</span>
        <span class="tag">Zero Trust</span>
        <span class="tag">PAM</span>
      </div>
    </div>

    <div class="skill-cat">
      <div class="skill-cat-title">Scripting &amp; Analysis</div>
      <div class="skill-tags">
        <span class="tag hot">Python</span>
        <span class="tag hot">KQL</span>
        <span class="tag">PowerShell</span>
        <span class="tag">Bash</span>
        <span class="tag">Splunk SPL</span>
        <span class="tag">Wireshark</span>
        <span class="tag">nmap</span>
        <span class="tag">tcpdump</span>
        <span class="tag">Regex</span>
        <span class="tag">JSON Parsing</span>
        <span class="tag">Log Analysis</span>
      </div>
    </div>

    <div class="skill-cat">
      <div class="skill-cat-title">Cloud Platforms</div>
      <div class="skill-tags">
        <span class="tag hot">AWS</span>
        <span class="tag hot">Microsoft Azure</span>
        <span class="tag hot">Google Cloud Platform</span>
        <span class="tag">Cloud Security Monitoring</span>
        <span class="tag">Cloud Migration</span>
        <span class="tag">IAM Policy Review</span>
        <span class="tag">S3 / Blob Storage</span>
        <span class="tag">CloudTrail / Azure Monitor</span>
        <span class="tag">Cloud SIEM Integration</span>
      </div>
    </div>

    <div class="skill-cat">
      <div class="skill-cat-title">Threat Hunting</div>
      <div class="skill-tags">
        <span class="tag hot">Hypothesis-Based Hunting</span>
        <span class="tag hot">Threat Hunting Labs</span>
        <span class="tag">Observation-Driven Hunting</span>
        <span class="tag">Adversary Profiling</span>
        <span class="tag">Lateral Movement Detection</span>
        <span class="tag">Persistence Mechanism Detection</span>
        <span class="tag">C2 Detection</span>
        <span class="tag">Incident Response</span>
        <span class="tag">Digital Forensics</span>
        <span class="tag">Timeline Reconstruction</span>
      </div>
    </div>

    <div class="skill-cat">
      <div class="skill-cat-title">Network Security</div>
      <div class="skill-tags">
        <span class="tag hot">DNS Analysis</span>
        <span class="tag hot">TCP/IP</span>
        <span class="tag">HTTP / HTTPS Analysis</span>
        <span class="tag">Firewall Configuration</span>
        <span class="tag">VLAN Segmentation</span>
        <span class="tag">VPN</span>
        <span class="tag">Packet Analysis</span>
        <span class="tag">Network Forensics</span>
        <span class="tag">IDS / IPS</span>
        <span class="tag">Zero Trust Networking</span>
      </div>
    </div>

    <div class="skill-cat">
      <div class="skill-cat-title">Operating Systems</div>
      <div class="skill-tags">
        <span class="tag hot">Linux</span>
        <span class="tag hot">Windows</span>
        <span class="tag hot">Kali Linux</span>
        <span class="tag">Ubuntu</span>
        <span class="tag">macOS</span>
        <span class="tag">iOS</span>
        <span class="tag">Android</span>
        <span class="tag">Windows Server</span>
        <span class="tag">REMnux</span>
      </div>
    </div>

  </div>
</section>
</div>

<hr class="divider">

<!-- PROJECTS -->
<div style="position:relative;z-index:1;padding:0 2rem;">
<section id="projects">
  <div class="sec-header reveal">
    <span class="sec-tag">// 03 &mdash; lab work</span>
    <h2 class="sec-title">Projects &amp; Write-Ups</h2>
  </div>
  <div class="tab-bar reveal">
    <button class="tab-btn active" onclick="switchTab(this,'all')">all</button>
    <button class="tab-btn" onclick="switchTab(this,'intel')">threat intel</button>
    <button class="tab-btn" onclick="switchTab(this,'hunting')">threat hunting</button>
    <button class="tab-btn" onclick="switchTab(this,'network')">network</button>
    <button class="tab-btn" onclick="switchTab(this,'vuln')">vulnerability</button>
    <button class="tab-btn" onclick="switchTab(this,'cloud')">cloud</button>
    <button class="tab-btn" onclick="switchTab(this,'arch')">architecture</button>
  </div>
  <div class="projects-grid reveal">

    <div class="proj-card" data-cat="intel">
      <div class="proj-type">// threat intelligence lab</div>
      <div class="proj-title">Malicious Infrastructure Investigation &middot; Microsoft Sentinel</div>
      <ul class="proj-star">
        <li><span class="star-label">SCENARIO</span><span>Suspicious domain and IP addresses appeared in enterprise telemetry with no clear attribution. The SOC needed to determine whether these indicators were part of an active attacker campaign.</span></li>
        <li><span class="star-label">GOAL</span><span>Identify the full scope of attacker infrastructure, map relationships between indicators, and produce an actionable intelligence report for the detection team.</span></li>
        <li><span class="star-label">ACTIONS</span><span>Used Maltego to pivot across domains, IPs, and hosting providers. Cross-referenced findings in Shodan, VirusTotal, and Censys. Mapped all observed TTPs to MITRE ATT&amp;CK techniques.</span></li>
        <li><span class="star-label">OUTCOME</span><span>Identified a cluster of related attacker infrastructure. Delivered a structured threat intelligence report with IOCs, infrastructure relationships, and ATT&amp;CK mappings ready for detection rule development.</span></li>
      </ul>
      <div class="proj-meta">
        <span class="proj-tag">Maltego</span><span class="proj-tag">Shodan</span>
        <span class="proj-tag">VirusTotal</span><span class="proj-tag">MITRE ATT&amp;CK</span><span class="proj-tag">Censys</span>
      </div>
      <a href="https://github.com/Hackth3br0nx/Cybersecurity-Portfolio/tree/main/threat-intel-investigation" target="_blank" rel="noopener" style="display:inline-flex;align-items:center;gap:6px;margin-top:1rem;font-family:var(--mono);font-size:12px;color:var(--accent2);text-decoration:none;">View Write-Up on GitHub &#8599;</a>
    </div>

    <div class="proj-card" data-cat="hunting">
      <div class="proj-type">// threat hunting lab</div>
      <div class="proj-title">Impossible Travel Detection &middot; KQL + Sentinel</div>
      <ul class="proj-star">
        <li><span class="star-label">SCENARIO</span><span>Authentication logs showed user sign-ins from geographically distant locations within timeframes physically impossible to travel. The hypothesis: compromised credentials being used by a remote threat actor.</span></li>
        <li><span class="star-label">GOAL</span><span>Build detection logic in Microsoft Sentinel to identify impossible travel login patterns and validate the hypothesis against simulated credential abuse in a personal lab environment.</span></li>
        <li><span class="star-label">ACTIONS</span><span>Wrote KQL queries against sign-in logs to calculate travel distance and velocity between sequential logins. Filtered for anomalous patterns, correlated with Defender for Identity alerts.</span></li>
        <li><span class="star-label">OUTCOME</span><span>Successfully detected simulated credential abuse scenarios. Query logic was tuned to reduce false positives and documented as a reusable detection rule template.</span></li>
      </ul>
      <div class="proj-meta">
        <span class="proj-tag">Microsoft Sentinel</span><span class="proj-tag">KQL</span>
        <span class="proj-tag">Defender for Identity</span><span class="proj-tag">Hypothesis-Based</span>
      </div>
      <a href="https://github.com/Hackth3br0nx/Cybersecurity-Portfolio/tree/main/impossible-travel-detection" target="_blank" rel="noopener" style="display:inline-flex;align-items:center;gap:6px;margin-top:1rem;font-family:var(--mono);font-size:12px;color:var(--accent2);text-decoration:none;">View Write-Up on GitHub &#8599;</a>
    </div>

    <div class="proj-card" data-cat="network">
      <div class="proj-type">// network analysis lab</div>
      <div class="proj-title">DNS Tunneling Detection &middot; Wireshark + Kali</div>
      <ul class="proj-star">
        <li><span class="star-label">SCENARIO</span><span>Packet captures contained unusual DNS traffic patterns — high query frequency, abnormally long subdomains, and consistent outbound communication to a single external resolver. Potential C2 channel via DNS tunneling.</span></li>
        <li><span class="star-label">GOAL</span><span>Confirm whether DNS tunneling was present, identify the exfiltration mechanism, and document the indicators for detection.</span></li>
        <li><span class="star-label">ACTIONS</span><span>Loaded PCAP into Wireshark on Kali Linux. Applied DNS and HTTP display filters to isolate suspicious traffic. Analyzed subdomain length, query frequency, and payload patterns consistent with tunneling tools.</span></li>
        <li><span class="star-label">OUTCOME</span><span>Confirmed DNS tunneling behavior used for data exfiltration. Documented IOCs including domain patterns, query intervals, and resolver IPs. Identified the likely tunneling tool based on traffic signatures.</span></li>
      </ul>
      <div class="proj-meta">
        <span class="proj-tag">Wireshark</span><span class="proj-tag">Kali Linux</span>
        <span class="proj-tag">DNS Analysis</span><span class="proj-tag">C2 Detection</span><span class="proj-tag">PCAP Analysis</span>
      </div>
      <a href="https://github.com/Hackth3br0nx/Cybersecurity-Portfolio/tree/main/01-network-traffic-analysis" target="_blank" rel="noopener" style="display:inline-flex;align-items:center;gap:6px;margin-top:1rem;font-family:var(--mono);font-size:12px;color:var(--accent2);text-decoration:none;">View Write-Up on GitHub &#8599;</a>
    </div>

    <div class="proj-card" data-cat="network">
      <div class="proj-type">// network traffic analysis lab</div>
      <div class="proj-title">Network Traffic Analysis &middot; Wireshark + tcpdump</div>
      <ul class="proj-star">
        <li><span class="star-label">SCENARIO</span><span>A simulated enterprise host generated anomalous traffic — high-frequency DNS queries and outbound connections on non-standard ports with no corresponding business justification.</span></li>
        <li><span class="star-label">GOAL</span><span>Analyze PCAP files to identify C2 communication, DNS tunneling, and suspicious HTTP activity. Document what normal vs suspicious traffic looks like for SOC use.</span></li>
        <li><span class="star-label">ACTIONS</span><span>Applied Wireshark display filters for DNS, TCP SYN, and HTTP POST traffic. Identified beaconing intervals, encoded POST payloads, and high-frequency subdomain queries.</span></li>
        <li><span class="star-label">OUTCOME</span><span>Confirmed C2 beaconing and DNS tunneling behavior. Produced detection notes with IOCs and Wireshark filter signatures for SOC analyst reuse.</span></li>
      </ul>
      <div class="proj-meta">
        <span class="proj-tag">Wireshark</span><span class="proj-tag">tcpdump</span>
        <span class="proj-tag">DNS Analysis</span><span class="proj-tag">TCP/IP</span><span class="proj-tag">C2 Detection</span>
      </div>
      <a href="https://github.com/Hackth3br0nx/Cybersecurity-Portfolio/tree/main/01-network-traffic-analysis" target="_blank" rel="noopener" style="display:inline-flex;align-items:center;gap:6px;margin-top:1rem;font-family:var(--mono);font-size:12px;color:var(--accent2);text-decoration:none;">View Write-Up on GitHub &#8599;</a>
    </div>

    <div class="proj-card" data-cat="vuln">
      <div class="proj-type">// vulnerability assessment lab</div>
      <div class="proj-title">Vulnerability Assessment &middot; Nmap + Nessus</div>
      <ul class="proj-star">
        <li><span class="star-label">SCENARIO</span><span>A simulated small business environment with 12 assets had not been formally assessed in 18 months. Potential unpatched vulnerabilities and misconfigurations across workstations, servers, and network infrastructure.</span></li>
        <li><span class="star-label">GOAL</span><span>Discover all assets, identify and prioritize vulnerabilities by severity, and deliver an executive summary and technical remediation report.</span></li>
        <li><span class="star-label">ACTIONS</span><span>Ran Nmap discovery and service scans across all subnets. Executed credentialed Nessus scan. Prioritized findings by CVSS score and asset criticality.</span></li>
        <li><span class="star-label">OUTCOME</span><span>Identified 3 Critical findings including EternalBlue on 6 workstations and default credentials on the firewall. Delivered prioritized remediation roadmap with 30-day action plan.</span></li>
      </ul>
      <div class="proj-meta">
        <span class="proj-tag">Nmap</span><span class="proj-tag">Nessus</span>
        <span class="proj-tag">CVE Analysis</span><span class="proj-tag">Risk Prioritization</span>
      </div>
      <a href="https://github.com/Hackth3br0nx/Cybersecurity-Portfolio/tree/main/02-vulnerability-assessment" target="_blank" rel="noopener" style="display:inline-flex;align-items:center;gap:6px;margin-top:1rem;font-family:var(--mono);font-size:12px;color:var(--accent2);text-decoration:none;">View Write-Up on GitHub &#8599;</a>
    </div>

    <div class="proj-card" data-cat="network">
      <div class="proj-type">// firewall &amp; segmentation lab</div>
      <div class="proj-title">Network Segmentation &middot; pfSense + VLAN Design</div>
      <ul class="proj-star">
        <li><span class="star-label">SCENARIO</span><span>A flat network gave every compromised host unrestricted lateral movement capability across all servers and infrastructure. Zero segmentation meant a single breach could reach everything.</span></li>
        <li><span class="star-label">GOAL</span><span>Design and implement VLAN segmentation with firewall rules to contain lateral movement, restrict server access, and isolate management infrastructure.</span></li>
        <li><span class="star-label">ACTIONS</span><span>Configured pfSense with 3 VLANs (User, Server, Management). Wrote default-deny firewall rules with explicit allow policies. Validated all rules using Nmap from each segment.</span></li>
        <li><span class="star-label">OUTCOME</span><span>All 5 validation tests passed. Lateral movement from User VLAN to Management VLAN blocked. Server access limited to SMB only from User VLAN. Attack surface significantly reduced.</span></li>
      </ul>
      <div class="proj-meta">
        <span class="proj-tag">pfSense</span><span class="proj-tag">VLAN</span>
        <span class="proj-tag">Firewall Rules</span><span class="proj-tag">Network Hardening</span>
      </div>
      <a href="https://github.com/Hackth3br0nx/Cybersecurity-Portfolio/tree/main/03-firewall-and-segmentation-lab" target="_blank" rel="noopener" style="display:inline-flex;align-items:center;gap:6px;margin-top:1rem;font-family:var(--mono);font-size:12px;color:var(--accent2);text-decoration:none;">View Write-Up on GitHub &#8599;</a>
    </div>

    <div class="proj-card" data-cat="hunting">
      <div class="proj-type">// siem threat hunting lab</div>
      <div class="proj-title">Credential Compromise Hunt &middot; Sentinel + Splunk</div>
      <ul class="proj-star">
        <li><span class="star-label">SCENARIO</span><span>No alert had fired, but routine log review flagged statistical anomalies in sign-in behavior. Hypothesis: a threat actor was authenticating with stolen credentials from geographically inconsistent locations.</span></li>
        <li><span class="star-label">GOAL</span><span>Hunt for credential compromise evidence using authentication telemetry, correlate with endpoint data, and map findings to MITRE ATT&amp;CK.</span></li>
        <li><span class="star-label">ACTIONS</span><span>Built KQL impossible travel queries in Sentinel. Correlated findings with Splunk endpoint logs. Reconstructed attacker timeline across 3 compromised accounts and 4 workstations.</span></li>
        <li><span class="star-label">OUTCOME</span><span>Confirmed credential compromise. Accounts disabled, sessions terminated. Detection rule documented. Timeline mapped from initial auth to lateral movement attempt in under 60 minutes.</span></li>
      </ul>
      <div class="proj-meta">
        <span class="proj-tag">Microsoft Sentinel</span><span class="proj-tag">KQL</span>
        <span class="proj-tag">Splunk</span><span class="proj-tag">MITRE ATT&amp;CK</span><span class="proj-tag">Incident Response</span>
      </div>
      <a href="https://github.com/Hackth3br0nx/Cybersecurity-Portfolio/tree/main/04-siem-threat-hunting" target="_blank" rel="noopener" style="display:inline-flex;align-items:center;gap:6px;margin-top:1rem;font-family:var(--mono);font-size:12px;color:var(--accent2);text-decoration:none;">View Write-Up on GitHub &#8599;</a>
    </div>

    <div class="proj-card" data-cat="cloud">
      <div class="proj-type">// cloud security lab</div>
      <div class="proj-title">Cloud Hardening &middot; AWS + Azure</div>
      <ul class="proj-star">
        <li><span class="star-label">SCENARIO</span><span>A simulated remote business migrated to AWS and Azure without security review. Public S3 buckets, wildcard IAM policies, disabled CloudTrail, and no alerting left the environment fully exposed.</span></li>
        <li><span class="star-label">GOAL</span><span>Identify and remediate cloud misconfigurations across both platforms. Establish logging, restrict public access, enforce least-privilege IAM, and document the before/after security posture.</span></li>
        <li><span class="star-label">ACTIONS</span><span>Blocked public S3 access, replaced wildcard IAM with least-privilege policies, enforced MFA conditions, enabled CloudTrail multi-region logging, and hardened Azure Blob storage access.</span></li>
        <li><span class="star-label">OUTCOME</span><span>All 6 critical misconfigurations remediated. CloudTrail logging enabled across all regions. Azure Monitor alerts configured. Environment moved from fully exposed to security baseline.</span></li>
      </ul>
      <div class="proj-meta">
        <span class="proj-tag">AWS</span><span class="proj-tag">Azure</span>
        <span class="proj-tag">IAM</span><span class="proj-tag">CloudTrail</span><span class="proj-tag">Cloud Security</span>
      </div>
      <a href="https://github.com/Hackth3br0nx/Cybersecurity-Portfolio/tree/main/05-cloud-security-lab" target="_blank" rel="noopener" style="display:inline-flex;align-items:center;gap:6px;margin-top:1rem;font-family:var(--mono);font-size:12px;color:var(--accent2);text-decoration:none;">View Write-Up on GitHub &#8599;</a>
    </div>

    <div class="proj-card" data-cat="arch">
      <div class="proj-type">// security architecture case study</div>
      <div class="proj-title">NIST Security Architecture &middot; 50-User Hybrid Company</div>
      <ul class="proj-star">
        <li><span class="star-label">SCENARIO</span><span>A 50-user hybrid company handling sensitive client data had no formal security program — antivirus only, no MFA, no SIEM, no segmentation, no incident response plan. NIST CSF maturity score: 1.2/5.</span></li>
        <li><span class="star-label">GOAL</span><span>Design a secure target architecture aligned to NIST CSF, map NIST 800-53 controls to identified risks, and deliver a phased implementation roadmap.</span></li>
        <li><span class="star-label">ACTIONS</span><span>Assessed environment against all 5 NIST CSF functions. Designed VLAN-segmented network, identity architecture with MFA and Conditional Access, and Sentinel-based detection stack. Mapped 10 priority controls to SP 800-53.</span></li>
        <li><span class="star-label">OUTCOME</span><span>Delivered target architecture design, full control mapping, 4-phase implementation roadmap, and 5 policy templates. Projected NIST CSF maturity improvement from 1.2 to 3.8/5 post-implementation.</span></li>
      </ul>
      <div class="proj-meta">
        <span class="proj-tag">NIST CSF</span><span class="proj-tag">NIST 800-53</span>
        <span class="proj-tag">Risk Assessment</span><span class="proj-tag">Security Architecture</span>
      </div>
      <a href="https://github.com/Hackth3br0nx/Cybersecurity-Portfolio/tree/main/06-nist-security-architecture" target="_blank" rel="noopener" style="display:inline-flex;align-items:center;gap:6px;margin-top:1rem;font-family:var(--mono);font-size:12px;color:var(--accent2);text-decoration:none;">View Write-Up on GitHub &#8599;</a>
    </div>

  </div>

  <div style="margin-top:2rem;padding:1.5rem;border:1px dashed rgba(0,245,160,0.2);font-family:var(--mono);font-size:13px;color:var(--muted);">
    <span style="color:var(--accent);">+ </span> More write-ups in progress &mdash; TryHackMe rooms, OSINT investigations, and detection rule library coming soon.
    <a href="https://github.com/Hackth3br0nx/Cybersecurity-Portfolio" target="_blank" rel="noopener" style="color:var(--accent2);text-decoration:none;"> View Full Portfolio on GitHub &#8594;</a>
  </div>

</section>
</div>

<hr class="divider">

<!-- CERTIFICATIONS -->
<div style="position:relative;z-index:1;padding:0 2rem;">
<section id="certs">
  <div class="sec-header reveal">
    <span class="sec-tag">// 04 &mdash; credentials</span>
    <h2 class="sec-title">Certifications</h2>
  </div>
  <div class="certs-grid reveal">
    <div class="cert-card"><div class="cert-issuer">EC-COUNCIL</div><div class="cert-name">Certified Ethical Hacker</div><div class="cert-dot"></div></div>
    <div class="cert-card"><div class="cert-issuer">GIAC</div><div class="cert-name">GSEC &mdash; Security Essentials</div><div class="cert-dot"></div></div>
    <div class="cert-card"><div class="cert-issuer">GIAC</div><div class="cert-name">GFACT &mdash; Foundational Cyber</div><div class="cert-dot"></div></div>
    <div class="cert-card"><div class="cert-issuer">CompTIA</div><div class="cert-name">Security+</div><div class="cert-dot"></div></div>
    <div class="cert-card"><div class="cert-issuer">CompTIA</div><div class="cert-name">Network+</div><div class="cert-dot"></div></div>
    <div class="cert-card"><div class="cert-issuer">CompTIA</div><div class="cert-name">A+</div><div class="cert-dot"></div></div>
    <div class="cert-card"><div class="cert-issuer">CompTIA</div><div class="cert-name">Infrastructure Specialist</div><div class="cert-dot"></div></div>
    <div class="cert-card"><div class="cert-issuer">CompTIA</div><div class="cert-name">Operations Specialist</div><div class="cert-dot"></div></div>
    <div class="cert-card"><div class="cert-issuer">AWS</div><div class="cert-name">Solutions Architect Associate</div><div class="cert-dot"></div></div>
    <div class="cert-card"><div class="cert-issuer">AWS</div><div class="cert-name">Cloud Practitioner</div><div class="cert-dot"></div></div>
    <div class="cert-card"><div class="cert-issuer">MICROSOFT</div><div class="cert-name">Azure Administrator AZ-104</div><div class="cert-dot"></div></div>
    <div class="cert-card"><div class="cert-issuer">MICROSOFT</div><div class="cert-name">Azure Fundamentals AZ-900</div><div class="cert-dot"></div></div>
    <div class="cert-card"><div class="cert-issuer">CISCO</div><div class="cert-name">CCNA</div><div class="cert-dot"></div></div>
    <div class="cert-card"><div class="cert-issuer">OKTA</div><div class="cert-name">Certified Professional</div><div class="cert-dot"></div></div>
  </div>
</section>
</div>

<hr class="divider">

<!-- CONTACT -->
<div style="position:relative;z-index:1;padding:0 2rem;">
<section id="contact">
  <div class="sec-header reveal" style="text-align:center;">
    <span class="sec-tag" style="display:block;text-align:center;">// 05 &mdash; connect</span>
    <h2 class="sec-title">Get In Touch</h2>
    <p style="font-family:var(--mono);font-size:12px;color:var(--muted);margin-top:1rem;max-width:400px;margin-left:auto;margin-right:auto;line-height:1.8;">Open to threat analyst roles, consulting, and collaboration on security research.</p>
  </div>

  <div class="contact-grid reveal">
    <div class="contact-item"><div class="contact-label">email</div><div class="contact-val">CyberJudoSec&#64;gmail&#46;com</div></div>
    <div class="contact-item"><div class="contact-label">location</div><div class="contact-val">Forsyth, Georgia</div></div>
    <div class="contact-item"><div class="contact-label">linkedin</div><div class="contact-val"><a href="https://linkedin.com/in/mralejandrogarcia85" target="_blank" rel="noopener" style="color:var(--accent2);text-decoration:none;">mralejandrogarcia85 &#8599;</a></div></div>
  </div>

  <div class="resume-section reveal">
    <div class="resume-label">download resume</div>
    <div class="resume-grid">
      <div class="resume-card">
        <div class="resume-role">// threat intelligence</div>
        <div class="resume-title">Cyber Threat Intelligence Analyst</div>
        <div class="resume-desc">Focused on adversary infrastructure analysis, OSINT enrichment, IOC documentation, and MITRE ATT&amp;CK mapping. Best for CTI and threat intelligence roles.</div>
        <a class="resume-dl-btn" href="resumes/Cyber_Threat_Intelligence_Analyst_Resume.pdf" download>
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M8 2v8M5 7l3 3 3-3M2 12v1a1 1 0 001 1h10a1 1 0 001-1v-1"/></svg>
          Download PDF
        </a>
      </div>
      <div class="resume-card">
        <div class="resume-role">// threat hunting</div>
        <div class="resume-title">Cybersecurity Threat Analyst</div>
        <div class="resume-desc">Focused on proactive threat hunting, KQL detection queries, SIEM investigation, and endpoint forensics. Best for SOC analyst and threat hunting roles.</div>
        <a class="resume-dl-btn" href="resumes/Cybersecurity_Threat_Analyst_Resume.pdf" download>
          <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M8 2v8M5 7l3 3 3-3M2 12v1a1 1 0 001 1h10a1 1 0 001-1v-1"/></svg>
          Download PDF
        </a>
      </div>
    </div>
  </div>

  <div style="text-align:center;margin-top:2.5rem;display:flex;justify-content:center;gap:1rem;flex-wrap:wrap;">
    <a class="btn btn-primary" href="mailto&#58;CyberJudoSec&#64;gmail&#46;com">Send Email &#8599;</a>
    <a class="btn btn-secondary" href="https://linkedin.com/in/mralejandrogarcia85" target="_blank" rel="noopener">LinkedIn &#8599;</a>
  </div>
</section>
</div>

<footer>
  <span style="color:var(--accent);">alex garcia</span> &middot; cybersecurity analyst &middot; forsyth, ga &middot; <span style="color:var(--accent2);">CyberJudoSec&#64;gmail&#46;com</span>
</footer>

<script>
  const heroText = "20 years of operational experience across the military, enterprise IT, QA engineering, and cybersecurity. I evolved from using technology, to understanding it, to building it, to securing and hardening it. Along the way I learned what threats are, how to assess them, and how to hunt them. I don't wait for alerts to find threats — I hunt them. Every investigation I run follows the same discipline I learned managing ordnance on a carrier: observe carefully, form a hypothesis, validate with evidence, and never guess.";
  const heroEl = document.getElementById('hero-typewriter');
  let heroIndex = 0;
  let heroDone = false;

  function typeHero() {
    if (heroIndex < heroText.length) {
      heroEl.textContent += heroText[heroIndex];
      heroIndex++;
      setTimeout(typeHero, 28);
    } else if (!heroDone) {
      heroDone = true;
      setTimeout(restartHero, 7000);
    }
  }

  function restartHero() {
    heroEl.textContent = '';
    heroIndex = 0;
    heroDone = false;
    setTimeout(typeHero, 1400);
  }

  typeHero();

  const phrases = [
    "CyberJudoSec",
    "Hello, World",
    "Wake Up, Neo",
    "Open Threat Intel",
    "I Know KQL",
    "Hack The Planet",
    "Hack Th3 Br0nx",
    "Nerdy Ninjutsu",
    "Open Domain Expansion",
    "ARISE",
    "Wu-Tang Is For The Children",
    "Follow The White Rabbit",
    "Threat Detected",
    "root@judosec:~#",
    "Initiating Hunt",
    "You Are Being Watched",
    "There Is No Patch For Human Error"
  ];
  const el = document.getElementById('typewriter');
  let phraseIndex = 0;
  let charIndex = 0;
  let deleting = false;
  let pauseTimer = null;

  function type() {
    const current = phrases[phraseIndex];
    if (!deleting) {
      charIndex++;
      el.textContent = current.substring(0, charIndex);
      if (charIndex === current.length) {
        deleting = true;
        pauseTimer = setTimeout(type, 2800);
        return;
      }
      setTimeout(type, 120);
    } else {
      charIndex--;
      el.textContent = current.substring(0, charIndex);
      if (charIndex === 0) {
        deleting = false;
        phraseIndex = (phraseIndex + 1) % phrases.length;
        setTimeout(type, 600);
        return;
      }
      setTimeout(type, 65);
    }
  }
  type();

  function toggleWhoami(btn) {
    const body = btn.nextElementSibling;
    const arrow = btn.querySelector('.whoami-arrow');
    const isOpen = body.classList.contains('open');
    body.classList.toggle('open', !isOpen);
    arrow.classList.toggle('open', !isOpen);
  }
  function toggleTL(btn) {
    const body = btn.nextElementSibling;
    const icon = btn.querySelector('.tl-toggle-icon');
    const isOpen = body.classList.contains('open');
    body.classList.toggle('open', !isOpen);
    icon.classList.toggle('open', !isOpen);
  }
  function scrollToSection(id) {
    document.getElementById(id).scrollIntoView({ behavior: 'smooth' });
  }
  function switchTab(btn, cat) {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    document.querySelectorAll('.proj-card').forEach(card => {
      card.style.display = (cat === 'all' || card.dataset.cat === cat) ? 'block' : 'none';
    });
  }
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(e => { if (e.isIntersecting) e.target.classList.add('visible'); });
  }, { threshold: 0.1 });
  document.querySelectorAll('.reveal').forEach(el => observer.observe(el));
</script>
</body>
</html>
