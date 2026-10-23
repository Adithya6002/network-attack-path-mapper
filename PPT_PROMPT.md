# Prompt: Project Review Presentation

Copy everything below the line into a presentation tool (Microsoft Copilot in PowerPoint, Gamma, Canva Magic Design, or a chat assistant that can build .pptx files).

---

Create a 10-slide presentation for a university project review in Computer Networks.

**Style requirements**
- Clean, professional, minimal design. No emojis, no clip art, no decorative stripes.
- 16:9 layout. Dark navy title slide and closing slide; white background for content slides.
- One accent colour (teal) for highlights and key numbers.
- Fonts: a serif for titles (e.g. Cambria), a sans-serif for body text (e.g. Calibri).
- Short bullet points only (no paragraphs). Maximum 5 bullets per slide.
- Show key numbers large and bold where they appear (e.g. "72/72", "34 → 12").
- Leave space on slides 5, 7 and 8 for one image each (placeholders are noted below).
- Add short speaker notes to each slide summarising what to say.

**Slide content**

**Slide 1: Network Attack Path Mapper**
- Graph-based analysis of attack paths in computer networks
- Adithya | Computer Networks Project Review

**Slide 2: Problem**
- Firewall rules are reviewed individually
- Allowed connections can chain into multi-step routes
- Servers that look isolated may still be reachable through other hosts

**Slide 3: Approach**
- Model the network as a directed graph
  - Nodes: hosts
  - Edges: a host can connect to a service on another host
- Inputs: hosts, open services, subnets, firewall rules

**Slide 4: Capabilities**
- Reachable hosts and hop count
- All routes to critical servers
- Choke points: hosts every route must pass through
- Before/after comparison of firewall changes

**Slide 5: Sample Result**
- After segmentation:
  - Connections: 34 → 12
  - Routes to database: 50+ → 2
  - Database distance: 1 hop → 2 hops, only via the web server
- File server remains exposed: it shares a subnet with the database
- [Image placeholder: network graph after segmentation]

**Slide 6: Progress: Implementation**
- Python tool for graph building, route analysis and choke-point detection
- Interactive before/after network visualisations
- 41 automated tests, all passing
- Code version-controlled on GitHub

**Slide 7: Progress: Lab Validation**
- 4 virtual machines, 3 subnets, real iptables firewall
- One policy file drives both the model and the lab firewall
- 72 of 72 measured connections matched the model (95% CI: 95.0–100%)
- [Image placeholder: lab measurement screenshot]

**Slide 8: Progress: Large-Scale Evaluation**
- Simulated networks of up to 1,000 hosts, 360 comparison runs
- Compared with common methods:
  - Network scan: missed 100% of multi-hop routes
  - Zone-level rule review: 49% false alarms
  - Only this tool detected the firewall misconfiguration
- 1,000 hosts analysed in under 15 seconds
- [Image placeholder: comparison chart]

**Slide 9: Novelty**
- Detects multi-hop exposure, not only direct connections
- Models traffic inside subnets, which firewalls cannot filter
- Validated on a real network using the same policy file as the model
- Quantifies failure rates of existing methods
- Identifies choke points to prioritise defence

**Slide 10: Status and Next Steps**
- Current status: TRL 3, validated analytically and in a lab
- Next steps:
  - Recommend the minimum firewall change to protect critical servers
  - Validate on a larger, real network
- Questions

---

## Images to insert after generating

| Slide | File (in the project folder) |
|---|---|
| 5 | Screenshot of `output\after.html` (open it in a browser, then press Win+Shift+S) |
| 7 | `evidence\screenshots\09-segmented-from-kali.png` |
| 8 | `experiments\results\fig_exposure.png` |

Optional extra figure for slide 8 or a backup slide: `experiments\results\fig_runtime.png`.
