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
- Up to 50 shortest-first paths per critical server within a chosen hop limit
- Choke points: hosts every route must pass through
- Before/after service comparison, host-inbound policies and advisory hardening

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
- 115 automated tests, all passing; Windows/Linux CI workflow included
- Restricted scanner arguments, validated policy inputs and offline reports

**Slide 7: Progress: Lab Validation**
- Original VM experiment: 72/72 TCP observations matched
- Expanded experiment: 12 endpoint namespaces, 4 subnets, 3 policies
- 1,980/1,980 measured TCP/UDP connections matched, including host-inbound controls
- One shared Linux kernel; generic TCP listeners and UDP echo; no exploit testing
- [Image placeholder: expanded validation table; retain original VM screenshot separately]

**Slide 8: Progress: Large-Scale Evaluation**
- Repeated synthetic benchmarks: 500, 1,000 and 2,000 actual hosts; four policies; three timing repeats
- Show recorded median/min–max runtime and peak process memory, including resource limits
- Earlier 360-run approach comparison uses this model as reference, not independent ground truth
- Four-hop/50-path cap; sampled centrality for larger graphs; one topology seed in timing repeats
- [Image placeholder: experiments/results/large_2026-10-28/scalability.png; read actual final figures from summary.md]

**Slide 9: Contribution and Limits**
- Detects multi-hop exposure, not only direct connections
- Models local-subnet traffic and optional host-inbound firewalls
- Validated on a real network using the same policy file as the model
- Compares reimplemented approaches on stated synthetic scenarios
- Uses established graph algorithms; paths assume intermediate-host compromise

**Slide 10: Status and Next Steps**
- Current status: TRL 3, validated analytically and in a lab
- Working advisory recommender preserves declared direct business flows
- Next: coordinated policy changes, independent operator/platform validation
- No automatic TRL upgrade from one expanded namespace experiment
- Questions

---

## Images to insert after generating

| Slide | File (in the project folder) |
|---|---|
| 5 | Screenshot of `output\after.html` (open it in a browser, then press Win+Shift+S) |
| 7 | Capture `evidence\namespace_lab_2026-10-28\validation.md`; use `evidence\screenshots\09-segmented-from-kali.png` as earlier VM evidence |
| 8 | `experiments\results\large_2026-10-28\scalability.png` |

Optional extra figure for slide 8 or a backup slide: `experiments\results\fig_runtime.png`.
