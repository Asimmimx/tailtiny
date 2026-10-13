"""Render the ESP32 compatibility chart (docs/compatibility.svg).

Status grid: one row per chip, one status chip per row. Status colors are the
reserved status palette (good/warning/serious/critical) and always come with an
icon + text label, never color alone. Text uses ink tokens, not status colors.
Light/dark both supported via prefers-color-scheme (GitHub honours it in SVG).
"""
import sys, json, html

rows = json.load(open(sys.argv[1], encoding='utf-8'))
out = sys.argv[2]

STATUS = {
    'tested':  ('good',     '✓', 'Tested on hardware with this fork'),
    'builds':  ('warning',  '○', 'Should work: builds, not tested with this fork'),
    'tight':   ('serious',  '!',      'Builds; very little RAM'),
    'no':      ('critical', '✕', 'Not supported'),
    'unknown': ('neutral',  '?',      'Needs newer ESP-IDF; not tried'),
}

W = 760
ROW_H = 44
TOP = 84
LEFT = 24
COL_CHIP = LEFT
COL_STATUS = 190
COL_NOTE = 400
H = TOP + ROW_H * len(rows) + 86

def esc(s):
    return html.escape(s, quote=True)

parts = [f'''<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" role="img" aria-labelledby="t d" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif">
<title id="t">TailTiny ESP32 compatibility</title>
<desc id="d">{esc('; '.join(f"{r['chip']}: {STATUS[r['status']][2]}. {r['note']}" for r in rows))}</desc>
<style>
  :root {{ --surface:#fcfcfb; --ink:#1a1a19; --ink2:#5f5e5a; --rule:#e6e5e0; --chipbg:#f3f2ee; }}
  @media (prefers-color-scheme: dark) {{
    :root {{ --surface:#1a1a19; --ink:#f3f2ee; --ink2:#a9a8a2; --rule:#33322f; --chipbg:#262624; }}
  }}
  .bg {{ fill: var(--surface); }}
  .title {{ fill: var(--ink); font-size: 18px; font-weight: 600; }}
  .sub {{ fill: var(--ink2); font-size: 12.5px; }}
  .hdr {{ fill: var(--ink2); font-size: 11.5px; font-weight: 600; letter-spacing: .04em; }}
  .chip {{ fill: var(--ink); font-size: 14px; font-weight: 600; }}
  .lbl {{ fill: var(--ink); font-size: 12.5px; }}
  .note {{ fill: var(--ink2); font-size: 12.5px; }}
  .rule {{ stroke: var(--rule); stroke-width: 1; }}
  .pill {{ fill: var(--chipbg); }}
  .good {{ fill: #0ca30c; }} .warning {{ fill: #fab219; }} .serious {{ fill: #ec835a; }} .critical {{ fill: #d03b3b; }} .neutral {{ fill: #8a8984; }}
  .icon {{ fill: #ffffff; font-size: 11px; font-weight: 700; }}
  .icon.warning {{ fill: #1a1a19; }}
</style>
<rect class="bg" width="{W}" height="{H}" rx="10"/>
<text class="title" x="{LEFT}" y="34">Which ESP32 works with TailTiny?</text>
<text class="sub" x="{LEFT}" y="54">Built with ESP-IDF v5.3.2 using the basic_connect example. Hardware testing on ESP32-C3.</text>
<text class="hdr" x="{COL_CHIP}" y="{TOP - 8}">CHIP</text>
<text class="hdr" x="{COL_STATUS}" y="{TOP - 8}">STATUS</text>
<text class="hdr" x="{COL_NOTE}" y="{TOP - 8}">NOTES</text>
<line class="rule" x1="{LEFT}" x2="{W - LEFT}" y1="{TOP}" y2="{TOP}"/>''']

for i, r in enumerate(rows):
    y = TOP + ROW_H * i
    cy = y + ROW_H / 2
    role, icon, label = STATUS[r['status']]
    short = {'tested': 'Tested', 'builds': 'Should work', 'tight': 'Low RAM', 'no': 'No', 'unknown': 'Unknown'}[r['status']]
    pill_w = 22 + 8 + len(short) * 7.4 + 12
    parts.append(f'<g><title>{esc(r["chip"] + ": " + label + ". " + r["note"])}</title>')
    parts.append(f'<text class="chip" x="{COL_CHIP}" y="{cy + 5}">{esc(r["chip"])}</text>')
    parts.append(f'<rect class="pill" x="{COL_STATUS}" y="{cy - 13}" width="{pill_w:.0f}" height="26" rx="13"/>')
    parts.append(f'<circle class="{role}" cx="{COL_STATUS + 13}" cy="{cy}" r="9"/>')
    parts.append(f'<text class="icon {role}" x="{COL_STATUS + 13}" y="{cy + 4}" text-anchor="middle">{icon}</text>')
    parts.append(f'<text class="lbl" x="{COL_STATUS + 28}" y="{cy + 4.5}">{esc(short)}</text>')
    parts.append(f'<text class="note" x="{COL_NOTE}" y="{cy + 4.5}">{esc(r["note"])}</text>')
    parts.append('</g>')
    parts.append(f'<line class="rule" x1="{LEFT}" x2="{W - LEFT}" y1="{y + ROW_H}" y2="{y + ROW_H}"/>')

ly = TOP + ROW_H * len(rows) + 32
legend_rows = [('tested', 'builds'), ('tight', 'no', 'unknown')]
for row in legend_rows:
    lx = LEFT
    for key in row:
        role, icon, label = STATUS[key]
        parts.append(f'<circle class="{role}" cx="{lx + 7}" cy="{ly - 4}" r="7"/>')
        parts.append(f'<text class="icon {role}" x="{lx + 7}" y="{ly - 0.5}" text-anchor="middle" font-size="9">{icon}</text>')
        parts.append(f'<text class="note" x="{lx + 19}" y="{ly}">{esc(label)}</text>')
        lx += 19 + len(label) * 6.4 + 26
    ly += 24

parts.append('</svg>')
open(out, 'w', encoding='utf-8', newline='\n').write('\n'.join(parts) + '\n')
print('wrote', out)
