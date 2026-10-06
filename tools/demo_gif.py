#!/usr/bin/env python3
"""Record the README's demo GIF: one scan, from the landing page to the Scorecard's executive summary.

The script drives a deployed CloudGauge with the Google Chrome installed on this machine (Playwright's ``chrome``
channel), signing every request to the service — with ``gcloud auth print-identity-token`` on a service without
Identity-Aware Proxy, or with a token of the service account (``--iap-service-account``, see ``tools/iap_token.py``)
on the v16 deployment, where IAP does not take Google-issued identity tokens — and takes a still at each step:

    landing page → the scope chosen → Scan in progress (one still per poll) → Scan complete →
    Overview → each category page → Scorecard → Generate executive summary → the summary.

The stills become a GIF with Pillow: one palette for every frame, a hold time per frame, an endless loop. Every
still is kept in the work directory with a ``frames.json`` manifest, so a frame can be swapped and the GIF rebuilt
(``--assemble-only``) without scanning again. Member emails are blurred before each still; nothing else is altered.
Native ``<select>`` menus are OS popups and never appear in a page screenshot, so the scope step is shown as its
states (scope chosen and the resources loading, resource chosen and the button enabled) rather than an open menu.

Setup — none of this is a project dependency, so use a venv of its own::

    python3 -m venv /tmp/gifenv && /tmp/gifenv/bin/pip install playwright pillow

Record the README GIF from an organization scan on the deployed service (about five minutes)::

    /tmp/gifenv/bin/python tools/demo_gif.py --base https://cloudgauge-....run.app \\
        --scope organization --scope-id 123456789012 \\
        --iap-service-account cloudgauge-sa@my-project.iam.gserviceaccount.com

Try the report half on an existing report first (no scan), or rebuild the GIF from the kept stills::

    /tmp/gifenv/bin/python tools/demo_gif.py --base ... --scope organization --scope-id 123456789012 --report JOB_ID
    /tmp/gifenv/bin/python tools/demo_gif.py --assemble-only --work-dir /tmp/cloudgauge-demo-gif
"""

import argparse
import json
import pathlib
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlparse

ROOT = pathlib.Path(__file__).resolve().parent.parent

# The category pages, in sidebar order, with the frame name and hold time (ms) for each.
CATEGORY_PAGES = [
    ("security-identity", "security", 2000),
    ("cost-optimization", "cost", 1800),
    ("reliability-resilience", "reliability", 1800),
    ("operational-excellence-observability", "operations", 1800),
]
# The accordion opened on the Security page: a check whose rows name resources, not people.
OPENED_CHECK = "Open Firewall Rules"

BLUR_EMAILS_JS = """
() => {
    const find = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}/g;
    const has = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}/;
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
        acceptNode: (node) => {
            const parent = node.parentElement;
            if (!parent || ['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEXTAREA'].includes(parent.tagName) || parent.closest('[data-blurred]')) {
                return NodeFilter.FILTER_REJECT;
            }
            return has.test(node.nodeValue) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_SKIP;
        },
    });
    const nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    let count = 0;
    for (const node of nodes) {
        const text = node.nodeValue;
        const fragment = document.createDocumentFragment();
        let last = 0;
        let match;
        find.lastIndex = 0;
        while ((match = find.exec(text))) {
            fragment.appendChild(document.createTextNode(text.slice(last, match.index)));
            const span = document.createElement('span');
            span.textContent = match[0];
            span.setAttribute('data-blurred', '');
            span.style.filter = 'blur(4px)';
            fragment.appendChild(span);
            last = match.index + match[0].length;
            count += 1;
        }
        fragment.appendChild(document.createTextNode(text.slice(last)));
        node.parentNode.replaceChild(fragment, node);
    }
    return count;
}
"""

STATUS_PAGE_JS = """
() => ({
    heading: (document.querySelector('h1') || {}).textContent || '',
    percent: (document.getElementById('progress-text') || {}).textContent || '',
    task: (document.getElementById('status-message') || {}).textContent || '',
})
"""

DETAIL_CHECK_JS = """
({ section, fallback }) => {
    const checks = [...document.querySelectorAll(`${section} details.check`)];
    const nameOf = (d) => ((d.querySelector('summary strong') || d.querySelector('summary') || {}).textContent || '').trim();
    let pick = checks.find((d, i) => i > 0 && d.open && d.querySelector('table') && !d.innerText.includes('@'))
        || checks.find((d) => nameOf(d) === fallback);
    if (!pick) return null;
    pick.open = true;
    pick.scrollIntoView({ block: 'start' });
    window.scrollBy(0, -16);
    return nameOf(pick);
}
"""


def identity_token():
    """The signed-in gcloud user's identity token, which a Cloud Run service without IAP accepts as a Bearer token."""
    try:
        result = subprocess.run(["gcloud", "auth", "print-identity-token"], capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError) as error:
        sys.exit(f"Could not get an identity token from gcloud ({error}); run `gcloud auth login` first.")
    return result.stdout.strip()


def bearer_token(args):
    """The token every request to the service carries.

    Behind Identity-Aware Proxy (the v16 deployment) a Google-issued identity token is not accepted; IAP takes a
    JWT signed by a service account that holds ``roles/iap.httpsResourceAccessor`` — ``tools/iap_token.py`` mints
    one when ``--iap-service-account`` names it (``tools/deploy.sh PROGRAMMATIC_ACCESS=1`` sets up both grants).
    The pages then read *Signed in as <that account>*, blurred like every other email.
    """
    if not args.iap_service_account:
        return identity_token()
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    from iap_token import mint_iap_token

    return mint_iap_token(args.iap_service_account, args.base)


class Recorder:
    """Takes the stills and keeps the manifest."""

    def __init__(self, page, work, blur):
        self.page, self.work, self.blur, self.frames = page, work, blur, []

    def snap(self, name, hold, path=None):
        if self.blur:
            self.page.evaluate(BLUR_EMAILS_JS)
        path = path or self.work / f"{len(self.frames) + 1:02d}-{name}.png"
        self.page.screenshot(path=str(path))
        self.frames.append({"file": path.name, "hold": hold})
        print(f"  {path.name}  hold {hold} ms")
        return path

    def add(self, path, hold):
        self.frames.append({"file": path.name, "hold": hold})


def spread(items, count):
    """``count`` items spread evenly over ``items``, first and last included."""
    if len(items) <= count:
        return list(items)
    last = len(items) - 1
    return [items[round(i * last / (count - 1))] for i in range(count)]


def run_scan(rec, page, args):
    """Frames 1–13: the landing page, the scope, the scan, the completion. Returns the job id."""
    page.goto(f"{args.base}/")
    page.wait_for_selector("#scope")
    rec.snap("landing", 1500)

    page.select_option("#scope", args.scope)
    rec.snap("scope-chosen", 800)  # the Resource select says "Loading…" while the listing is on its way
    page.wait_for_function(
        "(() => { const s = document.getElementById('scope_id'); return !s.disabled && s.options.length > 1; })()",
        timeout=90_000)
    page.select_option("#scope_id", args.scope_id)
    page.wait_for_function("!document.getElementById('submit-btn').disabled")
    rec.snap("resource-chosen", 1500)

    page.click("#submit-btn")
    page.wait_for_url("**/status/**", timeout=60_000)
    page.wait_for_selector("#progress-bar")
    page.wait_for_timeout(1500)
    rec.snap("scan-started", 1000)

    # One still per poll while the scan runs, kept only when the percentage moved.
    stills, last_percent = [], None
    deadline = time.monotonic() + args.timeout_minutes * 60
    while True:
        state = page.evaluate(STATUS_PAGE_JS)
        heading = state["heading"].strip()
        if heading == "Scan complete":
            break
        if heading == "Scan failed":
            sys.exit(f"The scan failed ({state['task'].strip()}); nothing was recorded.")
        if time.monotonic() > deadline:
            sys.exit(f"The scan did not finish within {args.timeout_minutes} minutes.")
        percent = state["percent"].strip()
        if percent and percent != last_percent:
            path = rec.work / f"scan-{len(stills):03d}-{percent.rstrip('%')}.png"
            page.screenshot(path=str(path))
            stills.append(path)
            last_percent = percent
            print(f"  {path.name}  {state['task'].strip()}")
        page.wait_for_timeout(3000)
    for path in spread(stills, args.scan_frames):
        rec.add(path, 700)
    print(f"  {len(stills)} stills of the scan, {min(len(stills), args.scan_frames)} kept")

    page.wait_for_selector("a.btn-primary")
    rec.snap("scan-complete", 2000)
    href = page.get_attribute("a.btn-primary", "href")  # /report/<job id>/<scope id>
    return href.split("/")[2]


def record_report(rec, page, args, job_id):
    """Frames 14–23: the report's pages, the Scorecard, the executive summary."""
    page.goto(f"{args.base}/report/{job_id}/{args.scope_id}")
    page.wait_for_selector("#overview-section")
    page.wait_for_timeout(500)
    rec.snap("overview", 2500)

    changes = page.locator("#overview-section .card", has_text="Changes since last scan")
    if changes.count():
        changes.first.evaluate("el => el.scrollIntoView({block: 'start'})")
        page.evaluate("window.scrollBy(0, -16)")
    else:
        page.evaluate("window.scrollBy(0, Math.round(window.innerHeight * 0.8))")
    page.wait_for_timeout(300)
    rec.snap("overview-scrolled", 2000)

    for section, name, hold in CATEGORY_PAGES:
        link = page.locator(f'a.nav-link[href="#{section}"]')
        if not link.count():
            print(f"  (no {section} page in this report)")
            continue
        link.click()
        page.evaluate("window.scrollTo(0, 0)")
        page.wait_for_timeout(300)
        rec.snap(name, hold)
        if section == "security-identity":
            # A second look at the page: an open check with a table of resources (never one naming people),
            # or failing that a known resource-only check opened for the frame.
            shown = page.evaluate(DETAIL_CHECK_JS, {"section": f"#{section}-section", "fallback": OPENED_CHECK})
            if shown:
                page.wait_for_timeout(300)
                rec.snap("security-check", 2000)
                print(f"    (showing {shown})")

    page.click('a.nav-link[href="#scorecard"]')
    page.evaluate("window.scrollTo(0, 0)")
    page.wait_for_timeout(300)
    rec.snap("scorecard", 2500)

    page.click("#summaryBtn")
    page.wait_for_function("document.getElementById('summaryBtn').textContent.includes('Writing')", timeout=10_000)
    page.locator("#ai-summary-container").evaluate("el => { el.scrollIntoView({block: 'start'}); window.scrollBy(0, -16); }")
    page.wait_for_timeout(200)
    rec.snap("summary-writing", 1000)
    page.wait_for_function("document.querySelector('#ai-summary-content .prose-block') !== null", timeout=180_000)
    page.wait_for_timeout(500)
    # The page was at its maximum scroll while the summary was pending; now that it is taller, bring the card to the top.
    page.locator("#ai-summary-container").evaluate("el => { el.scrollIntoView({block: 'start'}); window.scrollBy(0, -16); }")
    page.wait_for_timeout(200)
    rec.snap("summary-ready", 4000)


def record(args, work):
    from playwright.sync_api import sync_playwright

    token = bearer_token(args)
    host = urlparse(args.base).netloc
    width, height = (int(n) for n in args.viewport.split("x"))

    def sign(route, request):
        if urlparse(request.url).netloc == host:
            route.continue_(headers={**request.headers, "Authorization": f"Bearer {token}"})
        else:
            route.continue_()

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel="chrome", headless=not args.headed)
        context = browser.new_context(viewport={"width": width, "height": height}, device_scale_factor=1)
        context.route("**/*", sign)
        page = context.new_page()
        rec = Recorder(page, work, blur=not args.no_blur)
        job_id = args.report or run_scan(rec, page, args)
        print(f"report {job_id}")
        record_report(rec, page, args, job_id)
        browser.close()
    (work / "frames.json").write_text(json.dumps(rec.frames, indent=1))
    return rec.frames


def assemble(work, frames, out, width):
    """The stills into one GIF: scaled to ``width``, one palette built from every frame, a hold time each."""
    from PIL import Image

    images = []
    for frame in frames:
        image = Image.open(work / frame["file"]).convert("RGB")
        if image.width != width:
            image = image.resize((width, round(image.height * width / image.width)), Image.LANCZOS)
        images.append(image)
    strip = Image.new("RGB", (width, sum(image.height for image in images)))
    y = 0
    for image in images:
        strip.paste(image, (0, y))
        y += image.height
    palette = strip.quantize(colors=256, method=Image.Quantize.MEDIANCUT)
    quantized = [image.quantize(palette=palette, dither=Image.Dither.NONE) for image in images]
    out.parent.mkdir(parents=True, exist_ok=True)
    quantized[0].save(out, save_all=True, append_images=quantized[1:], duration=[frame["hold"] for frame in frames],
                      loop=0, optimize=False)
    total = sum(frame["hold"] for frame in frames) / 1000
    print(f"{out}: {len(frames)} frames, {images[0].width}x{images[0].height}, {total:.1f} s per loop, "
          f"{out.stat().st_size / 1_000_000:.2f} MB")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--base", help="the deployed service, e.g. https://cloudgauge-....run.app")
    parser.add_argument("--scope", default="organization", choices=["organization", "folder", "project"])
    parser.add_argument("--scope-id", help="the organization, folder or project to scan")
    parser.add_argument("--report", metavar="JOB_ID", help="skip the scan and record an existing report")
    parser.add_argument("--out", type=pathlib.Path, default=ROOT / "assets" / "cloudgauge.gif")
    parser.add_argument("--work-dir", type=pathlib.Path, default=pathlib.Path(tempfile.gettempdir()) / "cloudgauge-demo-gif")
    parser.add_argument("--width", type=int, default=960, help="the GIF's width in pixels (default 960)")
    parser.add_argument("--viewport", default="1120x700", help="the browser viewport (default 1120x700, above the 1100px breakpoint)")
    parser.add_argument("--scan-frames", type=int, default=8, help="stills of the scan kept in the GIF (default 8)")
    parser.add_argument("--timeout-minutes", type=int, default=20)
    parser.add_argument("--no-blur", action="store_true", help="leave member emails readable")
    parser.add_argument("--headed", action="store_true", help="watch the browser")
    parser.add_argument("--iap-service-account", metavar="EMAIL",
                        help="the service behind Identity-Aware Proxy: sign requests with a token of this service account "
                             "(tools/iap_token.py) instead of the gcloud identity token")
    parser.add_argument("--assemble-only", action="store_true", help="rebuild the GIF from the work directory's frames.json")
    args = parser.parse_args(argv)

    work = args.work_dir
    work.mkdir(parents=True, exist_ok=True)
    if args.assemble_only:
        frames = json.loads((work / "frames.json").read_text())
    else:
        if not args.base or not args.scope_id:
            parser.error("--base and --scope-id are required unless --assemble-only")
        args.base = args.base.rstrip("/")
        print(f"stills in {work}")
        frames = record(args, work)
    assemble(work, frames, args.out, args.width)


if __name__ == "__main__":
    main()
