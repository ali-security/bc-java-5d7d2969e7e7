"""Print per-suite JUnit results and every skipped test from the Ant XML reports."""
import glob
import sys
import xml.etree.ElementTree as ET

report_dir = sys.argv[1]
total = failures = errors = skipped = 0
for path in sorted(glob.glob(report_dir + "/TEST-*.xml")):
    suite = ET.parse(path).getroot()
    t = int(suite.get("tests", 0))
    f = int(suite.get("failures", 0))
    e = int(suite.get("errors", 0))
    s = int(suite.get("skipped", 0) or 0)
    total += t
    failures += f
    errors += e
    skipped += s
    print("SUITE %s: tests=%d failures=%d errors=%d skipped=%d time=%ss" % (suite.get("name"), t, f, e, s, suite.get("time")))
    for case in suite.iter("testcase"):
        for tag in ("skipped", "failure", "error"):
            el = case.find(tag)
            if el is not None:
                print("  %s %s.%s: %s" % (tag.upper(), case.get("classname"), case.get("name"), (el.get("message") or "").strip()[:300]))
print("SEAL TEST TOTAL: tests=%d passed=%d failures=%d errors=%d skipped=%d" % (total, total - failures - errors - skipped, failures, errors, skipped))
if total == 0:
    sys.exit(1)
