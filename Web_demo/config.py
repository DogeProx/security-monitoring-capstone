"""Demo targets shared by the dashboard, CLI and scheduler."""

DEMO_ORIGIN = "http://127.0.0.1:5000"
DEMO_TARGETS = [
    f"{DEMO_ORIGIN}/secure",
    f"{DEMO_ORIGIN}/vuln-headers",
    f"{DEMO_ORIGIN}/vuln-cookie",
]
