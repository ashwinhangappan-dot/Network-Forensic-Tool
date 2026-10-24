
from pathlib import Path
import json
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak
)

BASE_DIR = Path(__file__).resolve().parent.parent
RESULTS_DIR = BASE_DIR / "results"
OUTPUT_FILE = RESULTS_DIR / "network_forensic_report.pdf"


def safe_text(value):
    return escape(str(value if value is not None else "N/A"))


def flatten_json(data, prefix=""):
    rows = []

    if isinstance(data, dict):
        for key, value in data.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            rows.extend(flatten_json(value, name))

    elif isinstance(data, list):
        for index, value in enumerate(data):
            rows.extend(flatten_json(value, f"{prefix}[{index}]"))

    else:
        rows.append((prefix or "Value", str(data)))

    return rows


def generate_pdf():
    RESULTS_DIR.mkdir(exist_ok=True)

    report_path = RESULTS_DIR / "attack_report.json"
    forensic_path = RESULTS_DIR / "forensic_timeline.json"

    if not report_path.exists() or not forensic_path.exists():
        raise FileNotFoundError(
            "Analysis files missing. Analyze a PCAP first."
        )

    with report_path.open(encoding="utf-8") as file:
        report = json.load(file)

    with forensic_path.open(encoding="utf-8") as file:
        forensic = json.load(file)

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=18,
        leading=23,
        spaceAfter=12
    ))
    styles.add(ParagraphStyle(
        name="SmallCell",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11,
        wordWrap="CJK"
    ))

    story = []

    story.append(Paragraph(
        "NETWORK FORENSIC TOOL",
        styles["ReportTitle"]
    ))
    story.append(Paragraph(
        "Attack Analysis and Forensic Report",
        styles["Heading2"]
    ))
    story.append(Paragraph(
        "Generated on: " + datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
        styles["BodyText"]
    ))
    story.append(Spacer(1, 8 * mm))

    story.append(Paragraph("1. Analysis Summary", styles["Heading2"]))

    summary = [
        ["Metric", "Result"],
        ["Packets Analyzed", str(report.get("packets_analyzed", 0))],
        ["Alerts Found", str(report.get("alerts_found", 0))]
    ]

    summary_table = Table(summary, colWidths=[65 * mm, 90 * mm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("PADDING", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "TOP")
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 7 * mm))

    story.append(Paragraph("2. Attack Detection Details", styles["Heading2"]))

    alerts = report.get("alerts", [])
    alert_rows = [[
        "Time", "Attack Type", "Source IP", "Severity", "Details"
    ]]

    for alert in alerts:
        alert_rows.append([
            Paragraph(safe_text(alert.get("time", "N/A")),
                      styles["SmallCell"]),
            Paragraph(safe_text(alert.get("type", "N/A")),
                      styles["SmallCell"]),
            Paragraph(safe_text(alert.get("source_ip", "N/A")),
                      styles["SmallCell"]),
            Paragraph(safe_text(alert.get("severity", "N/A")),
                      styles["SmallCell"]),
            Paragraph(safe_text(alert.get("details", "N/A")),
                      styles["SmallCell"])
        ])

    if not alerts:
        alert_rows.append([
            Paragraph("No alerts detected.", styles["SmallCell"]),
            "", "", "", ""
        ])

    alert_table = Table(
        alert_rows,
        colWidths=[28 * mm, 31 * mm, 27 * mm, 20 * mm, 54 * mm],
        repeatRows=1
    )
    alert_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("PADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "TOP")
    ]))
    story.append(alert_table)
    story.append(Spacer(1, 7 * mm))

    story.append(Paragraph("3. Forensic Evidence", styles["Heading2"]))

    evidence_rows = [["Field", "Value"]]
    for key, value in flatten_json(forensic)[:150]:
        evidence_rows.append([
            Paragraph(safe_text(key), styles["SmallCell"]),
            Paragraph(safe_text(value), styles["SmallCell"])
        ])

    if len(evidence_rows) == 1:
        evidence_rows.append(["Evidence", "No forensic records available"])

    evidence_table = Table(
        evidence_rows,
        colWidths=[55 * mm, 105 * mm],
        repeatRows=1
    )
    evidence_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("PADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "TOP")
    ]))
    story.append(evidence_table)
    story.append(Spacer(1, 7 * mm))

    story.append(Paragraph("4. Conclusion", styles["Heading2"]))
    story.append(Paragraph(
        f"The analysis examined {report.get('packets_analyzed', 0)} "
        f"packets and reported {report.get('alerts_found', 0)} alert(s). "
        "Review the detection details and forensic evidence above "
        "for further investigation. Alerts indicate rule-based findings "
        "and should be verified before drawing conclusions.",
        styles["BodyText"]
    ))

    document = SimpleDocTemplate(
        str(OUTPUT_FILE),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm
    )
    document.build(story)
    print(f"Professional PDF report created: {OUTPUT_FILE}")


if __name__ == "__main__":
    generate_pdf()
