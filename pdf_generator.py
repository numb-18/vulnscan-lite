import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable
)

from config import REPORTS_DIR

def generate_pdf_report(scan_id: str, report_data: Dict[str, Any]) -> str:
    """
    Generates an executive-ready, professional PDF report for the scan findings.
    Returns the absolute path of the generated PDF.
    """
    REPORTS_DIR.mkdir(exist_ok=True)
    pdf_filename = f"vulnscan_{scan_id}.pdf"
    pdf_path = REPORTS_DIR / pdf_filename
    
    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )
    
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=22,
        leading=26,
        textColor=colors.HexColor("#0F172A")
    )
    
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#64748B")
    )
    
    h2_style = ParagraphStyle(
        "H2",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#1E293B"),
        spaceBefore=14,
        spaceAfter=6
    )
    
    body_style = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155")
    )
    
    code_style = ParagraphStyle(
        "CodeSnippet",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#0F172A")
    )
    
    elements = []
    
    # Header Banner
    elements.append(Paragraph("VULNSCAN LITE", title_style))
    elements.append(Paragraph("Automated Web Security Posture & Vulnerability Health Audit", subtitle_style))
    elements.append(Spacer(1, 8))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284C7"), spaceAfter=14))
    
    # Target URL and Score Banner Table
    target_url = report_data.get("target_url", "N/A")
    score = report_data.get("score", 0)
    grade = report_data.get("grade", "N/A")
    grade_label = report_data.get("grade_label", "")
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    grade_color = colors.HexColor(report_data.get("grade_color", "#0284C7"))
    
    summary_data = [
        [
            Paragraph(f"<b>Target URL:</b> {target_url}<br/>"
                      f"<b>Audit Date:</b> {created_at}<br/>"
                      f"<b>Scan Reference ID:</b> {scan_id}<br/>"
                      f"<b>Assessment Mode:</b> Passive Non-Intrusive Analysis", body_style),
            Paragraph(f"<font size='28' color='{grade_color.hexval()}'><b>{grade}</b></font><br/>"
                      f"<font size='14'><b>{score} / 100</b></font><br/>"
                      f"<font size='8' color='#64748B'>{grade_label}</font>", ParagraphStyle("CenterScore", alignment=1))
        ]
    ]
    
    summary_table = Table(summary_data, colWidths=[4.2 * inch, 2.8 * inch])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#E2E8F0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("PADDING", (0, 0), (-1, -1), 10),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 14))
    
    # Metric Summary Cards
    passed_count = report_data.get("passed_count", 0)
    failed_count = report_data.get("failed_count", 0)
    warning_count = report_data.get("warning_count", 0)
    total_checks = report_data.get("total_checks", 0)
    
    metric_data = [
        [
            Paragraph(f"<font color='#10B981'><b>PASSED CHECKS</b></font><br/><font size='14'><b>{passed_count}</b></font>", ParagraphStyle("M1", alignment=1)),
            Paragraph(f"<font color='#EF4444'><b>FAILED CHECKS</b></font><br/><font size='14'><b>{failed_count}</b></font>", ParagraphStyle("M2", alignment=1)),
            Paragraph(f"<font color='#F59E0B'><b>WARNINGS</b></font><br/><font size='14'><b>{warning_count}</b></font>", ParagraphStyle("M3", alignment=1)),
            Paragraph(f"<font color='#0284C7'><b>TOTAL AUDITED</b></font><br/><font size='14'><b>{total_checks}</b></font>", ParagraphStyle("M4", alignment=1))
        ]
    ]
    metric_table = Table(metric_data, colWidths=[1.75 * inch] * 4)
    metric_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F1F5F9")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(metric_table)
    elements.append(Spacer(1, 12))
    
    # Technology and SSL Details
    details = report_data.get("details", {})
    ssl_info = details.get("ssl_tls", {})
    cms_info = details.get("cms_tech", {})
    
    tech_stack_str = ", ".join(cms_info.get("tech_stack", [])) or "None identified / Custom"
    ssl_status = f"{ssl_info.get('tls_version', 'N/A')} | {ssl_info.get('cipher', 'N/A')}" if ssl_info.get("valid") else "Invalid / Insecure"
    ssl_days = f"{ssl_info.get('days_until_expiry', 'N/A')} days" if ssl_info.get("days_until_expiry") is not None else "N/A"
    
    tech_data = [
        [Paragraph("<b>Identified Tech Stack:</b>", body_style), Paragraph(tech_stack_str, body_style)],
        [Paragraph("<b>SSL/TLS Protocol:</b>", body_style), Paragraph(f"{ssl_status} (Issuer: {ssl_info.get('issuer', 'N/A')})", body_style)],
        [Paragraph("<b>Cert Expiration:</b>", body_style), Paragraph(f"{ssl_info.get('expires_on', 'N/A')} ({ssl_days} remaining)", body_style)]
    ]
    tech_table = Table(tech_data, colWidths=[2.0 * inch, 5.0 * inch])
    tech_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 3),
    ]))
    elements.append(tech_table)
    elements.append(Spacer(1, 14))
    
    # Failed Checks & Remediation Section
    elements.append(Paragraph("Deficiencies & Remediation Action Plan", h2_style))
    failed_checks = report_data.get("failed_checks", [])
    
    if not failed_checks:
        elements.append(Paragraph("<b>No failed checks found!</b> The audited domain adheres to standard defensive configurations.", body_style))
    else:
        for idx, item in enumerate(failed_checks, start=1):
            rem = item.get("remediation", {})
            nginx_snippet = rem.get("nginx", "")
            apache_snippet = rem.get("apache", "")
            
            rem_content = f"<b>{idx}. {item.get('name')}</b> ({item.get('category')})<br/>" \
                          f"<font color='#DC2626'><b>Finding:</b></font> {item.get('message')}<br/>"
            if item.get("risk"):
                rem_content += f"<font color='#B45309'><b>Risk Impact:</b></font> {item.get('risk')}<br/>"
            
            check_box = [
                [Paragraph(rem_content, body_style)],
            ]
            if nginx_snippet:
                check_box.append([Paragraph(f"<b>Nginx Remediation:</b><br/><font face='Courier' color='#0F172A'>{nginx_snippet}</font>", code_style)])
            if apache_snippet:
                check_box.append([Paragraph(f"<b>Apache Remediation:</b><br/><font face='Courier' color='#0F172A'>{apache_snippet}</font>", code_style)])
                
            check_table = Table(check_box, colWidths=[7.0 * inch])
            check_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FEF2F2")),
                ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#FECACA")),
                ("PADDING", (0, 0), (-1, -1), 7),
            ]))
            elements.append(KeepTogether([check_table, Spacer(1, 8)]))
            
    # Warnings Section (if any)
    warning_checks = report_data.get("warning_checks", [])
    if warning_checks:
        elements.append(Spacer(1, 6))
        elements.append(Paragraph("Security Warnings & Observability", h2_style))
        for idx, item in enumerate(warning_checks, start=1):
            w_content = f"<b>{idx}. {item.get('name')}</b> - {item.get('message')}"
            if item.get("risk"):
                w_content += f"<br/><font color='#B45309'>Risk:</font> {item.get('risk')}"
            w_table = Table([[Paragraph(w_content, body_style)]], colWidths=[7.0 * inch])
            w_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFFBEB")),
                ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#FDE68A")),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]))
            elements.append(KeepTogether([w_table, Spacer(1, 6)]))
            
    # Passed Checks Overview Table
    elements.append(Spacer(1, 10))
    elements.append(Paragraph("Passed Posture Verifications", h2_style))
    passed_rows = [["Check Name", "Category", "Verification Note"]]
    for item in report_data.get("passed_checks", []):
        passed_rows.append([
            Paragraph(f"<b>{item.get('name')}</b>", body_style),
            Paragraph(item.get("category", ""), body_style),
            Paragraph(item.get("message", "Passed"), body_style)
        ])
        
    passed_table = Table(passed_rows, colWidths=[2.2 * inch, 1.8 * inch, 3.0 * inch])
    passed_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("PADDING", (0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#FFFFFF"), colors.HexColor("#F8FAFC")]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    elements.append(passed_table)
    
    # Legal Disclaimer Footer
    elements.append(Spacer(1, 20))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceAfter=8))
    disclaimer_text = (
        "<b>LEGAL & COMPLIANCE DISCLAIMER:</b> Only scan websites you own or have explicit authorization to test. "
        "This report is generated using passive inspection techniques (HTTP header inspection, SSL certificate verification, "
        "and public HTML meta parsing). No active exploitation, intrusive fuzzing, or invasive attack payloads were executed."
    )
    elements.append(Paragraph(disclaimer_text, ParagraphStyle("Disclaimer", parent=styles["Normal"], fontSize=7.5, leading=10, textColor=colors.HexColor("#94A3B8"))))
    
    doc.build(elements)
    return str(pdf_path)
