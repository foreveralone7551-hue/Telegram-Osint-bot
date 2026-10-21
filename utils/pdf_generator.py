from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.colors import HexColor

def generate_hlr_pdf(data: dict, filename: str = "hlr_report.pdf") -> str:
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle(
        'TitleStyle', parent=styles['Heading1'], fontSize=20,
        textColor=HexColor("#2c3e50"), spaceAfter=20
    )
    text_style = ParagraphStyle(
        'TextStyle', parent=styles['Normal'], fontSize=12, spaceAfter=10
    )

    story.append(Paragraph(f"HLR Phone Report", title_style))
    story.append(Paragraph(f"<b>Number:</b> {data.get('phone')}", text_style))
    story.append(Spacer(1, 10))

    info = [
        ("Valid", data.get('valid')),
        ("Active", data.get('active')),
        ("Carrier", data.get('carrier')),
        ("Line Type", data.get('line_type')),
        ("Country", data.get('country')),
        ("Location", data.get('location')),
        ("Fraud Score", f"{data.get('fraud_score')} / 100"),
        ("Risky", data.get('risky')),
    ]

    for key, value in info:
        story.append(Paragraph(f"<b>{key}:</b> {value}", text_style))

    doc.build(story)
    return filename
