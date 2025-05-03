from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from titvo.app.scan.scan_entities import ScanResult


def create_issue_html(scan_result: ScanResult, template_path: str, template_name: str):
    """Genera el HTML del análisis usando una plantilla Jinja2."""
    # Configurar el entorno de Jinja2
    env = Environment(loader=FileSystemLoader(template_path))
    template = env.get_template(template_name)

    # Preparar los datos para la plantilla
    issues = scan_result.annotations
    total_issues = len(issues)

    # Contar issues por severidad
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for issue in issues:
        severity = issue.severity.lower()
        if severity in severity_counts:
            severity_counts[severity] += 1

    # Renderizar la plantilla
    html_content = template.render(
        scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total_issues=total_issues,
        critical_issues=severity_counts["critical"],
        high_issues=severity_counts["high"],
        medium_issues=severity_counts["medium"],
        low_issues=severity_counts["low"],
        issues=issues,
    )

    return html_content
