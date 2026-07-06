from typing import Literal
from pydantic import BaseModel, Field


class ReportAnnotation(BaseModel):
    title: str = Field(
        ...,
        description=(
            "Título del issue encontrado. Siempre debe estar presente. "
            "Si el issue es de tipo NONE, no debe estar presente."
        ),
    )
    description: str = Field(
        ...,
        description=(
            "Breve descripción del issue encontrado. "
            "Si el issue es de tipo NONE, no debe estar presente."
        ),
    )
    summary: str = Field(
        ...,
        description=(
            "Breve resumen del issue en menos de 400 caracteres. "
            "Si el issue es de tipo NONE, no debe estar presente."
        ),
    )
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"] = Field(
        ...,
        description=(
            "Nivel de severidad del issue. Siempre debe estar presente. "
            "Si el issue es de tipo NONE, no debe estar presente."
        ),
    )
    path: str = Field(
        ...,
        description="Ruta del archivo donde se encontró el issue. Siempre debe estar presente.",
    )
    line: int = Field(
        ...,
        description=(
            "Primera línea del archivo donde se encontró el issue. "
            "Si el issue es de tipo NONE, no debe estar presente."
        ),
        ge=0,
    )
    code: str = Field(
        ...,
        description=(
            "Fragmento de código donde se encontró el issue. "
            "Si el issue es de tipo NONE, no debe estar presente."
        ),
    )
    recommendation: str = Field(
        ...,
        description=(
            "Recomendación para corregir el issue. "
            "Si el issue es de tipo NONE, no debe estar presente."
        ),
    )
