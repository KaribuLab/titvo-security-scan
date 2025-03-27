import os
import sys
import json
import uuid
import base64
from base64 import b64decode
import logging
from datetime import datetime
import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv
from anthropic import Anthropic
from github import Github
import pytz
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import requests
from jinja2 import Environment, FileSystemLoader

# Configurar el logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
LOGGER = logging.getLogger("github_security_scan")

# Cargar variables de entorno desde el archivo .env
load_dotenv()

# Obtener las claves API desde el archivo .env
TITVO_SCAN_TASK_ID = os.getenv("TITVO_SCAN_TASK_ID")  # ID del trabajo de escaneo

# Modelo a utilizar
MODEL = "claude-3-7-sonnet-latest"
ACCESS_TOKEN_URL = "https://bitbucket.org/site/oauth2/access_token"
BITBUCKET_API_URL = "https://api.bitbucket.org/2.0"

# Inicializar el cliente de SSM
ssm = boto3.client("ssm")
secret_manager = boto3.client("secretsmanager")
s3 = boto3.client("s3")


def get_secret_manager_parameter(secret_name):
    """Obtiene un parámetro desde AWS Secret Manager."""
    try:
        response = secret_manager.get_secret_value(SecretId=secret_name)
        return response["SecretString"]
    except ClientError as e:
        LOGGER.error(
            "Error al obtener el parámetro %s desde Secret Manager: %s", secret_name, e
        )
        return None


def get_ssm_parameter(parameter_name):
    """Obtiene un parámetro desde AWS Parameter Store."""
    try:
        # Obtener el parámetro
        response = ssm.get_parameter(
            Name=parameter_name,
            WithDecryption=True,
        )

        # Extraer el valor del parámetro
        parameter_value = response["Parameter"]["Value"]
        LOGGER.info("Parámetro obtenido correctamente: %s", parameter_name)

        return parameter_value
    except ClientError as e:
        LOGGER.error(
            "Error al obtener el parámetro %s desde Parameter Store: %s",
            parameter_name,
            e,
        )
        return None


def get_anthropic_api_key():
    """Obtiene la clave de API de Anthropic desde Parameter Store."""
    param_path = f"/tvo/security-scan/{os.getenv('AWS_STAGE','prod')}"
    param_name = f"{param_path}/task-trigger/anthropic-api-key"

    return get_ssm_parameter(param_name)


def get_base_prompt():
    """Obtiene el system prompt desde Parameter Store."""
    param_path = f"/tvo/security-scan/{os.getenv('AWS_STAGE','prod')}"
    param_name = f"{param_path}/github-security-scan/system-prompt"

    system_prompt = get_ssm_parameter(param_name)

    if not system_prompt:
        LOGGER.error("No se pudo obtener el system prompt desde Parameter Store")
        LOGGER.error("Este parámetro es obligatorio para el funcionamiento del script")
        return None

    return system_prompt


def validate_environment_variables():
    """Valida que todas las variables de ambiente requeridas estén definidas."""
    if not all(
        [
            TITVO_SCAN_TASK_ID,
        ]
    ):
        LOGGER.error("Faltan variables de entorno.")
        LOGGER.error(
            "Asegúrate de configurar las siguientes variables en el archivo .env:"
        )
        LOGGER.error("- TITVO_SCAN_TASK_ID")
        return False
    return True


def github_download_repository_files(
    github_instance: Github, github_repo_name: str, github_commit_sha: str
):
    """Descarga los archivos del repositorio en el commit especificado."""
    try:
        # Obtener el repositorio
        LOGGER.info("Accediendo al repositorio: %s", github_repo_name)
        repo = github_instance.get_repo(github_repo_name)

        # Obtener el commit específico
        LOGGER.info("Obteniendo archivos del commit: %s", github_commit_sha)
        commit = repo.get_commit(github_commit_sha)

        # Crear directorio para los archivos si no existe
        os.makedirs("repo_files", exist_ok=True)

        # Descargar cada archivo del commit
        for file in commit.files:
            try:
                # Obtener el contenido del archivo
                content = repo.get_contents(file.filename, ref=github_commit_sha)

                # Crear directorios necesarios
                os.makedirs(
                    os.path.dirname(f"repo_files/{file.filename}"), exist_ok=True
                )

                # Decodificar y guardar el contenido
                if isinstance(content.content, str):
                    file_content = base64.b64decode(content.content).decode("utf-8")
                else:
                    file_content = content.decoded_content.decode("utf-8")

                with open(f"repo_files/{file.filename}", "w", encoding="utf-8") as f:
                    f.write(file_content)

                LOGGER.info("Archivo descargado: %s", file.filename)

            # pylint: disable=broad-exception-caught
            except Exception as e:
                # pylint: enable=broad-exception-caught
                LOGGER.error("Error al descargar %s: %s", file.filename, e)

        return True

    # pylint: disable=broad-exception-caught
    except Exception as e:
        # pylint: enable=broad-exception-caught
        LOGGER.error("Error al acceder al repositorio: %s", e)
        return False


def get_bitbucket_access_token():
    client_credentials = get_secret_manager_parameter(
        f"/tvo/security-scan/{os.getenv('AWS_STAGE','prod')}/bitbucket_client_credentials"
    )
    if client_credentials is not None or client_credentials != "":
        credentials = json.loads(client_credentials)
        client_id = credentials.get("key")
        client_secret = credentials.get("secret")
        response = requests.post(
            ACCESS_TOKEN_URL,
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "grant_type": "client_credentials",
            },
            timeout=30,
        )
        if response.status_code == 200:
            return response.json().get("access_token")
        else:
            LOGGER.error("Error al obtener el token de Bitbucket: %s", response.json())
            return None
    return None


def bitbucket_download_file(headers, workspace, repo, file_path, commit):
    """Descarga un archivo específico del commit."""
    content_url = (
        f"{BITBUCKET_API_URL}/repositories/{workspace}/{repo}/src/{commit}/{file_path}"
    )
    response = requests.get(content_url, headers=headers, timeout=30)

    if response.status_code == 200:
        # Crear directorios si no existen
        full_path = os.path.join("repo_files", file_path)
        dirname = os.path.dirname(full_path)
        if dirname != "":
            os.makedirs(dirname, exist_ok=True)

        # Guardar el contenido directamente
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(response.text)
        LOGGER.info("✓ Descargado: %s", full_path)
        return True
    return False


def bitbucket_download_repository_files(
    access_token: str,
    bitbucket_workspace: str,
    bitbucket_repo_slug: str,
    bitbucket_commit: str,
):
    """Descarga los archivos del repositorio de Bitbucket en el commit especificado.

    Args:
        bitbucket_workspace (str): El workspace de Bitbucket
        bitbucket_repo_slug (str): El slug del repositorio
        bitbucket_project_key (str): La clave del proyecto
        bitbucket_commit (str): El SHA del commit

    Returns:
        bool: True si la descarga fue exitosa, False en caso contrario
    """
    if access_token is None:
        LOGGER.error("No se pudo obtener el token de Bitbucket")
        return False

    try:
        LOGGER.info(
            "Accediendo al repositorio de Bitbucket: %s/%s",
            bitbucket_workspace,
            bitbucket_repo_slug,
        )
        LOGGER.info("Commit: %s", bitbucket_commit)

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }

        # Obtener información del commit específico usando la API REST
        commit_url = (
            f"{BITBUCKET_API_URL}/repositories/{bitbucket_workspace}/"
            f"{bitbucket_repo_slug}/commit/{bitbucket_commit}"
        )
        commit_response = requests.get(commit_url, headers=headers, timeout=30)

        if commit_response.status_code == 200:
            commit_info = commit_response.json()
            LOGGER.info("Información del commit %s:", bitbucket_commit)
            LOGGER.info("Hash: %s", commit_info["hash"])
            LOGGER.info("Fecha: %s", commit_info["date"])
            LOGGER.info("Mensaje: %s", commit_info["message"])
            LOGGER.info("Autor: %s", commit_info["author"]["raw"])

            # Obtener la lista de archivos modificados
            diff_url = (
                f"{BITBUCKET_API_URL}/repositories/{bitbucket_workspace}/"
                f"{bitbucket_repo_slug}/diff/{bitbucket_commit}"
            )
            diff_response = requests.get(diff_url, headers=headers, timeout=30)

            if diff_response.status_code == 200:
                diff_content = diff_response.text
                # Extraer los nombres de archivos del diff
                files = set()
                for line in diff_content.split("\n"):
                    if line.startswith("diff --git"):
                        # El formato es: diff --git a/path/to/file b/path/to/file
                        file_path = line.split(" b/")[1]
                        files.add(file_path)

                LOGGER.info("\nArchivos modificados:")
                for file in sorted(files):
                    LOGGER.info("- %s", file)

                LOGGER.info("\nDescargando archivos...")
                successful_downloads = 0
                for file in sorted(files):
                    if bitbucket_download_file(
                        headers,
                        bitbucket_workspace,
                        bitbucket_repo_slug,
                        file,
                        bitbucket_commit,
                    ):
                        successful_downloads += 1

                LOGGER.info(
                    "Resumen de descargas: %s/%s archivos descargados exitosamente",
                    successful_downloads,
                    len(files),
                )
            else:
                LOGGER.error(
                    "Error al obtener los archivos modificados: %s - %s",
                    diff_response.status_code,
                    diff_response.text,
                )
        else:
            LOGGER.error(
                "No se encontró el commit con hash %s",
                bitbucket_commit,
            )
            LOGGER.error(
                "Error: %s - %s",
                commit_response.status_code,
                commit_response.text,
            )

        return True

    except Exception as e:
        LOGGER.error("Error al acceder al repositorio de Bitbucket: %s", e)
        return False


def get_files_content():
    """Obtiene el contenido de todos los archivos descargados."""
    contenido_archivos = ""
    LOGGER.info("Obteniendo contenido de los archivos descargados")

    # Recorrer el directorio repo_files
    for root, _, files in os.walk("repo_files"):
        for file in files:
            # Construir la ruta completa del archivo
            ruta_archivo = os.path.join(root, file)

            # Obtener la ruta relativa para mostrarla en el prompt
            ruta_relativa = os.path.relpath(ruta_archivo, "repo_files")

            try:
                # Leer el contenido del archivo
                with open(ruta_archivo, "r", encoding="utf-8") as f:
                    contenido = f.read()

                # Añadir el nombre del archivo antes del bloque de código
                contenido_archivos += (
                    f"\n\n**Archivo: {ruta_relativa}**\n```\n{contenido}\n```"
                )
                LOGGER.debug(
                    "Contenido del archivo %s añadido al prompt", ruta_relativa
                )
            # pylint: disable=broad-exception-caught
            except Exception as e:
                # pylint: enable=broad-exception-caught
                LOGGER.error("Error al leer el archivo %s: %s", ruta_relativa, e)
                contenido_archivos += (
                    f"\n\n**Archivo: {ruta_relativa}**\n```\n"
                    f"Error al leer el archivo: {e}\n```"
                )

    return contenido_archivos


def generate_security_analysis_prompt(repo_info: dict, contenido_archivos: str) -> str:
    """Genera el prompt para el análisis de seguridad.

    Args:
        repo_info (dict): Diccionario con la información del repositorio
        contenido_archivos (str): Contenido de los archivos a analizar

    Returns:
        str: El prompt generado
    """
    repo_identifier = ""
    if repo_info.get("source") == "github":
        repo_identifier = repo_info.get("repo_name")
    elif repo_info.get("source") == "bitbucket":
        repo_identifier = f"{repo_info.get('workspace')}/{repo_info.get('repo_slug')}"

    return f"""
    A continuación te proporciono el código fuente de un commit específico 
    del repositorio {repo_identifier} (commit: {repo_info.get('commit_sha')}).
    Código fuente a analizar:{contenido_archivos}
    """


def analyze_code(
    client, system_prompt: str, user_prompt: str, scan_id: str, source: str
) -> tuple[bool, str]:
    """Realiza el análisis de seguridad del código.

    Args:
        client: Cliente de Claude
        system_prompt (str): Prompt del sistema
        user_prompt (str): Prompt del usuario
        scan_id (str): ID del escaneo

    Returns:
        tuple[bool, str]: Una tupla con (True si el commit es seguro, el análisis de seguridad)
    """
    try:
        # Enviar la solicitud a Claude
        respuesta = client.messages.create(
            model=MODEL,
            temperature=0.7,
            max_tokens=4000,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )

        # Obtener el análisis de Claude
        analysis = respuesta.content[0].text
        LOGGER.info("Análisis de seguridad recibido")

        # Mostrar la respuesta
        LOGGER.info("Respuesta :\n%s", analysis)

        # Verificar si el commit es seguro
        if not is_commit_safe(analysis, source):
            LOGGER.error(
                "¡COMMIT RECHAZADO! Se han detectado vulnerabilidades de seguridad."
            )
            return False, analysis
        else:
            LOGGER.info(
                "COMMIT APROBADO. No se detectaron vulnerabilidades "
                "de seguridad significativas."
            )
            # Actualizar el estado a COMPLETED
            update_scan_status(scan_id, "COMPLETED")
            return True, analysis

    except Exception as e:
        LOGGER.exception(e)
        exit_with_error(f"Error durante el análisis: {str(e)}", scan_id)
        return False, ""


def create_github_issue(
    analysis, commit_sha, github_instance, github_repo_name, github_assignee
):
    """Crea un issue en GitHub con el análisis de vulnerabilidades."""
    try:
        LOGGER.info("Creando issue en GitHub con el análisis de vulnerabilidades")

        # Obtener el repositorio
        repo = github_instance.get_repo(github_repo_name)

        # Obtener el commit específico
        commit = repo.get_commit(commit_sha)

        # Crear el título del issue
        title = f"[BUG] Security vulnerability in commit {commit_sha[:7]}"

        # Crear el cuerpo del issue
        body = (
            f"# 🐛 Security Bug Detected\n\n"
            f"**Commit:** {commit_sha}\n"
            f"**Author:** {commit.commit.author.name}\n\n"
            f"## Analysis Results\n\n{analysis}"
        )

        # Crear el issue con etiquetas de seguridad
        issue = repo.create_issue(title=title, body=body, labels=["bug"])

        # Asignar el issue al usuario especificado en la variable de ambiente
        try:
            # Solo asignar si hay un usuario configurado
            if github_assignee:
                LOGGER.info(
                    "Asignando issue al usuario configurado: %s", github_assignee
                )
                # Asignar el issue
                issue.add_to_assignees(github_assignee)
                LOGGER.info("Issue asignado a %s", github_assignee)

        except Exception as e:
            LOGGER.warning("Error al asignar el issue: %s", e)
            LOGGER.warning("Tipo de error: %s", type(e).__name__)

        return issue.html_url

    except Exception as e:
        LOGGER.error("Error al crear el issue en GitHub: %s", e)
        return None


def bitbucket_analysis_to_annotation(analysis_annotations, report_id):
    annotations = []
    for item in analysis_annotations:
        current_annotation = {}
        current_annotation["external_id"] = f"{report_id}-annotation-{uuid.uuid4()}"
        current_annotation["annotation_type"] = "VULNERABILITY"
        current_annotation["title"] = item.get("title")
        current_annotation["description"] = item.get("description")
        current_annotation["severity"] = item.get("severity")
        current_annotation["path"] = item.get("path")
        current_annotation["line"] = item.get("line")
        current_annotation["summary"] = item.get("summary")
        annotations.append(current_annotation)

    return annotations

def create_bitbucket_issue_html(json_analysis):
    """Genera el HTML del análisis usando una plantilla Jinja2."""
    try:
        # Configurar el entorno de Jinja2
        env = Environment(loader=FileSystemLoader('templates'))
        template = env.get_template('bitbucket_report.html')

        # Preparar los datos para la plantilla
        issues = json_analysis.get('annotations', [])
        total_issues = len(issues)
        
        # Contar issues por severidad
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        for issue in issues:
            severity = issue.get('severity', '').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        # Renderizar la plantilla
        html_content = template.render(
            workspace=json_analysis.get('workspace', ''),
            repo_slug=json_analysis.get('repo_slug', ''),
            commit_sha=json_analysis.get('commit_sha', ''),
            scan_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            total_issues=total_issues,
            recommendation=json_analysis.get('recommendation', ''),
            critical_issues=severity_counts['critical'],
            high_issues=severity_counts['high'],
            medium_issues=severity_counts['medium'],
            low_issues=severity_counts['low'],
            issues=issues
        )
        
        return html_content
    except Exception as e:
        LOGGER.error("Error al generar el HTML del reporte: %s", e)
        return "<html><body><h1>Error al generar el reporte</h1><p>Ha ocurrido un error al generar el reporte HTML.</p></body></html>"

def create_bitbucket_code_insights_report(
    access_token, workspace, repo, commit, is_safe, analysis
) -> str:
    """Crea un reporte de código en Bitbucket."""
    report_id = f"titvo-security-scan-{uuid.uuid4()}"
    create_report_url = (
        f"{BITBUCKET_API_URL}/repositories/{workspace}/{repo}/commit/{commit}/reports/"
        f"{report_id}"
    )
    create_annotation_url = (
        f"{BITBUCKET_API_URL}/repositories/{workspace}/{repo}/commit/{commit}/reports/"
        f"{report_id}/annotations"
    )
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }
    report_bucket = get_ssm_parameter(
        f"/tvo/security-scan/{os.getenv('AWS_STAGE','prod')}/"
        f"github-security-scan/report-bucket-name"
    )
    bucket_domain = get_ssm_parameter(
        f"/tvo/security-scan/{os.getenv('AWS_STAGE','prod')}/"
        f"github-security-scan/report-bucket-domain"
    )
    json_analysis = json.loads(analysis)
    # Añadir información adicional para la plantilla
    json_analysis['workspace'] = workspace
    json_analysis['repo_slug'] = repo
    json_analysis['commit_sha'] = commit
    analisys_annotations = json_analysis.get("annotations", [])
    html_analysis = create_bitbucket_issue_html(json_analysis)
    analysis_key = f"scm/bitbucket/scan/{TITVO_SCAN_TASK_ID}.html"
    s3.put_object(
        Bucket=report_bucket,
        Key=analysis_key,
        Body=html_analysis,
        ContentType="text/html; charset=utf-8",
    )
    report_url = f"{bucket_domain}/{analysis_key}"
    LOGGER.info("Reporte creado en S3: %s", report_url)
    payload = {
        "title": "Titvo Security Scan",
        "details": "Security scan report",
        "report_type": "SECURITY",
        "reporter": "titvo-security-scan",
        "result": "FAILED" if not is_safe else "SUCCESS",
        "data": [
            {
                "title": "Safe to merge?",
                "type": "BOOLEAN",
                "value": is_safe,
            },
            {
                "title": "Number of issues",
                "type": "NUMBER",
                "value": json_analysis.get("number_of_issues", 0),
            },
            {
                "title": "Report",
                "type": "LINK",
                "value": {"text": "See full report", "href": report_url},
            },
        ],
    }
    response = requests.put(
        create_report_url, headers=headers, json=payload, timeout=30
    )
    if response.status_code == 200:
        payload = bitbucket_analysis_to_annotation(analisys_annotations, report_id)
        response = requests.post(
            create_annotation_url, headers=headers, json=payload, timeout=30
        )
        if response.status_code == 200:
            LOGGER.info("Annotation creada exitosamente: %s", create_annotation_url)
        else:
            LOGGER.error(
                "Error al crear la annotation: %s - %s",
                response.status_code,
                response.text,
            )
            return None
        return report_url
    else:
        if response.json().get("key", "") == "report-service.report.max-reports":
            LOGGER.info("El reporte de código en Bitbucket está lleno")
            return ""
        LOGGER.error(
            "Error al crear el reporte de código en Bitbucket: %s", response.json()
        )
        return None


def is_commit_safe(analysis, source):
    """Determina si el commit es seguro basado en el análisis de Claude."""
    # Si el análisis contiene el patrón de rechazo, el commit no es seguro
    if source == "github" and "[COMMIT_RECHAZADO]" in analysis:
        return False
    elif source == "bitbucket" and "CRITICAL" in analysis:
        return False
    # Si no se encontró el patrón de rechazo, el commit es seguro
    return True


def get_table_name():
    """Obtiene el nombre de la tabla DynamoDB desde Parameter Store."""
    param_path = f"/tvo/security-scan/{os.getenv('AWS_STAGE','prod')}"
    param_name = f"{param_path}/task-trigger/dynamo-task-table-name"

    return get_ssm_parameter(param_name)


def get_scan_item(scan_id):
    """Obtiene el item de escaneo desde DynamoDB usando el scan_id."""
    try:
        # Obtener el nombre de la tabla
        nombre_tabla = get_table_name()
        if not nombre_tabla:
            LOGGER.error("No se pudo obtener el nombre de la tabla DynamoDB")
            return None

        # Inicializar el cliente de DynamoDB
        dynamodb = boto3.resource("dynamodb")
        tabla = dynamodb.Table(nombre_tabla)

        # Obtener el item
        response = tabla.get_item(Key={"scan_id": scan_id})

        # Verificar si el item existe
        if "Item" in response:
            LOGGER.info("Item de escaneo obtenido correctamente: %s", scan_id)
            item = response["Item"]
            return {
                "args": item["args"],
                "source": item["source"],
            }
        else:
            LOGGER.error("No se encontró el item con scan_id: %s", scan_id)
            return None
    except ClientError as e:
        LOGGER.error("Error al obtener el item desde DynamoDB: %s", e)
        return None


def update_scan_status(scan_id, status, result=None):
    """Actualiza el estado del escaneo en DynamoDB y opcionalmente el resultado."""
    # Obtener el nombre de la tabla
    nombre_tabla = get_table_name()
    if not nombre_tabla:
        LOGGER.error("No se pudo obtener el nombre de la tabla DynamoDB")
        return False

    # Inicializar el cliente de DynamoDB
    dynamodb = boto3.resource("dynamodb")
    tabla = dynamodb.Table(nombre_tabla)

    fecha_actual = datetime.now(pytz.utc).isoformat()

    # Preparar la expresión de actualización y los valores
    update_expression = "set #status = :s, updated_at = :u"
    expression_attribute_names = {"#status": "status"}
    expression_attribute_values = {":s": status, ":u": fecha_actual}

    # Si se proporciona el resultado, incluirlo en la actualización
    if result is not None:
        update_expression += ", scan_result = :r"
        expression_attribute_values[":r"] = result
        LOGGER.info("Se incluirá el resultado en la actualización: %s", result)

    # Actualizar el item
    tabla.update_item(
        Key={"scan_id": scan_id},
        UpdateExpression=update_expression,
        ExpressionAttributeNames=expression_attribute_names,
        ExpressionAttributeValues=expression_attribute_values,
        ReturnValues="UPDATED_NEW",
    )

    log_message = f"Estado del escaneo actualizado a: {status}, fecha: {fecha_actual}"
    if result is not None:
        log_message += f", result: {result}"
    LOGGER.info(log_message)

    return True


def exit_with_error(message, scan_id=None):
    """Actualiza el estado a ERROR en DynamoDB y termina el script con código 1."""
    LOGGER.error(message)
    if scan_id:
        update_scan_status(scan_id, "ERROR")
    sys.exit(1)


def decrypt(data):
    """Descifra un secreto desde AWS Secret Manager."""
    try:
        secret = get_secret_manager_parameter(
            f"/tvo/security-scan/{os.getenv('AWS_STAGE','prod')}/aes_secret"
        )
        if not secret:
            LOGGER.error("No se pudo obtener el secreto desde Secret Manager")
            return None
        key = b64decode(secret)
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted_data = unpad(cipher.decrypt(b64decode(data)), AES.block_size)
        return decrypted_data.decode("utf-8")
    except ClientError as e:
        LOGGER.exception(e)
        return None


def get_output_format(source):
    """Obtiene el formato de salida desde Parameter Store."""
    return get_ssm_parameter(
        f"/tvo/security-scan/{os.getenv('AWS_STAGE','prod')}/github-security-scan/output/{source}"
    )


def main():
    """Función principal para obtener una respuesta de Claude."""
    LOGGER.info("Iniciando análisis de seguridad")

    # Validar variables de ambiente
    if not validate_environment_variables():
        exit_with_error("Faltan variables de ambiente requeridas")

    # Imprimir el ID del trabajo de escaneo después de la validación
    LOGGER.info("ID del trabajo de escaneo: %s", TITVO_SCAN_TASK_ID)

    # Obtener el item de escaneo desde DynamoDB
    item_scan = get_scan_item(TITVO_SCAN_TASK_ID)
    if not item_scan:
        exit_with_error(
            "No se pudo obtener la información del escaneo desde DynamoDB",
            TITVO_SCAN_TASK_ID,
        )

    # Actualizar el estado a IN_PROGRESS
    if not update_scan_status(TITVO_SCAN_TASK_ID, "IN_PROGRESS"):
        exit_with_error(
            "No se pudo actualizar el estado del escaneo a IN_PROGRESS",
            TITVO_SCAN_TASK_ID,
        )
    # Obtener el system prompt desde Parameter Store
    base_prompt = get_base_prompt()
    if not base_prompt:
        exit_with_error(
            "No se pudo obtener el base prompt desde Parameter Store. "
            "Este parámetro es obligatorio.",
            TITVO_SCAN_TASK_ID,
        )
    LOGGER.info("System prompt obtenido correctamente")
    output_format = get_output_format(item_scan.get("source"))
    if not output_format:
        exit_with_error(
            "No se pudo obtener el formato de salida desde Parameter Store. "
            "Este parámetro es obligatorio.",
            TITVO_SCAN_TASK_ID,
        )
    LOGGER.info("Formato de salida obtenido correctamente")
    system_prompt = f"{base_prompt}\n\n{output_format}"
    # Inicializar el cliente de Anthropic
    client = Anthropic(api_key=get_anthropic_api_key())
    LOGGER.info("Enviando código para análisis")

    try:
        if item_scan.get("source") == "github":
            # Inicializar el cliente de GitHub
            github_client = Github(decrypt(item_scan.get("args").get("github_token")))
            github_repo_name = (
                item_scan.get("args").get("github_repo_name").replace('"', "")
            )
            github_commit_sha = (
                item_scan.get("args").get("github_commit_sha").replace('"', "")
            )
            github_assignee = (
                item_scan.get("args").get("github_assignee").replace('"', "")
            )
            # Descargar archivos del repositorio
            if not github_download_repository_files(
                github_client, github_repo_name, github_commit_sha
            ):
                exit_with_error(
                    "No se pudieron descargar los archivos del repositorio.",
                    TITVO_SCAN_TASK_ID,
                )
            # Obtener el contenido de los archivos
            contenido_archivos = get_files_content()

            # Preparar información del repositorio
            repo_info = {
                "source": "github",
                "repo_name": github_repo_name,
                "commit_sha": github_commit_sha,
                "assignee": github_assignee,
                "client": github_client,
            }

            # Generar el prompt
            user_prompt = generate_security_analysis_prompt(
                repo_info, contenido_archivos
            )

            # Realizar el análisis
            is_safe, analysis = analyze_code(
                client,
                system_prompt,
                user_prompt,
                TITVO_SCAN_TASK_ID,
                item_scan.get("source"),
            )
            if not is_safe:
                # Crear un issue en GitHub solo si se detectan vulnerabilidades
                issue_url = create_github_issue(
                    analysis,
                    github_commit_sha,
                    github_client,
                    github_repo_name,
                    github_assignee,
                )
                if issue_url:
                    LOGGER.info("Se ha creado un issue con el análisis: %s", issue_url)
                    LOGGER.error(
                        "Revisa el issue creado en GitHub para más detalles: %s",
                        issue_url,
                    )
                    # Actualizar el estado con la URL del issue
                    update_scan_status(
                        TITVO_SCAN_TASK_ID,
                        "FAILED",
                        {
                            "issue_url": issue_url,
                        },
                    )
            else:
                update_scan_status(
                    TITVO_SCAN_TASK_ID,
                    "SUCCESS",
                    {},
                )

        elif item_scan.get("source") == "bitbucket":
            # Obtener parámetros de Bitbucket
            bitbucket_workspace = (
                item_scan.get("args").get("bitbucket_workspace").replace('"', "")
            )
            bitbucket_repo_slug = (
                item_scan.get("args").get("bitbucket_repo_slug").replace('"', "")
            )
            bitbucket_project_key = (
                item_scan.get("args").get("bitbucket_project_key").replace('"', "")
            )
            bitbucket_commit = (
                item_scan.get("args").get("bitbucket_commit").replace('"', "")
            )

            access_token = get_bitbucket_access_token()
            if not access_token:
                exit_with_error(
                    "No se pudo obtener el token de Bitbucket",
                    TITVO_SCAN_TASK_ID,
                )

            # Descargar archivos del repositorio
            if not bitbucket_download_repository_files(
                access_token,
                bitbucket_workspace,
                bitbucket_repo_slug,
                bitbucket_commit,
            ):
                exit_with_error(
                    "No se pudieron descargar los archivos del repositorio de Bitbucket.",
                    TITVO_SCAN_TASK_ID,
                )

            # Obtener el contenido de los archivos
            contenido_archivos = get_files_content()

            # Preparar información del repositorio
            repo_info = {
                "source": "bitbucket",
                "workspace": bitbucket_workspace,
                "repo_slug": bitbucket_repo_slug,
                "project_key": bitbucket_project_key,
                "commit_sha": bitbucket_commit,
            }

            # Generar el prompt
            user_prompt = generate_security_analysis_prompt(
                repo_info, contenido_archivos
            )

            # Realizar el análisis
            is_safe, analysis = analyze_code(
                client,
                system_prompt,
                user_prompt,
                TITVO_SCAN_TASK_ID,
                item_scan.get("source"),
            )
            if not is_safe:
                report_url = create_bitbucket_code_insights_report(
                    access_token,
                    bitbucket_workspace,
                    bitbucket_repo_slug,
                    bitbucket_commit,
                    is_safe,
                    analysis,
                )
                if report_url is not None:
                    LOGGER.info(
                        "Se ha creado un reporte de código en Bitbucket: %s", report_url
                    )
                    LOGGER.error(
                        "Revisa el reporte de código en Bitbucket para más detalles: %s",
                        report_url,
                    )
                    # Actualizar el estado a FAILED
                    update_scan_status(
                        TITVO_SCAN_TASK_ID,
                        "FAILED",
                        {
                            "report_url": report_url,
                        },
                    )
                else:
                    exit_with_error(
                        "No se pudo crear el reporte de código en Bitbucket",
                        TITVO_SCAN_TASK_ID,
                    )
            else:
                update_scan_status(
                    TITVO_SCAN_TASK_ID,
                    "SUCCESS",
                    {},
                )

        else:
            LOGGER.info("No se pudo obtener el source del escaneo")
            exit_with_error(
                "No se pudo obtener el source del escaneo", TITVO_SCAN_TASK_ID
            )

    except Exception as e:
        LOGGER.exception(e)
        exit_with_error(f"Error durante el análisis: {str(e)}", TITVO_SCAN_TASK_ID)


if __name__ == "__main__":
    main()
