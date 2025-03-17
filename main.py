import os
import sys
import base64
import logging
from datetime import datetime
import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv
from anthropic import Anthropic
from github import Github
import pytz

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
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_REPO_NAME = os.getenv("GITHUB_REPO_NAME")
GITHUB_COMMIT_SHA = os.getenv("GITHUB_COMMIT_SHA")
GITHUB_ASSIGNEE = os.getenv("GITHUB_ASSIGNEE")  # Usuario para asignar issues
TITVO_SCAN_TASK_ID = os.getenv("TITVO_SCAN_TASK_ID")  # ID del trabajo de escaneo

# Modelo a utilizar
MODELO = "claude-3-7-sonnet-latest"


def validate_environment_variables():
    """Valida que todas las variables de ambiente requeridas estén definidas."""
    if not all(
        [
            ANTHROPIC_API_KEY,
            GITHUB_TOKEN,
            GITHUB_REPO_NAME,
            GITHUB_COMMIT_SHA,
            TITVO_SCAN_TASK_ID,
        ]
    ):
        LOGGER.error("Faltan variables de entorno.")
        LOGGER.error("Asegúrate de configurar las siguientes variables en el archivo .env:")
        LOGGER.error("- ANTHROPIC_API_KEY")
        LOGGER.error("- GITHUB_TOKEN")
        LOGGER.error("- GITHUB_REPO_NAME (formato: usuario/repositorio)")
        LOGGER.error("- GITHUB_COMMIT_SHA")
        LOGGER.error("- GITHUB_ASSIGNEE")
        LOGGER.error("- TITVO_SCAN_TASK_ID")
        return False
    return True


def download_repository_files(github_instance):
    """Descarga los archivos del repositorio en el commit especificado."""
    try:
        # Obtener el repositorio
        repo = github_instance.get_repo(GITHUB_REPO_NAME)
        LOGGER.info("Accediendo al repositorio: %s", GITHUB_REPO_NAME)

        # Obtener el commit específico
        commit = repo.get_commit(GITHUB_COMMIT_SHA)
        LOGGER.info("Obteniendo archivos del commit: %s", GITHUB_COMMIT_SHA)

        # Crear directorio para los archivos si no existe
        os.makedirs("repo_files", exist_ok=True)

        # Descargar cada archivo del commit
        for file in commit.files:
            try:
                # Obtener el contenido del archivo
                content = repo.get_contents(file.filename, ref=GITHUB_COMMIT_SHA)

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


def create_github_issue(analysis, commit_sha, github_instance):
    """Crea un issue en GitHub con el análisis de vulnerabilidades."""
    try:
        LOGGER.info("Creando issue en GitHub con el análisis de vulnerabilidades")

        # Obtener el repositorio
        repo = github_instance.get_repo(GITHUB_REPO_NAME)

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
        issue = repo.create_issue(
            title=title, 
            body=body,
            labels=["bug"]
        )

        # Asignar el issue al usuario especificado en la variable de ambiente
        try:
            # Solo asignar si hay un usuario configurado
            if GITHUB_ASSIGNEE:
                LOGGER.info(
                    "Asignando issue al usuario configurado: %s", GITHUB_ASSIGNEE
                )
                # Asignar el issue
                issue.add_to_assignees(GITHUB_ASSIGNEE)
                LOGGER.info("Issue asignado a %s", GITHUB_ASSIGNEE)

        except Exception as e:
            LOGGER.warning("Error al asignar el issue: %s", e)
            LOGGER.warning("Tipo de error: %s", type(e).__name__)

        return issue.html_url

    except Exception as e:
        LOGGER.error("Error al crear el issue en GitHub: %s", e)
        return None


# Prompt de sistema - Modifica esto según tus necesidades
SYSTEM_PROMPT = """
Eres Claude, un experto en seguridad informática y ciberseguridad.
Tu especialidad es el análisis de vulnerabilidades en código fuente, especialmente en código que no es capaz de detectarse en un análisis SAST.
Tu objetivo es analizar el código fuente de un repositorio y proporcionar un resumen de las vulnerabilidades encontradas.

Ejemplo de tipos de vulnerabilidades que debes buscar:
- Código backdoor
- Errores que podrían filtrar información sensible
- Filtración de datos de usuarios
- Filtración de secretos
- OWASP Top 10

FORMATO DE RESPUESTA:
1. SIEMPRE debes comenzar tu respuesta con uno de estos dos patrones:
   - "[COMMIT_RECHAZADO] - Este commit contiene vulnerabilidades de seguridad" (si encuentras vulnerabilidades de severidad media, alta o crítica)
   - "[COMMIT_APROBADO] - Este commit no contiene vulnerabilidades de seguridad significativas" (si no encuentras vulnerabilidades o solo encuentras de severidad baja)

2. Luego, proporciona un análisis detallado de las vulnerabilidades encontradas, organizadas por tipo y severidad.

3. Para cada vulnerabilidad, incluye:
   - Descripción del problema
   - Ubicación exacta (archivo y línea)
   - Impacto potencial
   - Recomendación para solucionarlo

Este formato es CRÍTICO para el procesamiento automatizado de tu respuesta.
"""


def is_commit_safe(analysis):
    """Determina si el commit es seguro basado en el análisis de Claude."""
    # Buscar el patrón específico que indica rechazo
    patron_rechazo = "[COMMIT_RECHAZADO]"

    # Si el análisis contiene el patrón de rechazo, el commit no es seguro
    if patron_rechazo in analysis:
        return False

    # Si no se encontró el patrón de rechazo, el commit es seguro
    return True


def get_table_name():
    """Obtiene el nombre de la tabla DynamoDB desde Parameter Store."""
    try:
        # Inicializar el cliente de SSM
        ssm = boto3.client("ssm")

        # Obtener el parámetro
        param_path = f"/tvo/security-scan/{os.getenv('AWS_STAGE','prod')}"
        param_name = f"{param_path}/task-trigger/dynamo-task-table-name"
        response = ssm.get_parameter(
            Name=param_name,
            WithDecryption=False,
        )

        # Extraer el valor del parámetro
        nombre_tabla = response["Parameter"]["Value"]
        LOGGER.info("Nombre de tabla DynamoDB obtenido: %s", nombre_tabla)

        return nombre_tabla
    except ClientError as e:
        LOGGER.error(
            "Error al obtener el nombre de la tabla desde Parameter Store: %s", e
        )
        return None


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
            return response["Item"]
        else:
            LOGGER.error("No se encontró el item con scan_id: %s", scan_id)
            return None
    except ClientError as e:
        LOGGER.error("Error al obtener el item desde DynamoDB: %s", e)
        return None


def update_scan_status(scan_id, status, issue_url=None):
    """Actualiza el estado del escaneo en DynamoDB y opcionalmente la URL del issue."""
    try:
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
        expression_attribute_values = {
            ":s": status,
            ":u": fecha_actual
        }
        
        # Si se proporciona la URL del issue, incluirla en la actualización
        if issue_url:
            update_expression += ", issue_url = :i"
            expression_attribute_values[":i"] = issue_url
            LOGGER.info("Se incluirá la URL del issue en la actualización: %s", issue_url)

        # Actualizar el item
        tabla.update_item(
            Key={"scan_id": scan_id},
            UpdateExpression=update_expression,
            ExpressionAttributeNames=expression_attribute_names,
            ExpressionAttributeValues=expression_attribute_values,
            ReturnValues="UPDATED_NEW",
        )

        log_message = f"Estado del escaneo actualizado a: {status}, fecha: {fecha_actual}"
        if issue_url:
            log_message += f", issue_url: {issue_url}"
        LOGGER.info(log_message)
        
        return True
    except ClientError as e:
        LOGGER.error("Error al actualizar el estado en DynamoDB: %s", e)
        return False


def exit_with_error(message, scan_id=None):
    """Actualiza el estado a ERROR en DynamoDB y termina el script con código 1."""
    LOGGER.error(message)
    if scan_id:
        update_scan_status(scan_id, "ERROR")
    sys.exit(1)


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
            TITVO_SCAN_TASK_ID
        )

    # Actualizar el estado a IN_PROGRESS
    if not update_scan_status(TITVO_SCAN_TASK_ID, "IN_PROGRESS"):
        exit_with_error(
            "No se pudo actualizar el estado del escaneo a IN_PROGRESS", 
            TITVO_SCAN_TASK_ID
        )

    # Inicializar el cliente de GitHub
    github_client = Github(GITHUB_TOKEN)

    # Descargar archivos del repositorio
    if not download_repository_files(github_client):
        exit_with_error(
            "No se pudieron descargar los archivos del repositorio.", 
            TITVO_SCAN_TASK_ID
        )

    # Obtener el contenido de los archivos
    contenido_archivos = get_files_content()

    # Inicializar el cliente de Anthropic
    client = Anthropic(api_key=ANTHROPIC_API_KEY)
    LOGGER.info("Enviando código para análisis")

    try:
        user_prompt = f"""
        A continuación te proporciono el código fuente de un commit específico 
        del repositorio {GITHUB_REPO_NAME} (commit: {GITHUB_COMMIT_SHA}).
        
        El formato de presentación es el siguiente:
        - Cada archivo se presenta con su nombre en formato **Archivo: ruta/al/archivo**
        - Seguido por el contenido del archivo dentro de un bloque de código markdown
        
        Analiza el código y proporciona un resumen de las vulnerabilidades encontradas en formato markdown, organizadas por tipo de vulnerabilidad y severidad.
        
        Recuerda que debes comenzar tu respuesta con el patrón [COMMIT_RECHAZADO] o [COMMIT_APROBADO] según corresponda.
        
        Código fuente a analizar:{contenido_archivos}
        """

        # Enviar la solicitud a Claude
        respuesta = client.messages.create(
            model=MODELO,
            max_tokens=4000,
            temperature=0.7,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )

        # Obtener el análisis de Claude
        analisis = respuesta.content[0].text
        LOGGER.info("Análisis de seguridad recibido")

        # Mostrar la respuesta
        LOGGER.info("Respuesta :\n%s", analisis)

        # Verificar si el commit es seguro
        if not is_commit_safe(analisis):
            LOGGER.error(
                "¡COMMIT RECHAZADO! Se han detectado vulnerabilidades de seguridad."
            )
            
            # Crear un issue en GitHub solo si se detectan vulnerabilidades
            issue_url = create_github_issue(analisis, GITHUB_COMMIT_SHA, github_client)
            if issue_url:
                LOGGER.info("Se ha creado un issue con el análisis: %s", issue_url)
                LOGGER.error(
                    "Revisa el issue creado en GitHub para más detalles: %s", issue_url
                )
            
            # Actualizar el estado a FAILED
            update_scan_status(TITVO_SCAN_TASK_ID, "FAILED", issue_url)
            
            # No usamos sys.exit(1) aquí para no indicar un error del script
            # Solo indicamos que el commit tiene vulnerabilidades
        else:
            LOGGER.info(
                "COMMIT APROBADO. No se detectaron vulnerabilidades de seguridad significativas."
            )
            # Actualizar el estado a COMPLETED sin crear issue
            update_scan_status(TITVO_SCAN_TASK_ID, "COMPLETED")

    except Exception as e:
        LOGGER.exception(e)
        exit_with_error(
            f"Error durante el análisis: {str(e)}", 
            TITVO_SCAN_TASK_ID
        )


if __name__ == "__main__":
    main()
