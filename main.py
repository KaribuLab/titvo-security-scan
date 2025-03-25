import os
import sys
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
MODELO = "claude-3-7-sonnet-latest"

# Inicializar el cliente de SSM
ssm = boto3.client("ssm")
secret_manager = boto3.client("secretsmanager")


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
            WithDecryption=False,
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


def get_system_prompt():
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
    github_instance, github_repo_name, github_commit_sha
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


def github_get_files_content():
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
        expression_attribute_values = {":s": status, ":u": fecha_actual}

        # Si se proporciona el resultado, incluirlo en la actualización
        if result is not None:
            update_expression += ", result = :r"
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

        log_message = (
            f"Estado del escaneo actualizado a: {status}, fecha: {fecha_actual}"
        )
        if result is not None:
            log_message += f", result: {result}"
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
        decrypted_data = unpad(
            cipher.decrypt(b64decode(data)), AES.block_size
        )
        return decrypted_data.decode("utf-8")
    except ClientError as e:
        LOGGER.exception(e)
        return None


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
    system_prompt = get_system_prompt()
    if not system_prompt:
        exit_with_error(
            "No se pudo obtener el system prompt desde Parameter Store. "
            "Este parámetro es obligatorio.",
            TITVO_SCAN_TASK_ID,
        )
    LOGGER.info("System prompt obtenido correctamente")

    # Inicializar el cliente de Anthropic
    client = Anthropic(api_key=get_anthropic_api_key())
    LOGGER.info("Enviando código para análisis")

    try:
        if item_scan.get("source") == "github":
            # Inicializar el cliente de GitHub
            github_client = Github(decrypt(item_scan.get("args").get("github_token")))
            github_repo_name = item_scan.get("args").get("github_repo_name")
            github_commit_sha = item_scan.get("args").get("github_commit_sha")
            github_assignee = item_scan.get("args").get("github_assignee")
            # Descargar archivos del repositorio
            if not github_download_repository_files(
                github_client, github_repo_name, github_commit_sha
            ):
                exit_with_error(
                    "No se pudieron descargar los archivos del repositorio.",
                    TITVO_SCAN_TASK_ID,
                )
            # Obtener el contenido de los archivos
            contenido_archivos = github_get_files_content()
            user_prompt = f"""
            A continuación te proporciono el código fuente de un commit específico 
            del repositorio {github_repo_name} (commit: {github_commit_sha}).
            
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
                system=system_prompt,
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
                issue_url = create_github_issue(
                    analisis,
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

                # Actualizar el estado a FAILED
                update_scan_status(
                    TITVO_SCAN_TASK_ID,
                    "FAILED",
                    {
                        "issue_url": issue_url,
                    },
                )

                # No usamos sys.exit(1) aquí para no indicar un error del script
                # Solo indicamos que el commit tiene vulnerabilidades
            else:
                LOGGER.info(
                    "COMMIT APROBADO. No se detectaron vulnerabilidades "
                    "de seguridad significativas."
                )
                # Actualizar el estado a COMPLETED sin crear issue
                update_scan_status(TITVO_SCAN_TASK_ID, "COMPLETED")
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
