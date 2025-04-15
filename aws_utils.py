import os
import logging
from base64 import b64decode
from datetime import datetime
import boto3
import pytz
from botocore.exceptions import ClientError
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

LOGGER = logging.getLogger(__name__)

# Inicializar los clientes de AWS
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


def get_output_format(source):
    """Obtiene el formato de salida desde Parameter Store."""
    return get_ssm_parameter(
        f"/tvo/security-scan/{os.getenv('AWS_STAGE','prod')}/github-security-scan/output/{source}"
    )


def get_task_table_name():
    """Obtiene el nombre de la tabla DynamoDB desde Parameter Store."""
    param_path = f"/tvo/security-scan/{os.getenv('AWS_STAGE','prod')}"
    param_name = f"{param_path}/task-trigger/dynamo-task-table-name"

    return get_ssm_parameter(param_name)


def get_scan_item(scan_id):
    """Obtiene el item de escaneo desde DynamoDB usando el scan_id."""
    try:
        # Obtener el nombre de la tabla
        nombre_tabla = get_task_table_name()
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
                "repositor_id": item.get("repositor_id", None),
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
    nombre_tabla = get_task_table_name()
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


def upload_html_to_s3(html_content, scan_id, source):
    """Sube un contenido HTML a S3 y devuelve la URL.

    Args:
        html_content (str): Contenido HTML a subir
        scan_id (str): ID del escaneo
        source (str): Fuente del análisis (github, bitbucket, cli)

    Returns:
        str: URL del reporte subido a S3, o None en caso de error
    """
    try:
        # Obtener el nombre del bucket y el dominio desde SSM
        report_bucket = get_ssm_parameter(
            f"/tvo/security-scan/{os.getenv('AWS_STAGE','prod')}/"
            f"github-security-scan/report-bucket-name"
        )
        bucket_domain = get_ssm_parameter(
            f"/tvo/security-scan/{os.getenv('AWS_STAGE','prod')}/"
            f"github-security-scan/report-bucket-domain"
        )

        if not report_bucket or not bucket_domain:
            LOGGER.error("No se pudo obtener el nombre del bucket o el dominio")
            return None

        # Definir la clave del archivo en S3 usando el source proporcionado
        analysis_key = f"scm/{source}/scan/{scan_id}.html"

        # Subir el archivo HTML a S3
        s3.put_object(
            Bucket=report_bucket,
            Key=analysis_key,
            Body=html_content,
            ContentType="text/html; charset=utf-8",
        )

        # Construir y devolver la URL completa del reporte
        report_url = f"{bucket_domain}/{analysis_key}"
        LOGGER.info("Reporte HTML subido a S3: %s", report_url)

        return report_url
    except Exception as e:
        LOGGER.error("Error al subir el reporte HTML a S3: %s", e)
        return None


def get_repository_table_name():
    """Obtiene el nombre de la tabla DynamoDB desde Parameter Store."""
    param_path = f"/tvo/security-scan/{os.getenv('AWS_STAGE','prod')}"
    param_name = f"{param_path}/github-security-scan/dynamo-repository-table-name"

    return get_ssm_parameter(param_name)


def get_hint_item(repositor_id):
    """Obtiene el hint de la tabla DynamoDB."""
    table_name = get_repository_table_name()
    table = boto3.resource("dynamodb").Table(table_name)
    response = table.get_item(Key={"repositor_id": repositor_id})
    return response.get("Item", {"repository_hint": None}).get("repository_hint", None)
