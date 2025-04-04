import os
import tarfile
import logging
import boto3

LOGGER = logging.getLogger(__name__)


def get_files_table_name(get_ssm_parameter):
    """Obtiene el nombre de la tabla DynamoDB desde Parameter Store."""
    param_path = f"/tvo/security-scan/{os.getenv('AWS_STAGE','prod')}"
    param_name = f"{param_path}/github-security-scan/dynamo-client-file-table-name"

    return get_ssm_parameter(param_name)


def get_files_bucket_name(get_ssm_parameter):
    """Obtiene el nombre del bucket de S3 desde Parameter Store."""
    param_path = f"/tvo/security-scan/{os.getenv('AWS_STAGE','prod')}"
    param_name = f"{param_path}/github-security-scan/s3-client-file-bucket-name"

    return get_ssm_parameter(param_name)


def file_download(file_key, bucket_name, s3_client):
    """Descarga un archivo gzip desde S3 y extrae su contenido en el directorio repo_files.

    Maneja archivos tar.gz que contienen múltiples archivos.
    """
    try:
        # Crear directorio repo_files si no existe
        os.makedirs("repo_files", exist_ok=True)

        # Nombre temporal para el archivo comprimido
        temp_gz_file = os.path.join("repo_files", os.path.basename(file_key))

        LOGGER.info("Descargando archivo %s desde S3", file_key)

        # Descargar el archivo comprimido desde S3
        file_gz = s3_client.get_object(Bucket=bucket_name, Key=file_key)

        # Guardar el archivo comprimido temporalmente
        with open(temp_gz_file, "wb") as f:
            f.write(file_gz["Body"].read())

        LOGGER.info("Descomprimiendo archivo %s", temp_gz_file)

        # Es un tarball, extraer múltiples archivos
        with tarfile.open(temp_gz_file, "r:gz") as tar:
            # Extraer todos los archivos en repo_files
            tar.extractall(path="repo_files")
            # Obtener la lista de archivos extraídos
            extracted_files = [member.name for member in tar.getmembers()]
            LOGGER.info("Extraídos %d archivos del tarball", len(extracted_files))

        # Eliminar el archivo comprimido temporal
        os.remove(temp_gz_file)

        for file in extracted_files:
            LOGGER.info("Archivo extraído: %s", file)

        LOGGER.info("Extracción completada en directorio repo_files")
        return extracted_files
    except Exception as e:
        LOGGER.error("Error al descargar y extraer el archivo desde S3:")
        LOGGER.exception(e)
        return None


def get_files_by_batch_id(batch_id, get_ssm_parameter):
    """Obtiene los archivos de un batch desde DynamoDB."""
    try:
        # Obtener el nombre de la tabla
        table_name = get_files_table_name(get_ssm_parameter)
        if not table_name:
            LOGGER.error("No se pudo obtener el nombre de la tabla DynamoDB")
            return None

        # Inicializar el cliente de DynamoDB
        dynamodb = boto3.resource("dynamodb")
        table = dynamodb.Table(table_name)

        # Crear la consulta equivalente al código Node.js
        response = table.query(
            IndexName="batch_id_gsi",
            KeyConditionExpression="batch_id = :batch_id",
            ExpressionAttributeValues={":batch_id": batch_id},
        )
        items = response.get("Items", [])
        files = []
        for item in items:
            file = {
                "file_id": item.get("file_id"),
                "batch_id": item.get("batch_id"),
                "file_key": item.get("file_key"),
                "ttl": item.get("ttl"),
            }
            files.append(file)
        return files
    except Exception as e:
        LOGGER.error("Error al obtener los archivos de un batch desde DynamoDB:")
        LOGGER.exception(e)
        return None


def is_commit_safe(analysis):
    """Determina si el commit es seguro basado en el análisis de CLI."""
    # Implementación específica para CLI
    # En este caso, usamos la misma lógica general
    if "CRITICAL" in analysis or "HIGH" in analysis:
        return False
    return True
