# Analizador de Seguridad para Commits de SCM

Este proyecto contiene un conjunto de scripts que analizan automáticamente commits de GitHub, Bitbucket o CLI en busca de vulnerabilidades de seguridad utilizando Claude 3.7 Sonnet de Anthropic.

## Funcionalidades

- Descarga automática de archivos de commits específicos desde:
  - GitHub
  - Bitbucket
  - CLI (mediante archivos tar.gz en S3)
- Análisis de seguridad del código utilizando Claude 3.7 Sonnet
- Creación automática de issues en GitHub con los resultados del análisis
- Generación de reportes de código en Bitbucket con las vulnerabilidades encontradas
- Detección de patrones específicos para aprobar o rechazar commits
- Seguimiento del estado de los escaneos en DynamoDB
- Obtención de configuración desde AWS Parameter Store y Secret Manager
- System prompt configurable a través de Parameter Store

## Organización del Código

El proyecto está organizado de forma modular:

- `main.py`: Coordina el flujo de trabajo general y delega en los módulos específicos
- `github_handler.py`: Contiene toda la lógica para interactuar con GitHub
- `bitbucket_handler.py`: Contiene toda la lógica para interactuar con Bitbucket
- `cli_handler.py`: Maneja las operaciones relacionadas con escaneos desde CLI
- `utils.py`: Proporciona funciones comunes como análisis de código y generación de prompts
- `aws_utils.py`: Contiene toda la lógica de interacción con servicios AWS

## Requisitos

- Python 3.8 o superior
- Una clave API de Anthropic
- Acceso a AWS (DynamoDB, Parameter Store y Secret Manager)
- Dependiendo del origen:
  - Un token de GitHub con permisos para crear issues
  - Credenciales de Bitbucket para crear reportes de código
  - Acceso a S3 para archivos CLI

## Instalación

1. Clona este repositorio:
```bash
git clone https://github.com/tu-usuario/github-security-scan.git
cd github-security-scan
```

2. Instala las dependencias:
```bash
pip install -r requirements.txt
```

3. Configura las variables de entorno:
   - Crea un archivo `.env` con las siguientes variables:
   ```
   TITVO_SCAN_TASK_ID=identificador_unico_del_escaneo
   AWS_STAGE=prod  # o 'dev' para entorno de desarrollo
   ```

## Uso del script

El script `main.py` analiza un commit específico de GitHub, Bitbucket o CLI y gestiona los resultados según el origen.

### Cómo usar el script

1. Configura las variables de entorno en el archivo `.env`
2. Ejecuta el script:
```bash
python main.py
```

El script realizará las siguientes acciones:
1. Obtendrá el item de escaneo desde DynamoDB y actualizará su estado a `IN_PROGRESS`
2. Detectará la fuente del escaneo (GitHub, Bitbucket o CLI)
3. Descargará los archivos según el origen:
   - En GitHub: Desde el commit especificado
   - En Bitbucket: A partir del diff del commit
   - En CLI: Desde archivos tar.gz en S3
4. Enviará el código a Claude para su análisis
5. Según el origen y el resultado:
   - GitHub: Creará un issue si hay vulnerabilidades
   - Bitbucket: Generará un reporte de código insights con las vulnerabilidades
   - CLI: Generará un reporte HTML y lo subirá a S3
6. Actualizará el estado en DynamoDB según el resultado

### Integración con AWS

#### DynamoDB

El script utiliza DynamoDB para almacenar y actualizar el estado de los escaneos:

- Tabla principal: Almacena los trabajos de escaneo y sus estados
- Tabla de archivos CLI: Almacena metadatos de archivos enviados desde CLI

#### Parameter Store

El script obtiene configuración dinámica desde Parameter Store:

- System prompt para Claude
- Formatos de salida específicos para cada origen
- Nombres de tablas DynamoDB
- Nombres y dominios de buckets S3

#### Secret Manager

Se utilizan secretos de AWS Secret Manager para:

- Credenciales de Bitbucket
- Claves de cifrado para tokens

#### S3

Se utiliza S3 para:

- Almacenar los archivos enviados desde CLI
- Guardar los reportes HTML generados

## Personalización

El script utiliza dos prompts principales:

- `system_prompt`: Define las instrucciones y comportamiento para Claude (obtenido desde Parameter Store)
- `user_prompt`: Define la consulta específica con el código a analizar

Ambos prompts pueden personalizarse a través de Parameter Store.

## Formato de respuesta

El análisis de seguridad se procesa según el origen:

- GitHub: Se busca el patrón `[COMMIT_RECHAZADO]` para determinar si hay vulnerabilidades críticas
- Bitbucket y CLI: Se buscan los patrones `CRITICAL` o `HIGH` en el análisis

## Configuración avanzada

El proyecto permite una gran flexibilidad a través de la configuración en Parameter Store:

- `/tvo/security-scan/{stage}/github-security-scan/system-prompt`: Instrucciones para Claude
- `/tvo/security-scan/{stage}/github-security-scan/output/{source}`: Formato de salida esperado según origen
- `/tvo/security-scan/{stage}/task-trigger/dynamo-task-table-name`: Nombre de la tabla principal
- `/tvo/security-scan/{stage}/github-security-scan/dynamo-client-file-table-name`: Nombre de la tabla de archivos CLI
- `/tvo/security-scan/{stage}/github-security-scan/s3-client-file-bucket-name`: Bucket para archivos CLI
- `/tvo/security-scan/{stage}/github-security-scan/report-bucket-name`: Bucket para reportes
- `/tvo/security-scan/{stage}/github-security-scan/report-bucket-domain`: Dominio para acceder a los reportes

Donde `{stage}` puede ser `prod` o `dev`, según el entorno.

## Ejecución local usando Docker

Crea un archivo `.env` con las variables de entorno necesarias:

```bash
TITVO_SCAN_TASK_ID=tvo-scan-1234567890 # Necesario para obtener el item de escaneo desde DynamoDB
AWS_REGION=us-east-1
AWS_DEFAULT_REGION=us-east-1
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
#LOG_LEVEL=DEBUG
```

```bash
docker build -t deleteme .
docker run -it --rm --env-file .env deleteme
```
