# Analizador de Seguridad para Commits de GitHub

Este proyecto contiene un script que analiza automáticamente commits de GitHub en busca de vulnerabilidades de seguridad utilizando Claude 3.7 Sonnet de Anthropic.

## Funcionalidades

- Descarga automática de archivos de un commit específico de GitHub
- Análisis de seguridad del código utilizando Claude 3.7 Sonnet
- Creación automática de issues en GitHub con los resultados del análisis
- Detección de patrones específicos para aprobar o rechazar commits
- Asignación automática de issues a un usuario específico
- Seguimiento del estado de los escaneos en DynamoDB
- Obtención de configuración desde AWS Parameter Store
- System prompt configurable a través de Parameter Store

## Requisitos

- Python 3.8 o superior
- Una clave API de Anthropic
- Un token de GitHub con permisos para crear issues
- Acceso al repositorio que se desea analizar

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
   ANTHROPIC_API_KEY=tu_clave_api_de_anthropic
   GITHUB_TOKEN=tu_token_de_github
   GITHUB_REPO_NAME=usuario/nombre-repositorio
   GITHUB_COMMIT_SHA=hash_del_commit
   GITHUB_ASSIGNEE=usuario_para_asignar_issues
   TITVO_SCAN_TASK_ID=identificador_unico_del_escaneo
   ```

> [!IMPORTANT]
> GITHUB_ASSIGNEE debe ser un usuario de GitHub válido. Se debe obtener con el API de GitHub [https://stackoverflow.com/questions/74252630/get-the-login-of-a-user-that-issued-a-comment-on-github-actions](https://stackoverflow.com/questions/74252630/get-the-login-of-a-user-that-issued-a-comment-on-github-actions).

## Uso del script

El script `main.py` analiza un commit específico de GitHub y crea un issue con los resultados.

### Cómo usar el script

1. Configura las variables de entorno en el archivo `.env` como se indicó anteriormente
2. Ejecuta el script:
```bash
python main.py
```

El script realizará las siguientes acciones:
1. Obtendrá el item de escaneo desde DynamoDB y actualizará su estado a `IN_PROGRESS`
2. Descargará los archivos del commit especificado
3. Enviará el código a Claude para su análisis
4. Si se detectan vulnerabilidades:
   - Creará un issue en GitHub con los resultados
   - Asignará el issue al usuario especificado en `GITHUB_ASSIGNEE`
   - Actualizará el estado a `FAILED` y guardará la URL del issue en DynamoDB
5. Si no se detectan vulnerabilidades:
   - Actualizará el estado a `COMPLETED` en DynamoDB
6. Si ocurre algún error durante el proceso:
   - Actualizará el estado a `ERROR` en DynamoDB
   - Terminará con código de salida 1

### Variables de entorno

- `ANTHROPIC_API_KEY`: Tu clave API de Anthropic
- `GITHUB_TOKEN`: Token de acceso personal de GitHub con permisos para crear issues
- `GITHUB_REPO_NAME`: Nombre del repositorio en formato "usuario/repositorio"
- `GITHUB_COMMIT_SHA`: Hash del commit que se desea analizar
- `GITHUB_ASSIGNEE`: Usuario de GitHub al que se asignarán los issues
- `TITVO_SCAN_TASK_ID`: Identificador único para el trabajo de escaneo actual
- `AWS_REGION`: Región de AWS donde se encuentra la tabla DynamoDB y Parameter Store

### Integración con DynamoDB

El script utiliza una tabla DynamoDB existente para almacenar y actualizar el estado de los escaneos:

1. Al iniciar el análisis, se obtiene el item correspondiente al `TITVO_SCAN_TASK_ID` desde DynamoDB
2. Se actualiza el estado a `IN_PROGRESS` y el campo `updated_at` a la fecha actual
3. Se actualiza el estado final según el resultado del análisis:
   - `COMPLETED`: Si no se detectan vulnerabilidades significativas (se elimina el campo `issue_url` si existía)
   - `FAILED`: Si se detectan vulnerabilidades (en este caso también se crea un issue en GitHub y se guarda su URL)
   - `ERROR`: Si ocurre algún error durante el proceso
4. En todos los casos se actualiza el campo `updated_at` con la fecha actual

El nombre de la tabla de DynamoDB se obtiene desde AWS Parameter Store con la clave `/tvo/security-scan/prod/task-trigger/dynamo-task-table-name`.

### Integración con Parameter Store

El script utiliza AWS Parameter Store para obtener configuración dinámica:

1. El nombre de la tabla DynamoDB se obtiene desde el parámetro `/tvo/security-scan/prod/task-trigger/dynamo-task-table-name`
2. El system prompt para Claude se obtiene desde el parámetro `/tvo/security-scan/prod/github-security-scan/system-prompt` (OBLIGATORIO)

Esto permite modificar el comportamiento del analizador sin necesidad de cambiar el código, facilitando:
- Ajustes en las instrucciones para Claude
- Cambios en el formato de respuesta esperado
- Actualización de criterios de análisis de seguridad

> [!IMPORTANT]
> El parámetro del system prompt es obligatorio para el funcionamiento del script. Si no se puede obtener, el script fallará con un error.

### Personalización

El script utiliza dos prompts principales:

- `system_prompt`: Define las instrucciones y comportamiento para Claude (obtenido desde Parameter Store)
- `user_prompt`: Define la consulta específica que se envía a Claude con el código a analizar

## Formato de respuesta

El análisis de Claude siempre comenzará con uno de estos patrones:
- `[COMMIT_RECHAZADO]` - Si se encuentran vulnerabilidades de severidad media, alta o crítica
- `[COMMIT_APROBADO]` - Si no se encuentran vulnerabilidades o solo se encuentran de severidad baja