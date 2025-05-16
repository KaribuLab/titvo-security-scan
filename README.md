# Analizador de Seguridad para Commits de SCM (TITVO)
[https://www.titvo.com](https://www.titvo.com)

Este proyecto contiene un sistema que analiza automáticamente commits de GitHub, Bitbucket o archivos enviados por CLI en busca de vulnerabilidades de seguridad utilizando modelos avanzados de LLM.

## Funcionalidades

- Descarga automática de archivos de commits específicos desde:
  - GitHub (usando la API de GitHub)
  - Bitbucket (usando la API REST de Bitbucket)
  - CLI (mediante archivos tar.gz almacenados en S3)
- Análisis de seguridad del código utilizando modelos de OpenAI
- Creación automática de issues en GitHub con los resultados del análisis
- Generación de reportes de código en Bitbucket con las vulnerabilidades encontradas
- Generación de reportes para archivos subidos por CLI
- Seguimiento del estado de los escaneos en DynamoDB
- Almacenamiento seguro de configuración en AWS Parameter Store y Secret Manager
- System prompt configurable a través de Parameter Store
- Nivel de logging configurable mediante variable de entorno

## Arquitectura

El proyecto sigue una arquitectura hexagonal (puertos y adaptadores) que separa la lógica de negocio de la infraestructura:

### Core (Dominio)
- Entidades y lógica de negocio independientes de infraestructura
- Puertos definidos como interfaces abstractas
- Casos de uso que orquestan la lógica del dominio

### Infraestructura
- Implementaciones concretas de los puertos definidos en el core
- Adaptadores para servicios externos (AWS, GitHub, Bitbucket)
- Servicios para almacenamiento, configuración y AI

### Aplicación
- Orquestación de casos de uso
- Gestión de tareas y flujos de trabajo
- Manejo de estado y progreso de escaneos

## Componentes Principales

### Servicios de Infraestructura
- **AWS**:
  - `DynamoConfigurationService`: Gestión de configuración usando DynamoDB
  - `S3StorageService`: Almacenamiento de archivos y reportes en S3
  - `DynamoTaskRepository`: Almacenamiento y seguimiento de tareas en DynamoDB
  - `DynamoHintRepository`: Almacenamiento de sugerencias en DynamoDB
  - `DynamoCliFilesRepository`: Gestión de archivos CLI en DynamoDB

- **Obtención de Archivos**:
  - `GithubFileFetcherService`: Descarga de archivos desde GitHub
  - `BitbucketFileFetcherService`: Descarga de archivos desde Bitbucket
  - `CliFileFetcherService`: Extracción de archivos desde tar.gz en S3

- **IA y Análisis**:
  - `OpenAIAiService`: Integración con OpenAI para análisis de seguridad

- **Servicios de Salida**:
  - `GithubOutputService`: Creación de issues en GitHub
  - `BitbucketOutputService`: Generación de reportes en Bitbucket
  - `CliOutputService`: Generación de reportes HTML para CLI

### Casos de Uso
- `ScanUseCase`: Orquestra el proceso completo de escaneo
- `TaskUseCase`: Gestión del ciclo de vida de tareas

## Estructura del Proyecto

```
src/titvo/
├── app/                    # Capa de aplicación
│   ├── cli_files/          # Entidades para archivos CLI
│   ├── scan/               # Casos de uso para escaneos
│   └── task/               # Gestión de tareas
│
├── core/                   # Dominio y lógica de negocio
│   ├── entities/           # Entidades del dominio
│   └── ports/              # Interfaces (puertos)
│
└── infraestructure/        # Implementaciones de infraestructura
    ├── ai/                 # Servicios de IA
    ├── aws/                # Servicios de AWS
    ├── file_fetchers/      # Servicios de obtención de archivos
    └── outputs/            # Servicios de salida
```

## Pruebas

El proyecto incluye pruebas unitarias e integración usando pytest y moto:

- **Pruebas Unitarias**: Validan componentes individuales con mocks
- **Pruebas de Integración**: Prueban la interacción entre componentes
- **Moto**: Simula servicios AWS (S3, DynamoDB) para pruebas sin conexión real

### Ejemplos de Pruebas
- Pruebas de repositorios DynamoDB
- Pruebas de servicios de almacenamiento S3
- Pruebas de obtención de archivos (GitHub, Bitbucket, CLI)
- Pruebas de servicios de salida

## Requerimientos

- Python 3.8 o superior
- Una clave API de OpenAI
- Acceso a AWS (DynamoDB, Parameter Store, Secret Manager, S3)
- Según el origen:
  - Token de GitHub con permisos para crear issues
  - Credenciales de Bitbucket para reportes de código
  - Acceso a S3 para archivos CLI

## Instalación

1. Clona este repositorio:
```bash
git clone https://github.com/KaribuLab/titvo-security-scan.git
cd titvo-security-scan
```

2. Instala las dependencias:
```bash
pip install -r requirements.txt
```

3. Configura las variables de entorno obligatorias en un archivo `.env`:
```bash
# Identificador único del escaneo (elige uno según el origen)
# Para CLI
TITVO_SCAN_TASK_ID=tvo-scan-xxxx-xxxx-xxxx-xxxxxxxxxxxx
# Para Bitbucket
#TITVO_SCAN_TASK_ID=tvo-scan-xxxx-xxxx-xxxx-xxxxxxxxxxxx
# Para Github
#TITVO_SCAN_TASK_ID=tvo-scan-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# Configuración de AWS
AWS_REGION=us-east-1
AWS_DEFAULT_REGION=us-east-1
AWS_ACCESS_KEY_ID=XXXXXXXXXXXXXXXXX
AWS_SECRET_ACCESS_KEY=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

# Nombres de las tablas DynamoDB y buckets S3
TITVO_DYNAMO_TASK_TABLE_NAME=tvo-security-scan-task-task-prod
TITVO_DYNAMO_CONFIGURATION_TABLE_NAME=tvo-security-scan-parameter-configuration-prod
TITVO_DYNAMO_HINT_TABLE_NAME=tvo-security-scan-account-repository-prod
TITVO_DYNAMO_CLI_FILES_TABLE_NAME=tvo-security-scan-task-cli-files-prod
TITVO_DYNAMO_CLI_FILES_BUCKET_NAME=tvo-security-scan-cli-files-prod

# Clave de cifrado
TITVO_ENCRYPTION_KEY_NAME=/tvo/security-scan/prod/aes_secret

# Nivel de log (DEBUG, INFO, WARNING, ERROR, CRITICAL)
TITVO_LOG_LEVEL=INFO

# Opcionales
#TITVO_TEMPLATE_PATH=templates
#TITVO_REPO_FILES_PATH=repo_files
#TITVO_SCAN_INFRASTRUCTURE=AWS
```

## Ejecución local usando Docker

```bash
# Crear archivo .env con las variables necesarias descritas arriba
docker build -t titvo-security-scan .
docker run -it --rm --env-file .env titvo-security-scan
```

## Despliegue

Opcionalmente se puede crear un archivo common_tags.json con las etiquetas necesarias:

```json
{
  "Project": "Titvo Security Scan",
  "Customer": "Titvo",
  "Team": "Area Creacion"
}
```

1. Crear archivo .env con las variables necesarias descritas arriba
  ```bash
  export AWS_ACCESS_KEY_ID="tu_access_key"
  export AWS_SECRET_ACCESS_KEY="tu_secret_key"
  export AWS_DEFAULT_REGION="us-east-1"
  export AWS_STAGE="prod"
  export PROJECT_NAME="titvo-security-scan" # Opcional si quiere mantener los valores por defecto. Esto se usará como prefijo para los recursos
  export PARAMETER_PATH="/titvo/security-scan" # Opcional si quiere mantener los valores por defecto. Esto se usará como prefijo para los parámetros
  export BUCKET_STATE_NAME="titvo-security-scan-terraform-state" # Opcional, si no se especifica se usará el nombre del proyecto. Por ejemplo: titvo-security-scan-terraform-state
  ```
  > [!IMPORTANT]
  > `PROJECT_NAME` y `PARAMETER_PATH`deben tener los mismos valores que se usarion en el proyecto [titvo-security-scan-infra-aws](https://github.com/KaribuLab/titvo-security-scan-infra-aws)
2. Desplegar el proyecto
  ```bash
  cd aws
  terragrunt run-all apply --auto-approve
  ```

## Formato de respuesta

El análisis de seguridad varía según el origen:

- **GitHub**: Se busca el patrón `[COMMIT_RECHAZADO]` para vulnerabilidades críticas
- **Bitbucket y CLI**: Se buscan los patrones `CRITICAL` o `HIGH` en el análisis

## Desarrollo

Para contribuir al proyecto:

1. Crea una rama para tu característica
2. Implementa los cambios siguiendo la arquitectura hexagonal
3. Añade pruebas unitarias y de integración
4. Envía un pull request

## Licencia

Este proyecto está licenciado bajo la [Licencia Apache 2.0](LICENSE).
