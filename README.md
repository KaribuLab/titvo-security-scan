# Analizador de Seguridad para Commits de GitHub

Este proyecto contiene un script que analiza automáticamente commits de GitHub en busca de vulnerabilidades de seguridad utilizando Claude 3.7 Sonnet de Anthropic.

## Funcionalidades

- Descarga automática de archivos de un commit específico de GitHub
- Análisis de seguridad del código utilizando Claude 3.7 Sonnet
- Creación automática de issues en GitHub con los resultados del análisis
- Detección de patrones específicos para aprobar o rechazar commits
- Asignación automática de issues a un usuario específico

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
   TITVO_SCAN_JOB_ID=identificador_unico_del_escaneo
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
1. Descargará los archivos del commit especificado
2. Enviará el código a Claude para su análisis
3. Creará un issue en GitHub con los resultados
4. Asignará el issue al usuario especificado en `GITHUB_ASSIGNEE`
5. Terminará con código de salida 1 si se detectan vulnerabilidades graves

### Variables de entorno

- `ANTHROPIC_API_KEY`: Tu clave API de Anthropic
- `GITHUB_TOKEN`: Token de acceso personal de GitHub con permisos para crear issues
- `GITHUB_REPO_NAME`: Nombre del repositorio en formato "usuario/repositorio"
- `GITHUB_COMMIT_SHA`: Hash del commit que se desea analizar
- `GITHUB_ASSIGNEE`: Usuario de GitHub al que se asignarán los issues
- `TITVO_SCAN_JOB_ID`: Identificador único para el trabajo de escaneo actual

### Personalización

El script utiliza dos prompts principales que puedes modificar en el código:

- `SYSTEM_PROMPT`: Define las instrucciones y comportamiento para Claude
- `user_prompt`: Define la consulta específica que se envía a Claude con el código a analizar

## Integración con CI/CD

Este script puede integrarse en flujos de trabajo de CI/CD para analizar automáticamente los commits antes de permitir su fusión en ramas principales.

Ejemplo de uso en GitHub Actions:
```yaml
name: Security Analysis
on: [pull_request]
jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - name: Install dependencies
        run: pip install -r requirements.txt
      - name: Run security analysis
        run: python main.py
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITHUB_REPO_NAME: ${{ github.repository }}
          GITHUB_COMMIT_SHA: ${{ github.event.pull_request.head.sha }}
          GITHUB_ASSIGNEE: ${{ github.event.pull_request.user.login }}
          TITVO_SCAN_JOB_ID: ${{ github.run_id }}-${{ github.run_number }}
```

## Formato de respuesta

El análisis de Claude siempre comenzará con uno de estos patrones:
- `[COMMIT_RECHAZADO]` - Si se encuentran vulnerabilidades de severidad media, alta o crítica
- `[COMMIT_APROBADO]` - Si no se encuentran vulnerabilidades o solo se encuentran de severidad baja 