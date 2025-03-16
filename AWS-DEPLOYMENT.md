# Despliegue en AWS

Este documento describe cómo se despliega el Analizador de Seguridad para Commits de GitHub en AWS utilizando Terragrunt y GitHub Actions.

## Arquitectura

El sistema se despliega con los siguientes componentes de AWS:

- **ECR (Elastic Container Registry)**: Almacena la imagen Docker del analizador
- **IAM Roles y Políticas**: Proporciona los permisos necesarios
- **DynamoDB**: Almacena los datos del análisis

## Requisitos previos

Para desplegar esta solución, necesitas:

1. Una cuenta de AWS con permisos adecuados
2. Configuración de Terragrunt en el directorio `terraform/`
3. Secretos configurados en GitHub:
   - `AWS_ACCESS_KEY_ID`: ID de clave de acceso de AWS
   - `AWS_SECRET_ACCESS_KEY`: Clave de acceso secreta de AWS
   - `AWS_REGION`: Región de AWS donde se desplegará la infraestructura

## Estructura de Terragrunt

La configuración de Terragrunt debe incluir:

1. Definición del repositorio ECR
2. Roles y políticas de IAM necesarios
3. Outputs que incluyan la URL del repositorio ECR

Ejemplo de output en Terragrunt:

```hcl
output "ecr_repository_url" {
  description = "URL del repositorio ECR"
  value       = module.ecr.repository_url
}
```

## Flujo de despliegue

El flujo de despliegue es el siguiente:

1. Se hace push a la rama principal o se activa manualmente el workflow
2. GitHub Actions ejecuta el workflow `.github/workflows/deploy-to-aws.yml`
3. Se instala Terraform y Terragrunt
4. Se ejecuta `terragrunt run-all init` y `terragrunt run-all apply` en modo no interactivo, utilizando las credenciales de AWS proporcionadas como variables de entorno
5. Se obtiene la URL del repositorio ECR desde los outputs de Terragrunt
6. Se construye la imagen Docker y se hace push al ECR

## Seguridad

Para mejorar la seguridad de este despliegue, considera:

1. Usar credenciales de AWS con el mínimo de permisos necesarios
2. Rotar regularmente las claves de acceso de AWS
3. Configurar políticas de IAM restrictivas para el repositorio ECR
4. Implementar escaneo de vulnerabilidades en las imágenes de Docker
5. Considerar el uso de OIDC para autenticación sin credenciales a largo plazo

## Monitoreo

Puedes configurar monitoreo para:

1. Actividad en el repositorio ECR
2. Ejecuciones del workflow de GitHub Actions

## Solución de problemas

Si encuentras problemas durante el despliegue:

1. Verifica los logs de GitHub Actions para identificar en qué paso falló
2. Comprueba que las credenciales de AWS tengan los permisos necesarios
3. Verifica que los secretos estén correctamente configurados en GitHub
4. Asegúrate de que la configuración de Terragrunt sea correcta y tenga los outputs necesarios

## Notas adicionales

2. La tabla DynamoDB debe existir con:
   - Clave primaria: `scan_id` (String)
   - Un campo `status` que puede tener los valores: `PENDING`, `IN_PROGRESS`, `COMPLETED`, `FAILED`, `ERROR`
   - Un campo `updated_at` que almacena la fecha de la última actualización en formato ISO (ej: "2025-03-16T06:44:14.075Z")

# Integración con AWS

Este documento describe cómo el Analizador de Seguridad para Commits de GitHub se integra con AWS.

## Arquitectura

El sistema utiliza los siguientes componentes de AWS:

- **DynamoDB**: Almacena el estado de los escaneos de seguridad
- **Parameter Store**: Almacena la configuración, como el nombre de la tabla DynamoDB

## Requisitos previos

Para ejecutar esta solución, necesitas:

1. Acceso a AWS con permisos para:
   - Leer parámetros de Parameter Store
   - Leer y escribir en la tabla DynamoDB

2. La tabla DynamoDB debe existir con:
   - Clave primaria: `scan_id` (String)
   - Un campo `status` que puede tener los valores: `PENDING`, `IN_PROGRESS`, `COMPLETED`, `FAILED`, `ERROR`
   - Un campo `updated_at` que almacena la fecha de la última actualización en formato ISO (ej: "2025-03-16T06:44:14.075Z")

3. Un parámetro en Parameter Store:
   - Nombre: `/tvo/security-scan/prod/task-trigger/dynamo-task-table-name`
   - Valor: Nombre de la tabla DynamoDB existente

## Flujo de ejecución

El flujo de ejecución del script es el siguiente:

1. El script obtiene el nombre de la tabla DynamoDB desde Parameter Store
2. Busca el item con el `scan_id` correspondiente al `TITVO_SCAN_TASK_ID` proporcionado
3. Actualiza el estado del item a `IN_PROGRESS` y el campo `updated_at` a la fecha actual
4. Realiza el análisis de seguridad del commit
5. Actualiza el estado final según el resultado y el campo `updated_at` a la fecha actual:
   - `COMPLETED`: Si no se detectan vulnerabilidades significativas
   - `FAILED`: Si se detectan vulnerabilidades
   - `ERROR`: Si ocurre algún error durante el proceso 