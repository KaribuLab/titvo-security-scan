# Despliegue en AWS

Este documento describe cómo se despliega el Analizador de Seguridad para Commits de GitHub en AWS utilizando Terragrunt y GitHub Actions.

## Arquitectura

El sistema se despliega con los siguientes componentes de AWS:

- **ECR (Elastic Container Registry)**: Almacena la imagen Docker del analizador
- **IAM Roles y Políticas**: Proporciona los permisos necesarios

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