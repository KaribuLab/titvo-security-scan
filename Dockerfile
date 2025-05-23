FROM python:3.12.8-alpine3.21

WORKDIR /app

# Copiar archivos del proyecto
COPY requirements.txt /app

# Crear usuario no privilegiado para seguridad
RUN adduser -D -u 1000 titvo

# Asignar permisos al usuario
RUN chown -R titvo:titvo /app

# Instalar dependencias
RUN pip install -r requirements.txt

COPY ./src/titvo /app/titvo
COPY ./src/container_runner.py /app/container_runner.py
# Cambiar al usuario no privilegiado
USER titvo

# Comando para ejecutar el script
CMD ["python", "/app/container_runner.py"]