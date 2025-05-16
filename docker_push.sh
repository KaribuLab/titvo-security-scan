#!/bin/bash
cwd=$(pwd)
cd $cwd/aws/ecr
ecr_repository_url=$(terragrunt output -raw ecr_repository_url)
echo $ecr_repository_url
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin $ecr_repository_url
cd $cwd
docker build -t $ecr_repository_url .
docker push $ecr_repository_url
