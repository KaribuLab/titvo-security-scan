output "job_definition_name" {
  value = aws_batch_job_definition.batch.name
}

output "job_queue_name" {
  value = aws_batch_job_queue.batch.name
}

output "job_definition_arn" {
  value = aws_batch_job_definition.batch.arn
}

output "job_queue_arn" {
  value = aws_batch_job_queue.batch.arn
}
