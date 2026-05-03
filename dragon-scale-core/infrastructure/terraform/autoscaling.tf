# ECS Auto-Scaling for DRAGON_SCALE services
#
# Scales api-gateway, ai-engine, and drl-engine based on CPU utilisation.
# Target tracking policies scale out at 60% CPU and scale in at 40% CPU.

# ── api-gateway ───────────────────────────────────────────────────────────────

resource "aws_appautoscaling_target" "api_gateway" {
  max_capacity       = 10
  min_capacity       = 2
  resource_id        = "service/${aws_ecs_cluster.dragon-scale.name}/${var.environment}-dragon-scale-api-gateway"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"

  depends_on = [aws_ecs_service.services]
}

resource "aws_appautoscaling_policy" "api_gateway_cpu" {
  name               = "${var.environment}-dragon-scale-api-gateway-cpu-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.api_gateway.resource_id
  scalable_dimension = aws_appautoscaling_target.api_gateway.scalable_dimension
  service_namespace  = aws_appautoscaling_target.api_gateway.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = 60.0
    scale_in_cooldown  = 120
    scale_out_cooldown = 60
  }
}

resource "aws_appautoscaling_policy" "api_gateway_memory" {
  name               = "${var.environment}-dragon-scale-api-gateway-memory-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.api_gateway.resource_id
  scalable_dimension = aws_appautoscaling_target.api_gateway.scalable_dimension
  service_namespace  = aws_appautoscaling_target.api_gateway.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageMemoryUtilization"
    }
    target_value       = 75.0
    scale_in_cooldown  = 120
    scale_out_cooldown = 60
  }
}

# ── ai-engine ─────────────────────────────────────────────────────────────────

resource "aws_appautoscaling_target" "ai_engine" {
  max_capacity       = 6
  min_capacity       = 1
  resource_id        = "service/${aws_ecs_cluster.dragon-scale.name}/${aws_ecs_service.ai_engine.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"

  depends_on = [aws_ecs_service.ai_engine]
}

resource "aws_appautoscaling_policy" "ai_engine_cpu" {
  name               = "${var.environment}-dragon-scale-ai-engine-cpu-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ai_engine.resource_id
  scalable_dimension = aws_appautoscaling_target.ai_engine.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ai_engine.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = 70.0
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}

# ── drl-engine ────────────────────────────────────────────────────────────────

resource "aws_appautoscaling_target" "drl_engine" {
  max_capacity       = 4
  min_capacity       = 1
  resource_id        = "service/${aws_ecs_cluster.dragon-scale.name}/${var.environment}-dragon-scale-drl-engine"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"

  depends_on = [aws_ecs_service.services]
}

resource "aws_appautoscaling_policy" "drl_engine_cpu" {
  name               = "${var.environment}-dragon-scale-drl-engine-cpu-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.drl_engine.resource_id
  scalable_dimension = aws_appautoscaling_target.drl_engine.scalable_dimension
  service_namespace  = aws_appautoscaling_target.drl_engine.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = 65.0
    scale_in_cooldown  = 180
    scale_out_cooldown = 60
  }
}
