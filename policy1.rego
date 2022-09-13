package terraform.rules.policy11

import future.keywords.in
import input.plan as plan
import input.run as run

# Allowed Terraform resources
allowed_resources = [
	"aws_security_group",
	"aws_s3_bucket"
]


array_contains(arr, elem) {
	arr[_] = elem
}

rule[outcome] {
  resource := plan.resource_changes[_]
  action := resource.change.actions[count(resource.change.actions) - 1]
  array_contains(["create", "update"], action)  # allow destroy action

  not array_contains(allowed_resources, resource.type)

  outcome := {
       "output": sprintf(
                      "%s: resource type %q is not allowed for organization %s",
                      [resource.address, resource.type, run.organization.name]
                    )
  }
}

