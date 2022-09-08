package terraform.rules.policy_11

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

# METADATA
# title: policy-11
# description: Ensure only a certain resource type is allowed.
# custom:
#  enforcement_level: mandatory
rule[outcome] {
  resource := plan.resource_changes[_]
  action := resource.change.actions[count(resource.change.actions) - 1]
  array_contains(["create", "update"], action)  # allow destroy action

  not array_contains(allowed_resources, resource.type)

  meta := rego.metadata.chain()
  outcome := {
       "policy_name": rego.metadata.rule().title,
       "description": rego.metadata.rule().description,
       "enforcement_level": rego.metadata.rule().custom.enforcement_level,
       "output": sprintf(
                      "%s: resource type %q is not allowed for organization %s",
                      [resource.address, resource.type, run.organization.name]
                    )
  }
}

