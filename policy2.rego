package terraform.rules.policy_22

# Check S3 bucket is not public

import input.plan as plan

# METADATA
# title: policy-22
# description: random id is of specific length.
# custom:
#  enforcement_level: mandatory
rule[outcome] {
	r = plan.resource_changes[_]
	r.mode == "managed"
	r.type == "random_id"
	r.change.after.byte_length > 0
    meta := rego.metadata.chain()

    outcome := {
           "policy_name": rego.metadata.rule().title,
           "description": rego.metadata.rule().description,
           "enforcement_level": rego.metadata.rule().custom.enforcement_level,
           "output": sprintf("%s cannot have byte_length",
                      	                    [r.type])
          }
}