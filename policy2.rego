package terraform.rules.policy22

# Check S3 bucket is not public

import input.plan as plan

rule[outcome] {
	r = plan.resource_changes[_]
	r.mode == "managed"
	r.type == "random_id"
	r.change.after.byte_length > 0

    outcome := {
           "output": sprintf("%s cannot have byte_length",
                      	                    [r.type])
          }
}