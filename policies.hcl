policy "policyVCS" {
  query = "data.terraform.main.main"
  enforcement_level = "mandatory"
}

policy "policyVCS" {
  query = "data.terraform.main"
  enforcement_level = "mandatory"
}
