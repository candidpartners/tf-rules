provider aws {
  region = "us-east-1"
}

module "my-module" {
  source = "./sample-module"
}
