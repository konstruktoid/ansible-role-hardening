workflow "New workflow" {
  on = "push"
  resolves = ["Konstruktoid YAML lint"]
}

action "Konstruktoid YAML lint" {
  uses = "./action-lint"
}
