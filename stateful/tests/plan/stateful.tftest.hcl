mock_provider "aws" {}

# Run 1: populated stateful rule group with rule_variables, stateful_rules,
# domain targets and rule_order all present.
run "stateful_populated" {
  command = plan

  variables {
    name        = "example-stateful"
    description = "example standard stateful rule"
    capacity    = 100

    rule_variables = {
      ipSets = {
        variable1 = {
          key    = "WEB_HOST"
          values = ["127.0.0.1/32"]
        }
        variable2 = {
          key    = "EC2_HOSTS"
          values = ["127.0.0.3/32"]
        }
      }
      portSets = {
        variable1 = {
          key    = "HTTP_PORTS"
          values = ["8443"]
        }
      }
    }

    stateful_rules = {
      rule1 = {
        sid             = 12345
        action          = "pass"
        source          = "127.0.0.1/32"
        sourcePort      = "443"
        destination     = "127.0.0.2/32"
        destinationPort = "443"
        protocol        = "tcp"
        direction       = "ANY"
        ruleOptions     = {}
      }
      rule2 = {
        sid             = 12346
        action          = "pass"
        source          = "127.0.0.1/32"
        sourcePort      = "8443"
        destination     = "127.0.0.2/32"
        destinationPort = "8443"
        protocol        = "tcp"
        direction       = "ANY"
        ruleOptions = {
          option1 = {
            keyword  = "msg"
            settings = ["\"this is a stateful pass rule\""]
          }
          option2 = {
            keyword = "noalert"
          }
        }
      }
    }

    domain_rule_type    = "ALLOWLIST"
    domain_target_type  = ["HTTP_HOST", "TLS_SNI"]
    domain_targets      = ["example.com", "contoso.org"]
    stateful_rule_order = "STRICT_ORDER"

    tags = {
      Environment = "test"
      Team        = "core-cloud"
    }
  }

  # Top-level deterministic attributes.
  assert {
    condition     = aws_networkfirewall_rule_group.this.name == "example-stateful"
    error_message = "name should equal var.name"
  }

  assert {
    condition     = aws_networkfirewall_rule_group.this.description == "example standard stateful rule"
    error_message = "description should equal var.description"
  }

  assert {
    condition     = aws_networkfirewall_rule_group.this.capacity == 100
    error_message = "capacity should equal var.capacity"
  }

  assert {
    condition     = aws_networkfirewall_rule_group.this.type == "STATEFUL"
    error_message = "type should be STATEFUL"
  }

  assert {
    condition     = aws_networkfirewall_rule_group.this.tags["Environment"] == "test"
    error_message = "tags should propagate from var.tags"
  }

  assert {
    condition     = aws_networkfirewall_rule_group.this.tags["Team"] == "core-cloud"
    error_message = "tags should propagate from var.tags"
  }

  # rule_variables dynamic block present with the ip_sets / port_sets built from input.
  assert {
    condition     = length(aws_networkfirewall_rule_group.this.rule_group[0].rule_variables) == 1
    error_message = "rule_variables block should be present when rule_variables var is non-empty"
  }

  assert {
    condition     = length(aws_networkfirewall_rule_group.this.rule_group[0].rule_variables[0].ip_sets) == 2
    error_message = "two ip_sets should be built from rule_variables.ipSets"
  }

  assert {
    condition     = length(aws_networkfirewall_rule_group.this.rule_group[0].rule_variables[0].port_sets) == 1
    error_message = "one port_set should be built from rule_variables.portSets"
  }

  # stateful_rule dynamic blocks built from stateful_rules input.
  assert {
    condition     = length(aws_networkfirewall_rule_group.this.rule_group[0].rules_source[0].stateful_rule) == 2
    error_message = "two stateful_rule blocks should be built from stateful_rules"
  }

  # action is upper-cased by the module.
  assert {
    condition = alltrue([
      for r in aws_networkfirewall_rule_group.this.rule_group[0].rules_source[0].stateful_rule : r.action == "PASS"
    ])
    error_message = "stateful_rule action should be upper-cased"
  }

  # protocol is upper-cased inside the header.
  assert {
    condition = alltrue([
      for r in aws_networkfirewall_rule_group.this.rule_group[0].rules_source[0].stateful_rule : r.header[0].protocol == "TCP"
    ])
    error_message = "stateful_rule header protocol should be upper-cased"
  }

  # domain rules_source_list present when domain_targets non-empty.
  assert {
    condition     = length(aws_networkfirewall_rule_group.this.rule_group[0].rules_source[0].rules_source_list) == 1
    error_message = "rules_source_list should be present when domain_targets is non-empty"
  }

  assert {
    condition     = aws_networkfirewall_rule_group.this.rule_group[0].rules_source[0].rules_source_list[0].generated_rules_type == "ALLOWLIST"
    error_message = "generated_rules_type should equal domain_rule_type"
  }

  assert {
    condition     = length(aws_networkfirewall_rule_group.this.rule_group[0].rules_source[0].rules_source_list[0].targets) == 2
    error_message = "domain targets should propagate to rules_source_list"
  }

  # stateful_rule_options present with rule_order upper-cased when stateful_rule_order set.
  assert {
    condition     = length(aws_networkfirewall_rule_group.this.rule_group[0].stateful_rule_options) == 1
    error_message = "stateful_rule_options should be present when stateful_rule_order is set"
  }

  assert {
    condition     = aws_networkfirewall_rule_group.this.rule_group[0].stateful_rule_options[0].rule_order == "STRICT_ORDER"
    error_message = "rule_order should equal upper(var.stateful_rule_order)"
  }
}

# Run 2: minimal rule group with all optional dynamic-block vars empty/toggled off.
run "stateful_minimal_optionals_off" {
  command = plan

  variables {
    name        = "minimal-stateful"
    description = "minimal stateful rule group"
    capacity    = 10

    stateful_rules = {
      only = {
        action          = "drop"
        source          = "10.0.0.1/32"
        sourcePort      = "80"
        destination     = "10.0.0.2/32"
        destinationPort = "80"
        protocol        = "tcp"
        direction       = "FORWARD"
        ruleOptions     = {}
      }
    }

    # optional dynamic-block vars left at defaults (empty)
    rule_variables      = {}
    domain_targets      = []
    stateful_rule_order = ""
    tags                = {}
  }

  assert {
    condition     = aws_networkfirewall_rule_group.this.name == "minimal-stateful"
    error_message = "name should equal var.name"
  }

  assert {
    condition     = aws_networkfirewall_rule_group.this.type == "STATEFUL"
    error_message = "type should be STATEFUL"
  }

  assert {
    condition     = aws_networkfirewall_rule_group.this.capacity == 10
    error_message = "capacity should equal var.capacity"
  }

  # optional blocks absent when their vars are empty
  assert {
    condition     = length(aws_networkfirewall_rule_group.this.rule_group[0].rule_variables) == 0
    error_message = "rule_variables block should be absent when rule_variables var is empty"
  }

  assert {
    condition     = length(aws_networkfirewall_rule_group.this.rule_group[0].rules_source[0].rules_source_list) == 0
    error_message = "rules_source_list should be absent when domain_targets is empty"
  }

  assert {
    condition     = length(aws_networkfirewall_rule_group.this.rule_group[0].stateful_rule_options) == 0
    error_message = "stateful_rule_options should be absent when stateful_rule_order is empty"
  }

  # single stateful_rule still built from input
  assert {
    condition     = length(aws_networkfirewall_rule_group.this.rule_group[0].rules_source[0].stateful_rule) == 1
    error_message = "one stateful_rule block should be built from stateful_rules"
  }

  assert {
    condition     = length(aws_networkfirewall_rule_group.this.encryption_configuration) == 0
    error_message = "encryption_configuration should be absent when var is empty"
  }
}
