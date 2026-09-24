mock_provider "aws" {}

# Run 1: populated stateless rule group with stateless_rules + custom_actions.
run "stateless_populated" {
  command = plan

  variables {
    name        = "example-stateless"
    description = "example stateless firewall group rules"
    capacity    = 100

    custom_actions = {
      action1 = {
        dimensions = ["2"]
      }
      action2 = {
        dimensions = ["3"]
      }
    }

    stateless_rules = {
      rule1 = {
        priority = 1
        action   = ["aws:pass"]
        source   = ["127.0.0.1/32", "127.0.0.2/32"]
        sourcePorts = [
          { from = 443, to = 443 },
          { from = 8443, to = 8443 },
        ]
        destination = ["127.0.0.1/32"]
        destinationPorts = [
          { from = 443, to = 443 },
        ]
        protocols = [6]
        tcp = {
          flags = ["SYN"]
          masks = ["SYN", "ACK"]
        }
      }
      rule2 = {
        priority = 2
        action   = ["aws:pass"]
        source   = ["127.0.0.1/32"]
        sourcePorts = [
          { from = 8080, to = 8080 },
        ]
        destination = ["127.0.0.1/32"]
        destinationPorts = [
          { from = 8080, to = 8080 },
        ]
        protocols = [17]
      }
    }

    tags = {
      Environment = "test"
      Team        = "core-cloud"
    }
  }

  # Top-level deterministic attributes.
  assert {
    condition     = aws_networkfirewall_rule_group.this.name == "example-stateless"
    error_message = "name should equal var.name"
  }

  assert {
    condition     = aws_networkfirewall_rule_group.this.description == "example stateless firewall group rules"
    error_message = "description should equal var.description"
  }

  assert {
    condition     = aws_networkfirewall_rule_group.this.capacity == 100
    error_message = "capacity should equal var.capacity"
  }

  assert {
    condition     = aws_networkfirewall_rule_group.this.type == "STATELESS"
    error_message = "type should be STATELESS"
  }

  assert {
    condition     = aws_networkfirewall_rule_group.this.tags["Environment"] == "test"
    error_message = "tags should propagate from var.tags"
  }

  assert {
    condition     = aws_networkfirewall_rule_group.this.tags["Team"] == "core-cloud"
    error_message = "tags should propagate from var.tags"
  }

  # stateless_rule dynamic blocks built from stateless_rules input.
  assert {
    condition     = length(aws_networkfirewall_rule_group.this.rule_group[0].rules_source[0].stateless_rules_and_custom_actions[0].stateless_rule) == 2
    error_message = "two stateless_rule blocks should be built from stateless_rules"
  }

  # custom_action dynamic blocks built from custom_actions input.
  assert {
    condition     = length(aws_networkfirewall_rule_group.this.rule_group[0].rules_source[0].stateless_rules_and_custom_actions[0].custom_action) == 2
    error_message = "two custom_action blocks should be built from custom_actions"
  }

  # priority values propagate.
  assert {
    condition = anytrue([
      for r in aws_networkfirewall_rule_group.this.rule_group[0].rules_source[0].stateless_rules_and_custom_actions[0].stateless_rule : r.priority == 1
    ])
    error_message = "stateless_rule priority should propagate from input"
  }

  # source address_definition built from input source list on rule1.
  assert {
    condition = anytrue([
      for r in aws_networkfirewall_rule_group.this.rule_group[0].rules_source[0].stateless_rules_and_custom_actions[0].stateless_rule :
      length(r.rule_definition[0].match_attributes[0].source) == 2
    ])
    error_message = "a rule should build two source address_definition blocks"
  }

  # tcp_flag block present for the rule that supplies tcp.
  assert {
    condition = anytrue([
      for r in aws_networkfirewall_rule_group.this.rule_group[0].rules_source[0].stateless_rules_and_custom_actions[0].stateless_rule :
      length(r.rule_definition[0].match_attributes[0].tcp_flag) == 1
    ])
    error_message = "tcp_flag should be built for a rule supplying tcp"
  }
}

# Run 2: minimal stateless rule group with custom_actions empty and
# encryption_configuration toggled on.
run "stateless_minimal_optionals" {
  command = plan

  variables {
    name        = "minimal-stateless"
    description = "minimal stateless rule group"
    capacity    = 10

    custom_actions = {}

    encryption_configuration = {
      type   = "CUSTOMER_KMS"
      key_id = "test-key-id"
    }

    stateless_rules = {
      only = {
        priority         = 1
        action           = ["aws:drop"]
        source           = ["10.0.0.1/32"]
        sourcePorts      = []
        destination      = ["10.0.0.2/32"]
        destinationPorts = []
        protocols        = [6]
      }
    }

    tags = {}
  }

  assert {
    condition     = aws_networkfirewall_rule_group.this.name == "minimal-stateless"
    error_message = "name should equal var.name"
  }

  assert {
    condition     = aws_networkfirewall_rule_group.this.type == "STATELESS"
    error_message = "type should be STATELESS"
  }

  assert {
    condition     = aws_networkfirewall_rule_group.this.capacity == 10
    error_message = "capacity should equal var.capacity"
  }

  # custom_action absent when custom_actions empty.
  assert {
    condition     = length(aws_networkfirewall_rule_group.this.rule_group[0].rules_source[0].stateless_rules_and_custom_actions[0].custom_action) == 0
    error_message = "custom_action block should be absent when custom_actions var is empty"
  }

  # single stateless_rule still built.
  assert {
    condition     = length(aws_networkfirewall_rule_group.this.rule_group[0].rules_source[0].stateless_rules_and_custom_actions[0].stateless_rule) == 1
    error_message = "one stateless_rule block should be built from stateless_rules"
  }

  # encryption_configuration present when var is non-empty.
  assert {
    condition     = length(aws_networkfirewall_rule_group.this.encryption_configuration) == 1
    error_message = "encryption_configuration block should be present when var is non-empty"
  }

  assert {
    condition     = aws_networkfirewall_rule_group.this.encryption_configuration[0].type == "CUSTOMER_KMS"
    error_message = "encryption_configuration type should propagate from var"
  }
}
