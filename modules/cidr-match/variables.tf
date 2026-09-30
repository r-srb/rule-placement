variable "firewalls" {
  description = "Firewall -> ability (stub and/or internet), directly connected subnets, and prefixes that are never internet (IPv4 CIDR, address sets already expanded)."
  type = map(object({
    ability          = list(string)
    subnets          = list(string)
    internet_exclude = list(string)
  }))

  validation {
    condition     = alltrue([for f in values(var.firewalls) : length(f.ability) > 0 && alltrue([for a in f.ability : contains(["stub", "internet"], a)])])
    error_message = "Every firewall needs an ability of \"stub\", \"internet\" or both."
  }

  validation {
    condition     = alltrue([for f in values(var.firewalls) : contains(f.ability, "stub") == (length(f.subnets) > 0)])
    error_message = "A firewall has subnets if and only if its ability includes \"stub\"."
  }

  validation {
    condition     = alltrue([for c in flatten([for f in values(var.firewalls) : concat(f.subnets, f.internet_exclude)]) : can(cidrnetmask(c))])
    error_message = "Every subnet and internet_exclude entry must be a valid IPv4 CIDR or the name of an address set (cidrnetmask() rejects IPv6, malformed values and unknown set names)."
  }
}

variable "cidrs" {
  description = "Queried prefixes (a rule's source_addresses or destination_addresses). May be larger than any connected subnet, e.g. 10.0.0.0/8."
  type        = list(string)

  validation {
    condition     = length(var.cidrs) > 0 && alltrue([for c in var.cidrs : can(cidrnetmask(c))])
    error_message = "Every rule side needs at least one prefix, and every queried prefix must be a valid IPv4 CIDR."
  }
}
