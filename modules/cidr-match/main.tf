locals {
  # Everything we have to reason about, deduplicated.
  all = distinct(concat(flatten([for f in values(var.firewalls) : concat(f.subnets, f.internet_exclude)]), var.cidrs))

  # --- pure-HCL IPv4 CIDR -> integer range -----------------------------
  # No bitwise operators in HCL, so masking is done as floor(ip/size)*size.
  octets = { for c in local.all : c => [for o in split(".", split("/", c)[0]) : tonumber(o)] }
  size   = { for c in local.all : c => pow(2, 32 - tonumber(split("/", c)[1])) }
  addr = { for c in local.all : c =>
    local.octets[c][0] * 16777216 +
    local.octets[c][1] * 65536 +
    local.octets[c][2] * 256 +
    local.octets[c][3]
  }

  # first = network address, last = broadcast address, as plain integers.
  range = { for c in local.all : c => {
    first = floor(local.addr[c] / local.size[c]) * local.size[c]
    last  = floor(local.addr[c] / local.size[c]) * local.size[c] + local.size[c] - 1
  } }

  # --- stub match ------------------------------------------------------
  # Two prefixes overlap iff a.first <= b.last && b.first <= a.last.
  # That is symmetric, so it catches both "query inside subnet"
  # (10.1.1.8/30 in 10.1.1.0/24) and "subnet inside query" (10.0.0.0/8).
  hits = { for fw, f in var.firewalls : fw => sort(distinct(flatten([
    for q in var.cidrs : [
      for s in f.subnets : s
      if local.range[q].first <= local.range[s].last && local.range[s].first <= local.range[q].last
    ]
  ]))) }

  # --- internet match --------------------------------------------------
  # A queried prefix is internet unless it sits wholly inside one excluded
  # prefix. Exact for ordinary rule prefixes; a query straddling two adjacent
  # excluded blocks without fitting in either would count as internet.
  internet = { for fw, f in var.firewalls : fw => sort(distinct([
    for q in var.cidrs : q
    if contains(f.ability, "internet") && !anytrue([
      for e in f.internet_exclude :
      local.range[e].first <= local.range[q].first && local.range[q].last <= local.range[e].last
    ])
  ])) }

  unmatched = sort([
    for q in distinct(var.cidrs) : q
    if !anytrue([
      for fw, f in var.firewalls : contains(local.internet[fw], q) || anytrue([
        for s in f.subnets :
        local.range[q].first <= local.range[s].last && local.range[s].first <= local.range[q].last
      ])
    ])
  ])
}
