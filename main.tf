terraform {
  required_version = ">= 1.3"
}

locals {
  inventory = yamldecode(file("${path.module}/firewalls.yaml"))

  # Set name -> CIDRs. A member that is not a CIDR names another set (one level deep).
  # Unknown set names are passed through unchanged, here and below, so the module's
  # CIDR validation reports them instead of a bare "Invalid index".
  address_sets = { for n, members in try(local.inventory.address_sets, {}) : n => flatten([
    for m in members : can(cidrnetmask(m)) ? [m] : try(tolist(local.inventory.address_sets[m]), [m])
  ]) }

  # Normalised for the module: ability is always a list, set names are expanded.
  firewalls = { for name, f in local.inventory.firewalls : name => {
    ability = flatten([try(f.ability, [])])
    subnets = try(f.subnets, [])
    internet_exclude = distinct(flatten([
      for e in try(f.internet_exclude, []) : can(cidrnetmask(e)) ? [e] : try(local.address_sets[e], [e])
    ]))
  } }

  internet_firewalls = [for fw, f in local.firewalls : fw if contains(f.ability, "internet")]

  # Every rules file in rules/, keyed "<ticket>/<rule name>".
  rules = merge([
    for f in fileset("${path.module}/rules", "*.y*ml") : {
      for name, r in try(yamldecode(file("${path.module}/rules/${f}")).net, {}) :
      "${trimsuffix(trimsuffix(f, ".yaml"), ".yml")}/${name}" => r
    }
  ]...)
}

# "Calling the function": once for the source side, once for the destination side.
module "src" {
  for_each  = local.rules
  source    = "./modules/cidr-match"
  firewalls = local.firewalls
  cidrs     = try(each.value.source_addresses, [])
}

module "dst" {
  for_each  = local.rules
  source    = "./modules/cidr-match"
  firewalls = local.firewalls
  cidrs     = try(each.value.destination_addresses, [])
}

locals {
  # Internet firewalls carrying the internet side of a rule. The other side decides the exit:
  #   * it sits only on internet-capable firewalls (a DMZ) -> break out there, nowhere else
  #   * it touches any stub-only firewall                  -> exit is not modelled, so every internet firewall
  #   * it matches no stub at all                          -> internet-to-internet or a typo; place nothing
  src_internet = { for k in keys(local.rules) : k => [
    for fw, p in module.src[k].internet : fw
    if length(p) > 0 && length(module.dst[k].matched) > 0 && (
      length(setsubtract(module.dst[k].matched, local.internet_firewalls)) > 0 || contains(module.dst[k].matched, fw)
    )
  ] }

  dst_internet = { for k in keys(local.rules) : k => [
    for fw, p in module.dst[k].internet : fw
    if length(p) > 0 && length(module.src[k].matched) > 0 && (
      length(setsubtract(module.src[k].matched, local.internet_firewalls)) > 0 || contains(module.src[k].matched, fw)
    )
  ] }

  # Firewalls owning each side of the rule, by stub subnet or by internet.
  src_on = { for k in keys(local.rules) : k => sort(distinct(concat(module.src[k].matched, local.src_internet[k]))) }
  dst_on = { for k in keys(local.rules) : k => sort(distinct(concat(module.dst[k].matched, local.dst_internet[k]))) }

  placement = {
    for k, r in local.rules : k => {
      firewalls = sort(distinct(concat(local.src_on[k], local.dst_on[k])))

      # Which side each firewall owns -> which interface the rule lands on.
      role = {
        for fw in distinct(concat(local.src_on[k], local.dst_on[k])) : fw =>
        contains(local.src_on[k], fw) && contains(local.dst_on[k], fw) ? "intra" :
        contains(local.src_on[k], fw) ? "egress" : "ingress"
      }

      # Connected subnets that matched, plus "internet" where the internet side matched.
      src_hits = { for fw in local.src_on[k] : fw => concat(module.src[k].hits[fw], contains(local.src_internet[k], fw) ? ["internet"] : []) }
      dst_hits = { for fw in local.dst_on[k] : fw => concat(module.dst[k].hits[fw], contains(local.dst_internet[k], fw) ? ["internet"] : []) }

      # Prefixes that match nothing - typically reserved/documentation space or a typo.
      unmatched = { src = module.src[k].unmatched, dst = module.dst[k].unmatched }

      rule = r
    }
  }

  orphans = sort([for k, p in local.placement : k if length(p.firewalls) == 0])
}

output "placement" {
  description = "Rule key -> firewalls the rule must be created on, plus why."
  value       = local.placement
}

output "by_firewall" {
  description = "Firewall -> rule keys to render on it."
  value = {
    for fw in keys(local.firewalls) : fw => sort([
      for k, p in local.placement : k if contains(p.firewalls, fw)
    ])
  }
}

output "unplaced_rules" {
  description = "Rules that land on no firewall - almost always a typo in the request."
  value       = local.orphans
}

output "unmatched_prefixes" {
  description = "Rule key -> prefixes that match no firewall, for rules that have any. Partial matches still place the rule."
  value = {
    for k, p in local.placement : k => p.unmatched
    if length(p.unmatched.src) + length(p.unmatched.dst) > 0
  }
}
