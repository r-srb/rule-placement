output "matched" {
  description = "Firewalls that connect at least one subnet overlapping the queried prefixes (stub match only)."
  value       = sort([for fw, h in local.hits : fw if length(h) > 0])
}

output "hits" {
  description = "Firewall -> the connected subnets that overlap the queried prefixes (empty list when none)."
  value       = local.hits
}

output "internet" {
  description = "Firewall -> queried prefixes that are internet by that firewall's internet_exclude (empty unless ability includes internet)."
  value       = local.internet
}

output "unmatched" {
  description = "Queried prefixes that overlap no connected subnet and are internet on no firewall."
  value       = local.unmatched
}
