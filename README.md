# firewall

stores all ip ranges in a dictionary with fast access. Access time is O(k) with k being the number for rules with the specific direction, protocol, and port. Space is up to O(k*n) with n being ports, k being number of rules per port

1. platform
2. data
3. policy
