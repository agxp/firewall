import ipaddress

class Firewall:
	def __init__(self, path):
		self.rules = {
			'inbound': {
				'tcp': {}, 
				'udp': {}
			}, 
			'outbound': {
				'tcp': {},
				'udp': {}
			}
		}
		
		with open(path, 'r') as f:
			self.processRules(f)
	
	def processRules(self, f):
		for line in f:
			l = line.split(',')
			dir, prot, port, ip = str(l[0]), str(l[1]), str(l[2]), str(l[3])
			ip = ip.strip()
			if dir == 'direction':
				continue
			start = 0
			end = 0
			if '-' in ip:
				start = int(ipaddress.IPv4Address(ip.split('-')[0]))
				end = int(ipaddress.IPv4Address(ip.split('-')[1]))
			else:
				start = int(ipaddress.IPv4Address(ip))
				end = start
			if '-' in port:
				p = port.split('-')
				for i in range(int(p[0]), int(p[1])):
					i = str(i)
					if i in self.rules[dir][prot]:
						self.rules[dir][prot][i].append((start, end))
					else:
						self.rules[dir][prot][i] = [(start, end)]
			else:
				if str(port) in self.rules[dir][prot]:
					self.rules[dir][prot][port].append((start, end))
				else:
					self.rules[dir][prot][port] = [(start, end)]
	
	def accept_packet(self, direction, protocol, port, ip_address):
		try:
			ip = int(ipaddress.IPv4Address(ip_address))
			port = str(port)
			valid = self.rules[direction][protocol][port]
			for (start, end) in valid:
				if ip >= start and ip <= end:
					return True
			return False
		except:
			return False

fw = Firewall('test.csv')
print(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2")) # matches first rule
#true
print(fw.accept_packet("inbound", "udp", 53, "192.168.2.1")) # matches third rule
#true
print(fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11")) # matches second rule
#true
print(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2"))
#false
print(fw.accept_packet("inbound", "udp", 24, "52.12.48.92"))
#false
print(fw.accept_packet("outbound", "udp", 1337, "52.12.48.92"))
#true
#print(fw.rules)