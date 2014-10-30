#!/usr/bin/python
# -*- coding: utf-8 -*-

"""Libvirt port-forwarding hook.

Libvirt hook for setting up iptables port-forwarding rules when using NAT-ed
networking.

Based on the work of Sascha Peilicke <saschpe@gmx.de>
"""
__author__ = "Iván De Gyves <fox@foxburu.mx>"
__version__ = "0.3"

import os
import json
import subprocess
import sys
import logging

logger = logging.getLogger('hooks-qemu.Firewall')

class Firewall(object):

	def __init__(self, fw_name, dom_name):
		logger.debug("Firewall {0} initialized".format(fw_name))
		self.__firewall = os.path.join(os.path.dirname(os.path.abspath(__file__)), fw_name + '.json')
		self.__schema = os.path.join(os.path.dirname(os.path.abspath(__file__)), fw_name + '.schema.json')
		self.dname = dom_name
		self.fwname = fw_name

	def __domain(self):
		if not hasattr(self, '__dom'):
			if not self.dname == "":
				self.__dom = self.__config().get(self.dname)
		
		return self.__dom

	def __host_ip(self):
		"""Returns the default route interface IP (if any).

		In other words, the public IP used to access the virtualization host. It
		is used as default public IP for guest forwarding rules should they not
		specify a different public IP to forward from.
		"""
		if not hasattr(self, "__ip"):
			cmd = "ip route | grep default | cut -d' ' -f5"
			default_route_interface = subprocess.check_output(cmd, shell=True).decode().strip()
			cmd = "ip addr show {0} | grep -E 'inet .*{0}' | cut -d' ' -f6 | cut -d'/' -f1".format(default_route_interface)
			self.__ip = subprocess.check_output(cmd, shell=True).decode().strip()

		return self.__ip

	def __config(self,validate=True):
		"""Returns the hook configuration.

		Assumes that the file /etc/libvirt/hooks/qemu.json exists and contains
		JSON-formatted configuration data. Optionally tries to validate the
		configuration if the 'jsonschema' module is available.

		Args:
			validate: Use JSON schema validation
		"""
		if not hasattr(self, "__conf"):
			with open(self.__firewall, "r") as f:
				self.__conf = json.load(f)
			if validate:
			    # Try schema validation but avoid hard 'jsonschema' requirement:
				try:
					import jsonschema
					with open(self.__schema, "r") as f:
						self.__conf.schema = json.load(f)
					jsonschema.validate(self.__conf,
								self.__conf.schema,
								format_checker=jsonschema.FormatChecker())
				except ImportError:
					pass

		return self.__conf

	def __iptables_forward(self, action, domain):
		"""Set iptables port-forwarding rules based on domain configuration.

		Args:
			action: iptables rule actions (one of '-I', '-A' or '-D')
			domain: Libvirt domain configuration
		"""
		IPTABLES_BINARY = subprocess.check_output(["which", "iptables"]).strip()
		public_ip = domain.get("public_ip", self.__host_ip())

	    	# Iterate over protocols (tcp, udp, icmp, ...)
		for protocol in domain["port_map"]:
			# Iterate over all public/private port pairs for the protocol
			for public_port, private_port in domain["port_map"].get(protocol):
				args = [IPTABLES_BINARY,
				    "-t", "nat", action, "PREROUTING",
				    "-p", protocol,
				    "-d", public_ip, "--dport", str(public_port),
				    "-j", "DNAT", "--to", "{0}:{1}".format(domain["private_ip"], str(private_port))]
				logger.debug("iptables invoked. cmdline => {0}".format(args))
				subprocess.call(args)

				args = [IPTABLES_BINARY,
				    "-t", "filter", action, "FORWARD",
				    "-p", protocol,
				    "--dport", str(private_port),
				    "-j", "ACCEPT"]
				if "interface" in domain:
					args += ["-o", domain["interface"]]
				logger.debug("iptables invoked. cmdline => {0}".format(args))
				subprocess.call(args)

	def __firewalld_forward(self, action, domain):
		"""Set firewalld port-forwarding rules based on domain configuration.

		Args:
			action: firewalld rule actions (remove or add)
			domain: Libvirt domain configuration
		"""
		# Get basic firewalling details.
		# TODO: Check how we can integrate zones on a 
		# more efficient way, of if we really need them...
		FIREWALLD_BINARY = subprocess.check_output(["which", "firewall-cmd"]).strip()
		intf = domain.get("interface")
		zone = domain.get("zone", 
			subprocess.check_output(["firewall-cmd", "--get-zone-of-interface={0}".format(intf)]).strip()
		       )
		private_ip = domain.get("private_ip")

	    	# Iterate over protocols (tcp, udp, icmp, ...)
		for protocol in domain["port_map"]:
			# Iterate over all public/private port pairs for the protocol
			for public_port, private_port in domain["port_map"].get(protocol):
				args = [FIREWALLD_BINARY,
					"--zone={0}".format(zone),
					"--{0}-forward-port=port={1}:proto={2}:toport={3}:toaddr={4}".format(
						action, public_port, protocol, private_port, private_ip
					)]
				logger.debug("firewall-cmd invoked. cmdline => {0}".format(args))
				subprocess.call(args)

	def __firewall_set(self, action, domain):
		opst=[]
		opst.append(subprocess.Popen(["systemctl", "list-unit-files"], stdout=subprocess.PIPE))
		opst.append(subprocess.Popen(["grep", "-E", '(firewalld|iptables)'], stdin=opst[0].stdout, stdout=subprocess.PIPE))
		opst.append(subprocess.Popen(["grep", "enabled"], stdin=opst[1].stdout, stdout=subprocess.PIPE))
		opst.append(subprocess.Popen(["awk", '{print $1;}'], stdin=opst[2].stdout, stdout=subprocess.PIPE))

		active_fw = subprocess.check_output(["sed", 's/.service$//'], stdin=opst[3].stdout).strip()

		if active_fw == b'firewalld':
			if action is 'on':
				self.__firewalld_forward('add', domain)
			elif action is 'off':
				self.__firewalld_forward('remove', domain)
			else:
				logger.warning("Invalid operation for " + active_fw + ": " + action)
		elif active_fw == b'iptables':
			if action is 'on':
				self.__iptables_forward('-I', domain)
			elif action is 'off':
				self.__iptables_forward('-D', domain)
			else:
				logger.warning("Invalid operation for " + active_fw + ": " + action)
		else:
			logger.error("Cannot detect an available firewall")

	def start(self):
		if self.__domain() is None:
			sys.exit(0);

		logger.info("Starting Firewall for " + self.dname + "...")
		self.__firewall_set('on', self.__domain())

	def stop(self):
		if self.__domain() is None:
			sys.exit(0);

		logger.info("Stopping Firewall for " + self.dname + "...")
		self.__firewall_set('off', self.__domain())

	def reconnect(self):
		logger.info("Reconnecting Firewall for " + self.dname + "...")
		self.stop()
		self.start()
