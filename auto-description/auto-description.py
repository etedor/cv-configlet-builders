#!/usr/bin/env python
"""Automatically configure interface descriptions based on neighbor device details."""

import json
import re
import ssl
from datetime import datetime

import netaddr
from cvplibrary import CVPGlobalVariables, Device, GlobalVariableNames, RestClient
from jinja2 import Template

ssl._create_default_https_context = ssl._create_unverified_context

CVP_URL = "https://www.arista.io/cvpservice"
CVP_ADD_CONFIGLET = "/configlet/addConfiglet.do"
CVP_GET_CONFIGLET_BY_NAME = "/configlet/getConfigletByName.do?name="
CVP_UPDATE_CONFIGLET = "/configlet/updateConfiglet.do"

OUI24_MASK = 0xFFFFFF000000
OUI28_MASK = 0xFFFFFFF00000
OUI36_MASK = 0xFFFFFFFFF000
SECONDS_PER_24H = 86400

OUI_CONFIGLET = "oui.json"
VRF_DEFAULT = "default"

# external oui lookup
EXTERNAL_OUI_LOOKUP = True
CURL_TIMEOUT = 300
OUI_LIST = "https://gitlab.com/wireshark/wireshark/-/raw/master/manuf"
OUI_PATTERN = r"^(?P<oui>([0-9A-F]{2}[:]){2,5}([0-9A-F]{2}))(\/\d+)?\s(?P<org>\S+).*$"

TEMPLATE = Template(
    """\
interface {{ interface }}
   description {{ description | upper }}
"""
)


class DUT(object):
    def __init__(self):
        device_ip = CVPGlobalVariables.getValue(GlobalVariableNames.CVP_IP)
        device_user = CVPGlobalVariables.getValue(GlobalVariableNames.ZTP_USERNAME)
        device_pass = CVPGlobalVariables.getValue(GlobalVariableNames.ZTP_PASSWORD)
        self.device = Device(device_ip, device_user, device_pass)

    def _run_cmd(self, command):
        """Run a command from the device under test."""
        return self.device.runCmds(["enable", command])[1]["response"]

    def curl(self, url, timeout=CURL_TIMEOUT, vrf=VRF_DEFAULT):
        """Run a curl command from the device under test."""
        command = "bash timeout {timeout} {vrf} curl --silent {url}".format(
            timeout=timeout,
            url=url,
            vrf="sudo ip netns exec ns-{vrf}".format(vrf=vrf)
            if vrf != VRF_DEFAULT
            else "",
        )
        try:
            return self._run_cmd(command)["messages"][0]
        except KeyError:
            return

    def oui_list(self, vrf=VRF_DEFAULT):
        """Return an up-to-date list of OUI-to-organization bindings."""

        def _download(vrf=VRF_DEFAULT):
            """Download and parse the latest OUI list."""
            db = {}

            response = self.curl(url=OUI_LIST, vrf=vrf)
            if not response:
                return db

            matches = re.finditer(OUI_PATTERN, response, re.MULTILINE)
            if not matches:
                return db

            for match in matches:
                oui = match.group("oui")
                if len(oui) == 8:
                    oui += ":00:00:00"
                oui = netaddr.EUI(oui)
                oui.dialect = netaddr.mac_bare
                oui = str(oui)

                org = match.group("org")

                if oui not in db or db[oui] == "IEEERegi":
                    db[oui] = org

            return db

        key, timestamp = configlet_exists(OUI_CONFIGLET)
        update_needed = (not key) or (timestamp and is_24h_old(timestamp))
        if update_needed:
            db = json.dumps(_download(vrf=vrf))
            if db and not key:
                configlet_add(configlet_data=db, configlet_name=OUI_CONFIGLET)
            elif db and key:
                configlet_update(
                    configlet_data=db, configlet_key=key, configlet_name=OUI_CONFIGLET
                )

        return json.loads(configlet_get(OUI_CONFIGLET))

    def org_from_mac(self, mac_address, vrf=VRF_DEFAULT):
        """Return the registered organization for a given MAC address."""
        org = "Unknown"
        mac_address = netaddr.EUI(mac_address)

        if EXTERNAL_OUI_LOOKUP:
            db = self.oui_list(vrf=vrf)
            for mask in (OUI36_MASK, OUI28_MASK, OUI24_MASK):
                oui = netaddr.EUI(int(mac_address.bin, 2) & mask)
                oui.dialect = netaddr.mac_bare
                oui = str(oui)
                if oui in db:
                    org = db[oui]
                    break
        else:
            try:
                org = mac_address.oui.registration().org
            except netaddr.NotRegisteredError:
                pass

        mac_address.dialect = netaddr.mac_bare
        last_six = ":".join(str(mac_address)[-6:][i : i + 2] for i in range(0, 6, 2))
        return str(org) + ", " + last_six

    def show(self, command):
        """Run a show command from the device under test."""
        return self._run_cmd("show " + command)


def auto_description(dut, interfaces, running_config):
    """Automatically configure interface descriptions based on neighbor device details."""
    vrf = vrf_from_terminattr(running_config)

    port_channels = set()
    for interface in sorted(interfaces.values(), key=lambda x: x["name"]):
        if not interface["name"].startswith("Ethernet") and not interface[
            "name"
        ].startswith("Management"):
            continue
        config = running_config["interface " + interface["name"]]
        if "no auto-description" in config["comments"]:
            continue

        description = None
        if len(interface.get("lldp_neighbors", [])) == 1:
            neighbor = interface["lldp_neighbors"][0]
            try:
                description = neighbor["systemName"]
            except KeyError:
                description = neighbor["chassisId"]

            if is_mac(description):
                description = dut.org_from_mac(description, vrf)
            else:
                if (
                    neighbor["neighborInterfaceInfo"]["interfaceIdType"]
                    == "interfaceName"
                ):
                    neighbor_interface_id = neighbor["neighborInterfaceInfo"][
                        "interfaceId_v2"
                    ]
                else:
                    neighbor_interface_id = neighbor["neighborInterfaceInfo"][
                        "interfaceDescription"
                    ]

                # shorten fqdn to simple hostname
                description = description.split(".")[0]

                # add description to port-channel if this intf is a member
                try:
                    # e.g. `"interfaceMembership": "Member of Port-Channel1"`
                    port_channel = interface["interfaceMembership"].split(" ")[2]
                    if port_channel not in port_channels:
                        print(
                            TEMPLATE.render(
                                interface=port_channel, description=description
                            )
                        )
                    port_channels.add(port_channel)
                except KeyError:
                    pass

                # add neighbor intf to description
                description += ", " + neighbor_interface_id

        # otherwise, try to determine vendor from mac oui
        elif len(interface.get("mac_address_table", [])) == 1:
            mac_address = interface["mac_address_table"][0]["macAddress"]
            description = dut.org_from_mac(mac_address, vrf)

        if description:
            print(TEMPLATE.render(interface=interface["name"], description=description))


def configlet_add(configlet_data, configlet_name):
    """This API is used to add a configlet."""
    data = {
        "config": configlet_data,
        "name": configlet_name,
    }
    client = RestClient(CVP_URL + CVP_ADD_CONFIGLET, "POST")
    client.setRawData(json.dumps(data))
    if client.connect():
        response = json.loads(client.getResponse())
        return not response.get("errorCode")


def configlet_exists(configlet_name):
    """This API is used to get a configlet by its name."""
    client = RestClient(CVP_URL + CVP_GET_CONFIGLET_BY_NAME + configlet_name, "GET")
    if client.connect():
        response = json.loads(client.getResponse())
        if "errorCode" not in response:
            return response["key"], response["dateTimeInLongFormat"]
    return False, 0


def configlet_get(configlet_name):
    """This API is used to get a configlet by its name."""
    client = RestClient(CVP_URL + CVP_GET_CONFIGLET_BY_NAME + configlet_name, "GET")
    if client.connect():
        response = json.loads(client.getResponse())
        if "errorCode" not in response:
            return response["config"]
    return "{}"


def configlet_update(configlet_data, configlet_key, configlet_name):
    """This API is used to update a configlet."""
    data = {
        "config": configlet_data,
        "key": configlet_key,
        "name": configlet_name,
        "waitForTaskIds": False,
        "reconciled": False,
    }
    client = RestClient(CVP_URL + CVP_UPDATE_CONFIGLET, "POST")
    client.setRawData(json.dumps(data))
    if client.connect():
        response = json.loads(client.getResponse())
        return not response.get("errorCode")


def is_24h_old(timestamp):
    """Returns true if the provided timestamp is more than 24 hours old, false otherwise."""
    return (
        datetime.utcnow() - datetime.utcfromtimestamp(timestamp / 1000)
    ).total_seconds() > SECONDS_PER_24H


def is_mac(mac_address):
    """Returns true if the provided string is a valid MAC address, false otherwise."""
    try:
        netaddr.EUI(mac_address)
        return True
    except netaddr.AddrFormatError:
        return False


def lldp_neighbors_to_interfaces(interfaces, lldp_neighbors):
    """Add LLDP neighbors to the corresponding interface."""
    for interface in lldp_neighbors:
        try:
            interfaces[interface]["lldp_neighbors"] = lldp_neighbors[interface][
                "lldpNeighborInfo"
            ]
        except KeyError:
            continue


def mac_address_table_to_interfaces(interfaces, mac_address_table):
    """Add MAC address table entries to the corresponding interface."""
    for mac_address in mac_address_table:
        try:
            interfaces[mac_address["interface"]].setdefault(
                "mac_address_table", []
            ).append(mac_address)
        except KeyError:
            continue


def vrf_from_terminattr(running_config):
    """Determine the internet-facing VRF from the device's TerminAttr config."""
    # e.g. `"exec /usr/bin/TerminAttr -cvvrf=MGMT": null,`
    vrf = VRF_DEFAULT
    try:
        args = next(
            key
            for key in running_config.get("daemon TerminAttr", {})["cmds"].keys()
            if "exec" in key
        ).split(" ")
    except (KeyError, StopIteration):
        return vrf
    for arg in args:
        if not arg.startswith("-cvvrf"):
            continue
        vrf = arg.split("=")[1]
    return vrf


def main():
    dut = DUT()

    interfaces = dut.show("interfaces")["interfaces"]
    lldp_neighbors = dut.show("lldp neighbors detail")["lldpNeighbors"]
    mac_address_table = dut.show("mac address-table")["unicastTable"]["tableEntries"]
    running_config = dut.show("running-config")["cmds"]

    lldp_neighbors_to_interfaces(interfaces, lldp_neighbors)
    mac_address_table_to_interfaces(interfaces, mac_address_table)
    auto_description(dut, interfaces, running_config)


if __name__ == "__main__":
    try:
        main()
    except ValueError:
        pass
