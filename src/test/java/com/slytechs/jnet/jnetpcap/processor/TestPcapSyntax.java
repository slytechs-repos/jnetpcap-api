/*
 * Sly Technologies Free License
 * 
 * Copyright 2024 Sly Technologies Inc.
 *
 * Licensed under the Sly Technologies Free License (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.slytechs.com/free-license-text
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package com.slytechs.jnet.jnetpcap.processor;

import java.io.File;
import java.io.IOException;

import org.jnetpcap.PcapException;
import org.junit.jupiter.api.Test;

import com.slytechs.jnet.jnetpcap.api.NetPcap;
import com.slytechs.jnet.platform.api.NotFound;
import com.slytechs.jnet.platform.api.util.HexStrings;
import com.slytechs.jnet.protocol.api.meta.PacketFormat;
import com.slytechs.jnet.protocol.tcpip.link.Ppp;
import com.slytechs.jnet.protocol.tcpip.network.Ip4;
import com.slytechs.jnet.protocol.tcpip.network.Ip4MtuProbeOption;
import com.slytechs.jnet.protocol.tcpip.network.Ip4MtuReplyOption;
import com.slytechs.jnet.protocol.tcpip.network.Ip4QuickStartOption;
import com.slytechs.jnet.protocol.tcpip.network.Ip4RecordRouteOption;
import com.slytechs.jnet.protocol.tcpip.network.Ip4RouterAlertOption;
import com.slytechs.jnet.protocol.tcpip.network.Ip4SecurityDefunctOption;
import com.slytechs.jnet.protocol.tcpip.network.Ip4TimestampOption;
import com.slytechs.jnet.protocol.tcpip.network.Ip4TracerouteOption;
import com.slytechs.jnet.protocol.tcpip.network.Ip6;
import com.slytechs.jnet.protocol.tcpip.network.Ip6AuthHeaderExtension;
import com.slytechs.jnet.protocol.tcpip.network.Ip6DestinationExtension;
import com.slytechs.jnet.protocol.tcpip.network.Ip6EcapsSecPayloadExtension;
import com.slytechs.jnet.protocol.tcpip.network.Ip6FragmentExtension;
import com.slytechs.jnet.protocol.tcpip.network.Ip6HopByHopExtension;
import com.slytechs.jnet.protocol.tcpip.network.Ip6MobilityExtension;
import com.slytechs.jnet.protocol.tcpip.network.Ip6RoutingExtension;
import com.slytechs.jnet.protocol.tcpip.network.Ip6Shim6Extension;

/**
 * @author Mark Bednarczyk
 *
 */
public class TestPcapSyntax {

	@Test
	void test(String[] args) throws NotFound, IOException, PcapException {
		final File FILE = new File("pcaps/HTTP.cap");

//		Pack.listAllDeclaredPacks().forEach(System.out::println);
//		Arrays.stream(CoreId.values()).forEach(System.out::println);

		/**
		 * <pre>
		 * Breakdown of the packet:
		
		PPP Header:
		
		7E: Flag byte
		FF: Address byte (broadcast)
		03: Control byte (unnumbered information)
		0021: Protocol (IPv4)
		
		
		Payload (simple IPv4 packet):
		
		45: IPv4 version and header length
		Rest of payload bytes representing a minimal IPv4 packet
		
		
		End flag:
		
		7E: Ending flag byte
		 * </pre>
		 */
		final byte[] pppPacket = HexStrings.parseHexString(
				"7E FF 03 00 21 45 00 00 14 00 01 00 00 40 00 7C E7 7F 00 00 01 7F 00 00 01 7E");

		Ppp ppp = new Ppp();
		ppp.setFormatter(new PacketFormat());

		ppp.bind(pppPacket);

		System.out.println(ppp);

		try (var pcap = NetPcap.offline(FILE)) {

			Ip4 ip4 = new Ip4();
			Ip6 ip6 = new Ip6();

			pcap.dispatchPacket(60, (u, packet) -> {

				if (packet.hasHeader(ip6)) {
					System.out.println("Source IP: " + ip4.srcAsAddress());
					System.out.println("Destination IP: " + ip4.dstAsAddress());
					System.out.println("Next Header: " + ip6.nextHeader());
					System.out.println("Hop Limit: " + ip6.hopLimit());
					System.out.println("Payload Length: " + ip6.payloadLength());
					System.out.println("Traffic Class: " + ip6.trafficClass());
					System.out.println("Flow Label: " + ip6.flowLabel());

					// Authentication Header
					Ip6AuthHeaderExtension authHeader = new Ip6AuthHeaderExtension();
					if (packet.hasHeader(authHeader)) {
						System.out.println("Authentication Header present");
						// Access authentication data
					}

					// Destination Options Header
					Ip6DestinationExtension destOptions = new Ip6DestinationExtension();
					if (packet.hasHeader(destOptions)) {
						System.out.println("Destination Options Header present");
						// Access destination options
					}

					// Encapsulating Security Payload Header
					Ip6EcapsSecPayloadExtension espHeader = new Ip6EcapsSecPayloadExtension();
					if (packet.hasHeader(espHeader)) {
						System.out.println("ESP Header present");
						// Access ESP data
					}

					// Fragment Header
					Ip6FragmentExtension fragmentHeader = new Ip6FragmentExtension();
					if (packet.hasHeader(fragmentHeader)) {
						System.out.println("Fragment Header present");
						System.out.println("Fragment Offset: " + fragmentHeader.fragmentOffset());
					}

					// Hop-by-Hop Options Header
					Ip6HopByHopExtension hopByHopHeader = new Ip6HopByHopExtension();
					if (packet.hasHeader(hopByHopHeader)) {
						System.out.println("Hop-by-Hop Options Header present");
						// Access hop-by-hop options
					}

					// Mobility Header
					Ip6MobilityExtension mobilityHeader = new Ip6MobilityExtension();
					if (packet.hasHeader(mobilityHeader)) {
						System.out.println("Mobility Header present");
						// Access mobility data
					}

					// Routing Header
					Ip6RoutingExtension routingHeader = new Ip6RoutingExtension();
					if (packet.hasHeader(routingHeader)) {
						System.out.println("Routing Header present");
						System.out.println("Routing Type: " + routingHeader.routingType());
					}

					// Shim6 Header
					Ip6Shim6Extension shim6Header = new Ip6Shim6Extension();
					if (packet.hasHeader(shim6Header)) {
						System.out.println("Shim6 Header present");
						// Access Shim6 data
					}
				}

				if (packet.hasHeader(ip4)) {
					System.out.println("Source IP: " + ip4.srcAsAddress());
					System.out.println("Destination IP: " + ip4.dstAsAddress());
					System.out.println("Protocol: " + ip4.protocol());
					System.out.println("TTL: " + ip4.ttl());
					System.out.println("Total Length: " + ip4.totalLength());
					System.out.println("Identification: " + ip4.identification());
					System.out.println("Don't Fragment: " + ip4.flags_DF());
					System.out.println("More Fragments: " + ip4.flags_MF());
					System.out.println("Fragment Offset: " + ip4.fragOffset());

					// MTU Probe Option
					Ip4MtuProbeOption mtuProbeOption = new Ip4MtuProbeOption();
					if (ip4.hasOption(mtuProbeOption)) {
						System.out.println("MTU Probe Option present");
						// Access option-specific data
					}

					// MTU Reply Option
					Ip4MtuReplyOption mtuReplyOption = new Ip4MtuReplyOption();
					if (ip4.hasOption(mtuReplyOption)) {
						System.out.println("MTU Reply Option present");
						// Access option-specific data
					}

					// Quick-Start Option
					Ip4QuickStartOption quickStartOption = new Ip4QuickStartOption();
					if (ip4.hasOption(quickStartOption)) {
						System.out.println("Quick-Start Option present");
						// Access option-specific data
					}

					// Record Route Option
					Ip4RecordRouteOption recordRouteOption = new Ip4RecordRouteOption();
					if (ip4.hasOption(recordRouteOption)) {
						System.out.println("Record Route Option present");
						// Access recorded routes
					}

					// Security and Extended Security Option
					Ip4SecurityDefunctOption securityOption = new Ip4SecurityDefunctOption();
					if (ip4.hasOption(securityOption)) {
						System.out.println("Security Option present");
						// Access security-related data
					}

					// Timestamp Option
					Ip4TimestampOption timestampOption = new Ip4TimestampOption();
					if (ip4.hasOption(timestampOption)) {
						System.out.println("Timestamp Option present");
						// Access timestamp data
					}

					// Traceroute Option
					Ip4TracerouteOption tracerouteOption = new Ip4TracerouteOption();
					if (ip4.hasOption(tracerouteOption)) {
						System.out.println("Traceroute Option present");
						// Access traceroute data
					}

					// Router Alert Option
					Ip4RouterAlertOption routerAlertOption = new Ip4RouterAlertOption();
					if (ip4.hasOption(routerAlertOption)) {
						System.out.println("Router Alert Option present");
						System.out.println("Alert Value: " + routerAlertOption.routerAlert());
					}
				}
			}, "");

		} catch (PcapException e) {
			e.printStackTrace();
		}
	}

}
