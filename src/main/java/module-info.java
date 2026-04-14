/*
 * Sly Technologies Free License
 * 
 * Copyright 2023 Sly Technologies Inc.
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

/**
 * High-level packet capture and protocol dissection API for jNetPcap.
 *
 * <p>
 * This module provides {@link com.slytechs.sdk.jnetpcap.api.NetPcap}, the
 * primary entry point for packet capture and offline file reading. It bridges
 * the low-level libpcap bindings in {@code com.slytechs.sdk.jnetpcap} with the
 * protocol dissection framework in {@code com.slytechs.sdk.protocol.core}.
 * </p>
 *
 * <h2>Key Classes</h2>
 * <ul>
 * <li>{@link com.slytechs.sdk.jnetpcap.api.NetPcap} - Live capture and offline
 * file reading with integrated protocol dissection</li>
 * <li>{@link com.slytechs.sdk.jnetpcap.api.PacketHandler} - Callback interfaces
 * for packet processing</li>
 * </ul>
 *
 * <h2>Quick Start</h2>
 * 
 * <pre>{@code
 * try (NetPcap pcap = NetPcap.openOffline("capture.pcap")) {
 * 	Ip4 ip = new Ip4();
 * 	pcap.loop(-1, packet -> {
 * 		if (packet.hasHeader(ip))
 * 			System.out.println(ip.src() + " -> " + ip.dst());
 * 	});
 * }
 * }</pre>
 *
 * <h2>Module Dependencies</h2>
 * <p>
 * This module re-exports the following modules transitively, so consumers only
 * need a single dependency:
 * </p>
 * <ul>
 * <li>{@code com.slytechs.sdk.jnetpcap} - Low-level libpcap FFM bindings</li>
 * <li>{@code com.slytechs.sdk.protocol.core} - Packet, Header,
 * PacketSettings</li>
 * <li>{@code com.slytechs.sdk.protocol.tcpip} - Ethernet, IPv4, TCP, UDP and
 * more</li>
 * <li>{@code com.slytechs.sdk.common} - Memory management and utilities</li>
 * </ul>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see <a href="https://github.com/slytechs-repos/jnetpcap-sdk">jNetPcap
 *      SDK</a>
 */
module com.slytechs.sdk.jnetpcap.api {
	exports com.slytechs.sdk.jnetpcap.api;

	opens com.slytechs.jnet.jnetpcap.api.foreign
			to com.slytechs.sdk.common;

	requires transitive com.slytechs.sdk.jnetpcap;
	requires transitive com.slytechs.sdk.protocol.core;
	requires transitive com.slytechs.sdk.protocol.tcpip;
	requires transitive com.slytechs.sdk.common;
	requires lexactivator;

}