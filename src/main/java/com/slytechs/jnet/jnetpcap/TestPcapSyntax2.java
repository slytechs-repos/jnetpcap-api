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
package com.slytechs.jnet.jnetpcap;

import java.io.File;
import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.jnetpcap.PcapException;
import org.jnetpcap.PcapIf;

import com.slytechs.jnet.jnetruntime.NotFound;
import com.slytechs.jnet.jnetruntime.util.MemoryUnit;
import com.slytechs.jnet.protocol.core.Ip4Reassembled;
import com.slytechs.jnet.protocol.core.Ip4Statistics;
import com.slytechs.jnet.protocol.core.Ip6Reassembled;
import com.slytechs.jnet.protocol.core.Ip6Statistics;
import com.slytechs.jnet.protocol.core.IpReassembly;
import com.slytechs.jnet.protocol.core.IpReassemblyConfig;
import com.slytechs.jnet.protocol.core.IpReassemblyHandler;

/**
 * @author Mark Bednarczyk
 *
 */
public class TestPcapSyntax2 {

	public TestPcapSyntax2() {
	}

	public static void main(String[] args) throws NotFound, IOException, PcapException {
		final File FILE = new File("pcaps/HTTP.cap");
		final AtomicInteger pktCount = new AtomicInteger(1);

		final int COUNT = 2;
		PcapIf defaultIf = NetPcap.getDefaultDevice();

//		try (var pcap = NetPcap.live(defaultIf)) {} catch (PcapException e1) {}
//		try (var pcap = NetPcap.dead(PcapDlt.EN10MB)) {} catch (PcapException e1) {}
//		try (var pcap = NetPcap.offline(FILE)) {} catch (PcapException e1) {}

		try (var pcap = NetPcap.offline(FILE)) {

			IpReassemblyConfig ipConfig = new IpReassemblyConfig();
			ipConfig.setMaxPacketSize(8, MemoryUnit.KILOBYTES);
			ipConfig.setTimeout(30, TimeUnit.SECONDS);

			IpReassembly ipReassembly = new IpReassembly(ipConfig);
			pcap.setIpReassembler(ipReassembly);

			ipReassembly.addReassemblyHandler(new IpReassemblyHandler() {
				@Override
				public void reassembledIpv4(Ip4Reassembled reassembled) {
					System.out.println("Reassembled IPv4 datagram: " + reassembled.getLength() + " bytes");
					// Process the reassembled IPv4 datagram
				}

				@Override
				public void reassembledIpv6(Ip6Reassembled reassembled) {
					System.out.println("Reassembled IPv6 datagram: " + reassembled.getLength() + " bytes");
					// Process the reassembled IPv6 datagram
				}
			});

			// IPv4 Reassembly Statistics
			Ip4Statistics ip4Stats = ipReassembly.getIp4Statistics();
			System.out.println("Reassembled IPv4 datagrams: " + ip4Stats.getReassembledDatagrams());
			System.out.println("Fragmented IPv4 datagrams: " + ip4Stats.getFragmentedDatagrams());
			System.out.println("Discarded IPv4 fragments: " + ip4Stats.getDiscardedFragments());

			// IPv6 Reassembly Statistics
			Ip6Statistics ip6Stats = ipReassembly.getIp6Statistics();
			System.out.println("Reassembled IPv6 datagrams: " + ip6Stats.getReassembledDatagrams());
			System.out.println("Fragmented IPv6 datagrams: " + ip6Stats.getFragmentedDatagrams());
			System.out.println("Discarded IPv6 fragments: " + ip6Stats.getDiscardedFragments());

//			pcap.addProcessor(0, PeekProcessor::new, StatefulNativePacket.class)
//					.peek((MemorySegment h, MemorySegment d, NativeProcessorContext ctx) -> {
//						System.out.printf("#%03d ::peek:NativePacketPipe h=%s bytes, data=%s bytes%n",
//								pktCount.getAndIncrement(),
//								h.byteSize(),
//								d.byteSize());
//					});
//
//			pcap.addProcessor(0, PeekProcessor::new, StatefulRawPacket.class)
//					.peek((PcapHeader h, MemorySegment d, RawProcessorContext ctx) -> {
//						System.out.printf("#%03d ::peek:RawPacketPipe hdr=%s, data=%s%n",
//								pktCount.getAndIncrement(),
//								h.toString(),
//								d.byteSize());
//					});

//			System.out.println("TestPcapSyntax:: pcap.name=" + pcap.name());

//			pcap.setPromisc(true);
//			pcap.activate();

			pcap.dispatchNative(2, (MemorySegment u, MemorySegment h, MemorySegment d) -> {
				System.out.printf("#%03d ::dispatchNative hdr=%s bytes, data=%s bytes%n",
						pktCount.getAndIncrement(),
						h.byteSize(),
						d.byteSize());
			}, MemorySegment.NULL);

//			pcap.dispatchPacket(COUNT, (String user, Packet packet) -> {
//				try {
//					System.out.printf("#%03d ::dispatchPacket \"%s\"%n" + "%s%n",
//							pktCount.getAndIncrement(),
//							user,
//							packet.getHeader(new Ip4()));
//
//				} catch (HeaderNotFound e) {
//					e.printStackTrace();
//				}
//
//			}, "Hello World");
//
//			pcap.dispatchArray(COUNT, (String user, PcapHeader hdr, byte[] packet) -> {
//				int len = hdr.captureLength() < 64 ? hdr.captureLength() : 64;
//				System.out.printf("#%03d ::dispatchArray caplen=%s bytes, ts=%s, dump:%n%s",
//						pktCount.getAndIncrement(),
//						hdr.captureLength(),
//						new Timestamp(hdr.toEpochMilli()),
//						HexStrings.toHexDump(packet, 0, len));
//			}, "");
//
//			pcap.dispatchBuffer(COUNT, (String user, PcapHeader hdr, ByteBuffer packet) -> {
//				int len = hdr.captureLength() < 64 ? hdr.captureLength() : 64;
//				System.out.printf("#%03d ::dispatchBuffer caplen=%s bytes, ts=%s, dump:%n%s",
//						pktCount.getAndIncrement(),
//						hdr.captureLength(),
//						new Timestamp(hdr.toEpochMilli()),
//						HexStrings.toHexDump(packet.limit(len)));
//			}, "");
//
//			pcap.dispatchSegment(COUNT, (String user, MemorySegment hdr, MemorySegment data) -> {
//				System.out.printf("#%03d ::dispatchSegment hdr=%s bytes, data=%s bytes%n",
//						pktCount.getAndIncrement(),
//						hdr.byteSize(),
//						data.byteSize());
//			}, "");

		} catch (PcapException e) {
			e.printStackTrace();
		}
	}

}
