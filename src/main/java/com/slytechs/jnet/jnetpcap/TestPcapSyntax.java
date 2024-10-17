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
import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicInteger;

import org.jnetpcap.PcapException;
import org.jnetpcap.PcapHeader;

import com.slytechs.jnet.jnetpcap.NativePacketPipeline.NativeProcessorContext;
import com.slytechs.jnet.jnetpcap.NativePacketPipeline.StatefulNativePacket;
import com.slytechs.jnet.jnetpcap.RawPacketPipeline.RawProcessorContext;
import com.slytechs.jnet.jnetpcap.RawPacketPipeline.StatefulRawPacket;
import com.slytechs.jnet.jnetruntime.NotFound;
import com.slytechs.jnet.jnetruntime.pipeline.PeekProcessor;
import com.slytechs.jnet.jnetruntime.time.Timestamp;
import com.slytechs.jnet.jnetruntime.util.HexStrings;
import com.slytechs.jnet.protocol.HeaderNotFound;
import com.slytechs.jnet.protocol.Packet;
import com.slytechs.jnet.protocol.core.Ip4;

/**
 * @author Mark Bednarczyk
 *
 */
public class TestPcapSyntax {

	public TestPcapSyntax() {
	}

	public static void main(String[] args) throws NotFound, IOException {
		final File FILE = new File("pcaps/HTTP.cap");
		final AtomicInteger pktCount = new AtomicInteger(1);

		final int COUNT = 2;

		try (var pcap = NetPcap.openOffline(FILE)) {

			pcap.addProcessor(0, PeekProcessor::new, StatefulNativePacket.class)
					.peek((MemorySegment h, MemorySegment d, NativeProcessorContext ctx) -> {
						System.out.printf("#%03d ::peek:NativePacketPipe h=%s bytes, data=%s bytes%n",
								pktCount.getAndIncrement(),
								h.byteSize(),
								d.byteSize());
					});

			pcap.addProcessor(0, PeekProcessor::new, StatefulRawPacket.class)
					.peek((PcapHeader h, MemorySegment d, RawProcessorContext ctx) -> {
						System.out.printf("#%03d ::peek:RawPacketPipe hdr=%s, data=%s%n",
								pktCount.getAndIncrement(),
								h.toString(),
								d.byteSize());
					});

//			System.out.println("TestPcapSyntax:: pcap.name=" + pcap.name());

//			pcap.setPromisc(true);
//			pcap.activate();

			pcap.dispatchNative(2, (MemorySegment u, MemorySegment h, MemorySegment d) -> {
				System.out.printf("#%03d ::dispatchNative hdr=%s bytes, data=%s bytes%n",
						pktCount.getAndIncrement(),
						h.byteSize(),
						d.byteSize());
			}, MemorySegment.NULL);

			pcap.dispatchPacket(COUNT, (String user, Packet packet) -> {
				try {
					System.out.printf("#%03d ::dispatchPacket \"%s\"%n" + "%s%n",
							pktCount.getAndIncrement(),
							user,
							packet.getHeader(new Ip4()));

				} catch (HeaderNotFound e) {
					e.printStackTrace();
				}

			}, "Hello World");

			pcap.dispatchArray(COUNT, (String user, PcapHeader hdr, byte[] packet) -> {
				int len = hdr.captureLength() < 64 ? hdr.captureLength() : 64;
				System.out.printf("#%03d ::dispatchArray caplen=%s bytes, ts=%s, dump:%n%s",
						pktCount.getAndIncrement(),
						hdr.captureLength(),
						new Timestamp(hdr.toEpochMilli()),
						HexStrings.toHexDump(packet, 0, len));
			}, "");

			pcap.dispatchBuffer(COUNT, (String user, PcapHeader hdr, ByteBuffer packet) -> {
				int len = hdr.captureLength() < 64 ? hdr.captureLength() : 64;
				System.out.printf("#%03d ::dispatchBuffer caplen=%s bytes, ts=%s, dump:%n%s",
						pktCount.getAndIncrement(),
						hdr.captureLength(),
						new Timestamp(hdr.toEpochMilli()),
						HexStrings.toHexDump(packet.limit(len)));
			}, "");

			pcap.dispatchSegment(COUNT, (String user, MemorySegment hdr, MemorySegment data) -> {
				System.out.printf("#%03d ::dispatchSegment hdr=%s bytes, data=%s bytes%n",
						pktCount.getAndIncrement(),
						hdr.byteSize(),
						data.byteSize());
			}, "");

		} catch (PcapException e) {
			e.printStackTrace();
		}
	}

}
