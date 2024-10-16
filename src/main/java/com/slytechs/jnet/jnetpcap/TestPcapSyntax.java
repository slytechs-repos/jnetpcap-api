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

import com.slytechs.jnet.jnetpcap.NativePacketPipeline.NativePacketPipe;
import com.slytechs.jnet.jnetpcap.NativePacketPipeline.NativeProcessorContext;
import com.slytechs.jnet.jnetpcap.RawPacketPipeline.RawPacketPipe;
import com.slytechs.jnet.jnetpcap.RawPacketPipeline.RawProcessorContext;
import com.slytechs.jnet.jnetruntime.NotFound;
import com.slytechs.jnet.jnetruntime.pipeline.PeekProcessor;
import com.slytechs.jnet.jnetruntime.time.Timestamp;
import com.slytechs.jnet.jnetruntime.util.HexStrings;

/**
 * @author Mark Bednarczyk
 *
 */
public class TestPcapSyntax {

	public TestPcapSyntax() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * @param args
	 * @throws NotFound
	 * @throws IOException
	 */
	public static void main(String[] args) throws NotFound, IOException {
		final File FILE = new File("pcaps/HTTP.cap");
		final AtomicInteger pktCount = new AtomicInteger(1);
		
		final int COUNT = 1;

		try (var pcap = NetPcap2.openOffline(FILE)) {

//			if (true)
//				return;

			pcap.addProcessor(0, PeekProcessor::new, NativePacketPipe.class)
					.peek((MemorySegment h, MemorySegment d, NativeProcessorContext ctx) -> {
						System.out.printf("#%03d: peek::NativePacketPipe(h=%s bytes, data=%s bytes)%n",
								pktCount.getAndIncrement(),
								h.byteSize(),
								d.byteSize());
					});

			pcap.addProcessor(0, PeekProcessor::new, RawPacketPipe.class)
					.peek((PcapHeader h, MemorySegment d, RawProcessorContext ctx) -> {
						System.out.printf("#%03d: peek::RawPacketPipe(hdr=%s, data=%s)%n",
								pktCount.getAndIncrement(),
								h.toString(),
								d.byteSize());
					});

//			System.out.println("TestPcapSyntax:: pcap.name=" + pcap.name());

//			pcap.setPromisc(true);
//			pcap.activate();

//			pcap.dispatchNative(2, (MemorySegment u, MemorySegment h, MemorySegment d) -> {
//				System.out.printf("dispatch::#%d h=%s, d=%s%n", pktCount.getAndIncrement(), h.byteSize(), d.byteSize());
//			}, MemorySegment.NULL);

//			pcap.dispatchPacket(5, (String user, Packet packet) -> {
//				System.out.println(packet);
//			}, "");

			pcap.dispatchArray(COUNT, (String user, PcapHeader hdr, byte[] packet) -> {
				System.out.printf("#%03d ::dispatchArray caplen=%s bytes, ts=%s, dump:%n%s",
						pktCount.getAndIncrement(),
						hdr.captureLength(),
						new Timestamp(hdr.toEpochMilli()),
						HexStrings.toHexDump(packet, 0, hdr.captureLength()));
			}, "");

			pcap.dispatchBuffer(COUNT, (String user, PcapHeader hdr, ByteBuffer packet) -> {
				System.out.printf("#%03d ::dispatchBuffer caplen=%s bytes, ts=%s, dump:%n%s",
						pktCount.getAndIncrement(),
						hdr.captureLength(),
						new Timestamp(hdr.toEpochMilli()),
						HexStrings.toHexDump(packet));
			}, "");

//			pcap.dispatchSegment(5, (String user, MemorySegment hdr, MemorySegment data) -> {
//				System.out.printf("dispatch:: h=%s, d=%s%n", hdr, data);
//			}, "");

		} catch (PcapException e) {
			e.printStackTrace();
		}
	}

}
