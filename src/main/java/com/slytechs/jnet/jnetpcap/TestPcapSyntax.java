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
import java.lang.foreign.MemorySegment;
import java.nio.ByteBuffer;

import org.jnetpcap.PcapException;
import org.jnetpcap.PcapHeader;

import com.slytechs.jnet.jnetpcap.NativePacketPipeline.NativePacketPipe;
import com.slytechs.jnet.jnetruntime.NotFound;
import com.slytechs.jnet.jnetruntime.pipeline.PeekProcessor;
import com.slytechs.jnet.protocol.Packet;

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
	 */
	public static void main(String[] args) throws NotFound {
		final File FILE = new File("/Users/mark/pcaps/200722_tcp_anon.pcapng");

		try (var pcap = new NetPcap2(FILE)) {

			pcap.addProcessor(0, PeekProcessor::new, NativePacketPipe.class)
					.peek((h, d, ctx) -> System.out.printf("peek:: h=%s, d=%s%n", h, d));

			System.out.println("TestPcapSyntax:: name=" + pcap.name());

//			pcap.setPromisc(true);
//			pcap.activate();

			pcap.dispatchNative(5, (MemorySegment u, MemorySegment h, MemorySegment d) -> {
				System.out.printf("dispatch:: h=%s, d=%s%n", h, d);
			}, MemorySegment.NULL);
			
			pcap.dispatchPacket(5, (String user, Packet packet) -> {
				System.out.println(packet);
			}, "");
			
			pcap.dispatchArray(5, (String user, PcapHeader hdr, byte[] packet) -> {
				System.out.println(hdr);
			}, "");
			
			pcap.dispatchBuffer(5, (String user, PcapHeader hdr, ByteBuffer packet) -> {
				System.out.println(hdr);
			}, "");
			
			pcap.dispatchSegment(5, (String user, MemorySegment hdr, MemorySegment data) -> {
				System.out.printf("dispatch:: h=%s, d=%s%n", hdr, data);
			}, "");

		} catch (PcapException e) {
			e.printStackTrace();
		}
	}

}
