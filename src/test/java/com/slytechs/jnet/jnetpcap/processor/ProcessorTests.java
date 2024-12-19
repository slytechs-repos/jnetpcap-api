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

import java.io.FileNotFoundException;
import java.io.IOException;

import org.jnetpcap.PcapException;
import org.junit.jupiter.api.Test;

import com.slytechs.jnet.jnetpcap.api.NetPcap;

/**
 * The Class ProcessorTests.
 *
 * @author Mark Bednarczyk
 */
class ProcessorTests {

	/** Location of the test resources directory. */
	private static final String RESOURCES_DIR = "src/test/resources";

	/**
	 * Test base processor setup.
	 *
	 * @throws PcapException         the pcap exception
	 * @throws IOException
	 * @throws FileNotFoundException
	 */
	@Test
	void testBaseProcessorSetup() throws PcapException, FileNotFoundException, IOException {
		final String FILE = RESOURCES_DIR + "/HTTP.cap";

		try (var pcap = NetPcap.offline(FILE)) {

			/**
			 * <pre>
			 * +PrePcapPipeline
			 * 		+ ProtocolPipeline
			 * 		+ TcpIpProtocolFamily
			 * 		+ QuicProtocolFamily
			 * 		+ HttpProtocolFamily
			 * </pre>
			 */
//			try (var stack = pcap.protocolStack()) {
//				
//				TcpIpProtocolFamily tcpIp = stack.installPipeline(TcpIpProtocolFamily::new);
//				
//				tcpIp.install(IpfReassembler::new)
//					.forEach(p -> {});
//				
//				stack.install(PacketPlayer::new);
//
//				stack.install(PacketRepeater::new)
//						.repeatCount(10)
//						.forEach((user, header, packet) -> System.out.println(packet));
//
//				stack.install(IpfReassembler::new)
//						.forEach(System.out::println);
//			}

		}

	}

}
