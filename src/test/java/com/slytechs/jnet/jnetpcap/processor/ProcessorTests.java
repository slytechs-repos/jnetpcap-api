/*
 * Copyright 2024 Sly Technologies Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.slytechs.jnet.jnetpcap.processor;

import org.jnetpcap.PcapException;
import org.jnetpcap.windows.WinPcap;
import org.junit.jupiter.api.Test;

import com.slytechs.jnet.jnetpcap.IpfReassembler;
import com.slytechs.jnet.jnetpcap.NetPcap;
import com.slytechs.jnet.jnetpcap.PacketPlayer;
import com.slytechs.jnet.jnetpcap.PacketRepeater;
import com.slytechs.jnet.protocol.core.TcpIpProtocolFamily;

/**
 * @author Sly Technologies Inc
 * @author repos@slytechs.com
 *
 */
class ProcessorTests {

	/** Location of the test resources directory */
	private static final String RESOURCES_DIR = "src/test/resources";

	@Test
	void testBaseProcessorSetup() throws PcapException {
		final String FILE = RESOURCES_DIR + "/HTTP.cap";

		try (var pcap = NetPcap.openOffline(WinPcap::openOffline, FILE)) {

			/**
			 * <pre>
			 * + PcapPipeline
			 * 	 + ProtocolPipeline
			 * 		+ TcpIpProtocolFamily
			 * 		+ QuicProtocolFamily
			 * 		+ HttpProtocolFamily
			 * </pre>
			 */
			try (var stack = pcap.protocolStack()) {
				
				TcpIpProtocolFamily tcpIp = stack.installPipeline(TcpIpProtocolFamily::new);
				
				tcpIp.install(IpfReassembler::new)
					.forEach(p -> {});
				
				stack.install(PacketPlayer::new);

				stack.install(PacketRepeater::new)
						.repeatCount(10)
						.forEach((user, header, packet) -> System.out.println(packet));

				stack.install(IpfReassembler::new)
						.forEach(System.out::println);
			}

		}

	}

}
