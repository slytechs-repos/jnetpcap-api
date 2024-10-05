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

import java.lang.foreign.MemorySegment;

import org.jnetpcap.PcapException;

import com.slytechs.jnet.jnetruntime.NotFound;

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
	 */
	public static void main(String[] args) {

		try (var pcap = new NetPcap2()) {

			System.out.println("TestPcapSyntax:: name=" + pcap.name());

			pcap.activate();

			pcap.dispatch(5, (MemorySegment u, MemorySegment h, MemorySegment d) -> {
				System.out.printf("u=%s, h=%s, d=%s%n", u, h, d);
			}, MemorySegment.NULL);

		} catch (PcapException | NotFound e) {
			e.printStackTrace();
		}
	}

}
