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

import org.jnetpcap.PcapHandler.OfByteBuffer;

import com.slytechs.jnet.jnetruntime.pipeline.AbstractPipeline;

/**
 * The Class PcapPipeline.
 *
 * @author Mark Bednarczyk
 */
public final class PcapPipeline
		extends AbstractPipeline<OfByteBuffer<?>, PcapPipeline> {

	/** The Constant NAME. */
	public static final String NAME = "pcap-pipeline";

	/**
	 * Instantiates a new pcap pipeline.
	 */
	public PcapPipeline() {
		super(NAME, PcapDataType.PCAP_RAW_PACKET);
	}

}
