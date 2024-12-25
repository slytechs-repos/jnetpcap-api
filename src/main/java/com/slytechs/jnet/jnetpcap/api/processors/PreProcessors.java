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
package com.slytechs.jnet.jnetpcap.api.processors;

import java.lang.foreign.MemorySegment;

import com.slytechs.jnet.jnetpcap.api.internal.PrePcapPipeline.PreContext;
import com.slytechs.jnet.platform.api.data.common.processor.Processor;
import com.slytechs.jnet.platform.api.util.Detail;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public interface PreProcessors {

	int PACKET_PLAYER_PRIORITY = 0;
	int PACKET_REPEATER_PRIORITY = 20;
	int DATA_OBFUSCATOR_PRIORITY = 30;
	int PACKET_PEEKER_PRIORITY = 40;
	int PACKET_REBUFFER_PRIORITY = 50;
	int PACKET_MIXER_PRIORITY = 60;
	int PACKET_DEDUPLICATOR_PRIORITY = 70;
	int PACKET_DROPPER_PRIORITY = 80;
	int PACKET_GENERATOR_PRIORITY = 90;
	int PACKET_DELAY_PRIORITY = 100;

	/** Internal pipeline data handling interface, not ment to be used externally */
	interface PreProcessor {
		long preProcessPacket(MemorySegment header, MemorySegment packet,
				@SuppressWarnings("exports") PreContext preContext);
	}

	Processor<PreProcessor> addProcessor(Processor<PreProcessor> newProcessor);

	default Processor<PreProcessor> addProcessor(int priority, Processor<PreProcessor> newProcessor) {
		return addProcessor(newProcessor.setPriority(priority));
	}

	String toString(Detail detail);
}
