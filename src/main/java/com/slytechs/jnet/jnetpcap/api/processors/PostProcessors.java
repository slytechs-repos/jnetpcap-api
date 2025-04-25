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

import com.slytechs.jnet.jnetpcap.api.impl.PostPcapPipeline.PostContext;
import com.slytechs.jnet.platform.api.util.format.Detail;
import com.slytechs.jnet.protocol.api.common.Packet;

/**
 * 
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 */
public interface PostProcessors {

	int IPF_REASSEMBLER_PRIORITY = 0;

	/** Internal pipeline data handling interface, not ment to be used externally */
	public interface PostProcessor {
		void postProcessPacket(Packet packet, @SuppressWarnings("exports") PostContext postContext);
	}

	String toString(Detail detail);
}
