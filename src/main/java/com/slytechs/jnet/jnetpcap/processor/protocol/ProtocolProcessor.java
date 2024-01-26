/*
 * Sly Technologies Free License
 * 
 * Copyright 2023 Sly Technologies Inc.
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
package com.slytechs.jnet.jnetpcap.processor.protocol;

import com.slytechs.jnet.jnetpcap.NetPcapHandler.OfPacket;
import com.slytechs.jnet.jnetpcap.NetPcapHandler.OfPacketConsumer;
import com.slytechs.jnet.jnetpcap.processor.Processor;

public interface ProtocolProcessor extends Processor {

	<U> ProtocolProcessor peek(OfPacket<U> packet, U userData);

	<U> ProtocolProcessor forEach(OfPacket<U> packet, U userData);

	<U> ProtocolProcessor peek(OfPacketConsumer packet);

	<U> ProtocolProcessor forEach(OfPacketConsumer packet);

}