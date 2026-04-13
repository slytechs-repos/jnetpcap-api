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

/**
 * Provides packet dissection and IP fragment reassembly services.
 * 
 * @author Mark Bednarczyk.
 */
module com.slytechs.sdk.jnetpcap.api {
	exports com.slytechs.sdk.jnetpcap.api;

	opens com.slytechs.jnet.jnetpcap.api.foreign
			to com.slytechs.sdk.common;

	requires transitive com.slytechs.sdk.jnetpcap;
	requires transitive com.slytechs.sdk.protocol.core;
	requires transitive com.slytechs.sdk.protocol.tcpip;
	requires transitive com.slytechs.sdk.common;
	requires lexactivator;

}