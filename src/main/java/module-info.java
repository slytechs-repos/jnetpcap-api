/*
 * Apache License, Version 2.0
 * 
 * Copyright 2013-2022 Sly Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
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
 * @author Mark Bednarczyk
 * @author Sly Technologies Inc.
 * @author repos@slytechs.com
 *
 */
module com.slytechs.jnetpcap.pro {
	exports com.slytechs.jnetpcap.pro;

	requires transitive org.jnetpcap;
	requires transitive com.slytechs.protocol;
}