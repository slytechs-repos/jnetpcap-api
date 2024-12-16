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
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.concurrent.TimeUnit;

/**
 * @author Mark Bednarczyk
 */
class PcapUtils {

	public static void checkFileExists(File file) throws FileNotFoundException {
		if (!file.exists())
			throw new FileNotFoundException("File does not exist: " + file.getPath());
	}

	public static void checkFileCanRead(File file) throws FileNotFoundException, IOException {
		checkFileExists(file);

		if (!file.canRead())
			throw new IOException("File is not readable: " + file.getPath());
	}

	public static void checkFileCanWrite(File file) throws IOException {
		if (!file.canWrite())
			throw new IOException("File is not writable: " + file.getPath());
	}

	public static final String shortName(String name) {
		if (name.contains("/")) {
			String[] c = name.split("\\/");
			name = c[c.length - 1];
		}

		return name;
	}

	/**
	 * Delay.
	 * 
	 * @throws InterruptedException
	 */
	public static void delay(long minIfgNano) throws InterruptedException {
		final long MIN_BLOCK = 150_000_000;
		long start = System.nanoTime();
		long end = start + minIfgNano;

		long remaining = end - start;
		do {
			remaining = end - start;

			if (remaining > MIN_BLOCK)
				delayBlock(end);
			else
				delaySpin(end);

		} while (remaining > 0);
	}

	/**
	 * Delay spin.
	 *
	 * @param endNanoTime the end nano time
	 */
	public static void delaySpin(long endNanoTime) {
		while (System.nanoTime() < endNanoTime);
	}

	/**
	 * Delay block.
	 *
	 * @param endNanoTime the end nano time
	 * @throws InterruptedException the interrupted exception
	 */
	public static void delayBlock(long endNanoTime) throws InterruptedException {
		TimeUnit.NANOSECONDS.sleep(endNanoTime - System.nanoTime());
	}

	private PcapUtils() {
	}

}
