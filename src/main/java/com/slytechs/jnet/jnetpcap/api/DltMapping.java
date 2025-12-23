/*
 * Sly Technologies Free License
 * 
 * Copyright 2025 Sly Technologies Inc.
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
package com.slytechs.jnet.jnetpcap.api;

import com.slytechs.sdk.jnetpcap.constant.PcapDlt;

/**
 * Maps pcap DLT (Data Link Type) values to L2 frame type constants.
 * 
 * <p>
 * This class provides a one-way mapping from libpcap's DLT values to the
 * protocol-api's L2FrameType constants. It is intentionally standalone with
 * no dependencies on protocol-api to keep the jnetpcap-wrapper module
 * independent.
 * </p>
 * 
 * <h2>Usage</h2>
 * <pre>{@code
 * int dlt = pcap.datalink();
 * int l2Type = DltMapping.toL2FrameType(dlt);
 * descriptor.setL2FrameType(l2Type);
 * }</pre>
 * 
 * <h2>DLT Sources</h2>
 * <ul>
 *   <li><a href="https://www.tcpdump.org/linktypes.html">tcpdump.org link types</a></li>
 *   <li>pcap/dlt.h from libpcap source</li>
 * </ul>
 *
 * @author Mark Bednarczyk [mark@slytechs.com]
 * @author Sly Technologies Inc.
 * @see PcapDlt
 */
public final class DltMapping {

    private DltMapping() {
        // Static utility class
    }

    // ════════════════════════════════════════════════════════════════════════════
    // L2FrameType Constants (duplicated to avoid module dependency)
    // These MUST match com.slytechs.sdk.protocol.core.L2FrameType
    // ════════════════════════════════════════════════════════════════════════════

    // @formatter:off
    
    // Common (0x00-0x0F)
    private static final int L2_UNKNOWN          = 0x00;
    private static final int L2_ETHER            = 0x01;
    private static final int L2_PPP              = 0x02;
    private static final int L2_SLL              = 0x03;
    private static final int L2_SLL2             = 0x04;
    private static final int L2_LOOPBACK         = 0x05;
    private static final int L2_RAW_IP4          = 0x06;
    private static final int L2_RAW_IP6          = 0x07;
    private static final int L2_PPP_HDLC         = 0x08;
    private static final int L2_CHDLC            = 0x09;
    private static final int L2_PPPOE            = 0x0A;

    // Wireless (0x10-0x1F)
    private static final int L2_IEEE80211           = 0x10;
    private static final int L2_IEEE80211_RADIOTAP  = 0x11;
    private static final int L2_IEEE80211_AVS       = 0x12;
    private static final int L2_IEEE80211_PRISM     = 0x13;
    private static final int L2_IEEE80211_PPI       = 0x14;

    // Linux-specific (0x20-0x2F)
    private static final int L2_NETLINK          = 0x20;
    private static final int L2_NFLOG            = 0x21;
    private static final int L2_NFQUEUE          = 0x22;
    private static final int L2_LINUX_CAN        = 0x23;
    private static final int L2_LINUX_USB        = 0x24;
    private static final int L2_LINUX_USB_MM     = 0x25;
    private static final int L2_VSOCK            = 0x26;
    private static final int L2_LAPD             = 0x27;

    // Legacy (0x30-0x3F)
    private static final int L2_FDDI             = 0x30;
    private static final int L2_TOKEN_RING       = 0x31;
    private static final int L2_ARCNET           = 0x32;
    private static final int L2_ATM              = 0x33;
    private static final int L2_FRELAY           = 0x34;
    private static final int L2_SLIP             = 0x35;
    private static final int L2_CHAOS            = 0x36;

    // Specialty (0x40-0x4F)
    private static final int L2_BLUETOOTH_HCI    = 0x40;
    private static final int L2_BLUETOOTH_LE     = 0x41;
    private static final int L2_BLUETOOTH_MON    = 0x42;
    private static final int L2_IPOIB            = 0x43;
    private static final int L2_DOCSIS           = 0x44;

    // BSD (0x50-0x5F)
    private static final int L2_PFLOG            = 0x50;
    private static final int L2_PFSYNC           = 0x51;
    private static final int L2_ENC              = 0x52;

    // IoT (0x60-0x6F)
    private static final int L2_IEEE802_15_4     = 0x60;
    private static final int L2_IEEE802_15_4_TAP = 0x61;
    private static final int L2_AX25             = 0x62;
    private static final int L2_DECT             = 0x63;

    // @formatter:on

    // ════════════════════════════════════════════════════════════════════════════
    // DLT Constants (from pcap/dlt.h and tcpdump.org)
    // ════════════════════════════════════════════════════════════════════════════

    // @formatter:off
    
    // Common DLTs
    private static final int DLT_NULL            = 0;
    private static final int DLT_EN10MB          = 1;     // Ethernet
    private static final int DLT_IEEE802         = 6;     // Token Ring
    private static final int DLT_ARCNET          = 7;
    private static final int DLT_SLIP            = 8;
    private static final int DLT_PPP             = 9;
    private static final int DLT_FDDI            = 10;
    private static final int DLT_ATM_RFC1483     = 11;
    private static final int DLT_RAW             = 12;    // Raw IP (BSD)
    private static final int DLT_PPP_SERIAL      = 50;    // PPP over serial (HDLC-like)
    private static final int DLT_PPP_ETHER       = 51;    // PPPoE
    private static final int DLT_C_HDLC          = 104;   // Cisco HDLC
    private static final int DLT_IEEE802_11      = 105;   // 802.11 native
    private static final int DLT_FRELAY          = 107;   // Frame Relay
    private static final int DLT_LOOP            = 108;   // OpenBSD loopback
    private static final int DLT_LINUX_SLL       = 113;   // Linux cooked v1
    private static final int DLT_LTALK           = 114;   // LocalTalk
    private static final int DLT_PFLOG           = 117;   // OpenBSD pflog
    private static final int DLT_PRISM_HEADER    = 119;   // Prism monitor
    private static final int DLT_AIRONET_HEADER  = 120;   // Aironet
    private static final int DLT_IP_OVER_FC      = 122;   // IP over Fibre Channel
    private static final int DLT_IEEE802_11_RADIO = 127;  // Radiotap
    private static final int DLT_ARCNET_LINUX    = 129;   // ARCNET (Linux)
    private static final int DLT_LINUX_IRDA      = 144;   // Linux IrDA
    private static final int DLT_LINUX_LAPD      = 177;   // Linux LAPD
    private static final int DLT_RAW_ALT         = 101;   // Raw IP (some systems)
    private static final int DLT_RAW_LINUX       = 228;   // Raw IP (Linux)
    private static final int DLT_RAW_OPENBSD     = 14;    // Raw IP (OpenBSD)

    // Bluetooth
    private static final int DLT_BLUETOOTH_HCI_H4      = 187;
    private static final int DLT_BLUETOOTH_HCI_H4_PHDR = 201;
    private static final int DLT_BLUETOOTH_LE_LL      = 251;
    private static final int DLT_BLUETOOTH_LE_LL_PHDR = 256;
    private static final int DLT_BLUETOOTH_LINUX_MONITOR = 254;

    // Linux USB
    private static final int DLT_USB_LINUX       = 189;
    private static final int DLT_USB_LINUX_MMAPPED = 220;

    // Netfilter
    private static final int DLT_NFLOG           = 239;
    private static final int DLT_NETLINK         = 253;

    // CAN
    private static final int DLT_CAN_SOCKETCAN   = 227;

    // BSD
    private static final int DLT_ENC             = 109;
    private static final int DLT_PFSYNC          = 246;

    // 802.11 variants
    private static final int DLT_IEEE802_11_RADIO_AVS = 163;
    private static final int DLT_PPI             = 192;

    // 802.15.4 (ZigBee)
    private static final int DLT_IEEE802_15_4    = 195;
    private static final int DLT_IEEE802_15_4_WITHFCS = 230;
    private static final int DLT_IEEE802_15_4_TAP = 283;

    // Misc
    private static final int DLT_AX25            = 3;
    private static final int DLT_CHAOS           = 5;
    private static final int DLT_INFINIBAND      = 247;
    private static final int DLT_DOCSIS          = 143;
    private static final int DLT_VSOCK           = 271;
    private static final int DLT_DECT            = 172;

    // Linux cooked v2
    private static final int DLT_LINUX_SLL2      = 276;
    
    // @formatter:on

    // ════════════════════════════════════════════════════════════════════════════
    // Mapping Methods
    // ════════════════════════════════════════════════════════════════════════════

    /**
     * Converts a pcap DLT value to an L2FrameType constant.
     *
     * @param dlt the pcap datalink type value
     * @return the corresponding L2FrameType constant, or L2_UNKNOWN if not mapped
     */
    public static int toL2FrameType(int dlt) {
        return switch (dlt) {
            // Common
            case DLT_NULL, DLT_LOOP              -> L2_LOOPBACK;
            case DLT_EN10MB                      -> L2_ETHER;
            case DLT_PPP                         -> L2_PPP;
            case DLT_PPP_SERIAL                  -> L2_PPP_HDLC;
            case DLT_PPP_ETHER                   -> L2_PPPOE;
            case DLT_C_HDLC                      -> L2_CHDLC;
            case DLT_LINUX_SLL                   -> L2_SLL;
            case DLT_LINUX_SLL2                  -> L2_SLL2;

            // Raw IP (multiple DLT values map to same type)
            case DLT_RAW, DLT_RAW_ALT,
                 DLT_RAW_LINUX, DLT_RAW_OPENBSD  -> L2_RAW_IP4;

            // Legacy
            case DLT_IEEE802                     -> L2_TOKEN_RING;
            case DLT_ARCNET, DLT_ARCNET_LINUX    -> L2_ARCNET;
            case DLT_SLIP                        -> L2_SLIP;
            case DLT_FDDI                        -> L2_FDDI;
            case DLT_ATM_RFC1483                 -> L2_ATM;
            case DLT_FRELAY                      -> L2_FRELAY;
            case DLT_CHAOS                       -> L2_CHAOS;

            // Wireless
            case DLT_IEEE802_11                  -> L2_IEEE80211;
            case DLT_IEEE802_11_RADIO            -> L2_IEEE80211_RADIOTAP;
            case DLT_IEEE802_11_RADIO_AVS        -> L2_IEEE80211_AVS;
            case DLT_PRISM_HEADER                -> L2_IEEE80211_PRISM;
            case DLT_PPI                         -> L2_IEEE80211_PPI;

            // Linux specific
            case DLT_NETLINK                     -> L2_NETLINK;
            case DLT_NFLOG                       -> L2_NFLOG;
            case DLT_CAN_SOCKETCAN               -> L2_LINUX_CAN;
            case DLT_USB_LINUX                   -> L2_LINUX_USB;
            case DLT_USB_LINUX_MMAPPED           -> L2_LINUX_USB_MM;
            case DLT_VSOCK                       -> L2_VSOCK;
            case DLT_LINUX_LAPD                  -> L2_LAPD;

            // BSD specific
            case DLT_PFLOG                       -> L2_PFLOG;
            case DLT_PFSYNC                      -> L2_PFSYNC;
            case DLT_ENC                         -> L2_ENC;

            // Bluetooth
            case DLT_BLUETOOTH_HCI_H4,
                 DLT_BLUETOOTH_HCI_H4_PHDR       -> L2_BLUETOOTH_HCI;
            case DLT_BLUETOOTH_LE_LL,
                 DLT_BLUETOOTH_LE_LL_PHDR        -> L2_BLUETOOTH_LE;
            case DLT_BLUETOOTH_LINUX_MONITOR     -> L2_BLUETOOTH_MON;

            // Specialty
            case DLT_INFINIBAND                  -> L2_IPOIB;
            case DLT_DOCSIS                      -> L2_DOCSIS;

            // IoT
            case DLT_IEEE802_15_4,
                 DLT_IEEE802_15_4_WITHFCS        -> L2_IEEE802_15_4;
            case DLT_IEEE802_15_4_TAP            -> L2_IEEE802_15_4_TAP;
            case DLT_AX25                        -> L2_AX25;
            case DLT_DECT                        -> L2_DECT;

            default                              -> L2_UNKNOWN;
        };
    }

    /**
     * Checks if the given DLT value has a known mapping.
     *
     * @param dlt the pcap datalink type value
     * @return true if a mapping exists
     */
    public static boolean isKnown(int dlt) {
        return toL2FrameType(dlt) != L2_UNKNOWN;
    }

    /**
     * Returns the L2FrameType name for a DLT value.
     *
     * @param dlt the pcap datalink type value
     * @return the L2FrameType name, or "UNKNOWN" if not mapped
     */
    public static String l2Name(int dlt) {
        int l2 = toL2FrameType(dlt);
        return switch (l2) {
            case L2_UNKNOWN          -> "UNKNOWN";
            case L2_ETHER            -> "ETHER";
            case L2_PPP              -> "PPP";
            case L2_SLL              -> "SLL";
            case L2_SLL2             -> "SLL2";
            case L2_LOOPBACK         -> "LOOPBACK";
            case L2_RAW_IP4          -> "RAW_IP4";
            case L2_RAW_IP6          -> "RAW_IP6";
            case L2_PPP_HDLC         -> "PPP_HDLC";
            case L2_CHDLC            -> "CHDLC";
            case L2_PPPOE            -> "PPPOE";
            case L2_IEEE80211        -> "IEEE80211";
            case L2_IEEE80211_RADIOTAP -> "IEEE80211_RADIOTAP";
            case L2_IEEE80211_AVS    -> "IEEE80211_AVS";
            case L2_IEEE80211_PRISM  -> "IEEE80211_PRISM";
            case L2_IEEE80211_PPI    -> "IEEE80211_PPI";
            case L2_NETLINK          -> "NETLINK";
            case L2_NFLOG            -> "NFLOG";
            case L2_LINUX_CAN        -> "LINUX_CAN";
            case L2_LINUX_USB        -> "LINUX_USB";
            case L2_LINUX_USB_MM     -> "LINUX_USB_MM";
            case L2_VSOCK            -> "VSOCK";
            case L2_LAPD             -> "LAPD";
            case L2_FDDI             -> "FDDI";
            case L2_TOKEN_RING       -> "TOKEN_RING";
            case L2_ARCNET           -> "ARCNET";
            case L2_ATM              -> "ATM";
            case L2_FRELAY           -> "FRELAY";
            case L2_SLIP             -> "SLIP";
            case L2_BLUETOOTH_HCI    -> "BLUETOOTH_HCI";
            case L2_BLUETOOTH_LE     -> "BLUETOOTH_LE";
            case L2_BLUETOOTH_MON    -> "BLUETOOTH_MON";
            case L2_IPOIB            -> "IPOIB";
            case L2_DOCSIS           -> "DOCSIS";
            case L2_PFLOG            -> "PFLOG";
            case L2_PFSYNC           -> "PFSYNC";
            case L2_ENC              -> "ENC";
            case L2_IEEE802_15_4     -> "IEEE802_15_4";
            case L2_IEEE802_15_4_TAP -> "IEEE802_15_4_TAP";
            case L2_AX25             -> "AX25";
            case L2_DECT             -> "DECT";
            default                  -> "UNKNOWN(0x" + Integer.toHexString(l2) + ")";
        };
    }
}