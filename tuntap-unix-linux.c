/*
 * Copyright (c) 2012 Tristan Le Guern <leguern AT medu DOT se>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tuntap.h"

int
tuntap_sys_start(struct device *dev, int mode, int tun) {
	int fd;
	int persist;
	char *ifname;
	struct ifreq ifr;

	fd = -1;
	persist = 0;
	if ((fd = open("/dev/net/tun", O_RDWR)) == -1) {
		tuntap_log(0, "libtuntap (sys): open /dev/net/tun");
		return -1;
	}

	(void)memset(&ifr, '\0', sizeof ifr);

	if (mode & TUNTAP_MODE_PERSIST) {
		mode &= ~TUNTAP_MODE_PERSIST;
		persist = 1;
	}

        /* Set the mode: tun or tap */
	if (mode == TUNTAP_MODE_ETHERNET) {
		ifr.ifr_flags = IFF_TAP;
		ifname = "tap%i";
	} else if (mode == TUNTAP_MODE_TUNNEL) {
		ifr.ifr_flags = IFF_TUN;
		ifname = "tun%i";
	} else {
		return -1;
	}
	ifr.ifr_flags |= IFF_NO_PI;

	/* Configure the interface */
	if (ioctl(fd, TUNSETIFF, &ifr) == -1) {
		tuntap_log(0, "libtuntap (sys): ioctl TUNSETIFF");
		return -1;
	}

	/* Set it persistent if needed */
	if (persist == 1) {
		if (ioctl(fd, TUNSETPERSIST, &ifr) == -1) {
        		(void)fprintf(stderr, "libtuntap (sys): "
			    "failed to set persistent\n");
			return -1;
		}
        }

	/* Set the interface name, if any */
	if (tun != TUNTAP_ID_ANY) {
		if (fd > TUNTAP_ID_MAX) {
			return -1;
		}
		(void)snprintf(ifr.ifr_name, sizeof ifr.ifr_name,
		    ifname, tun);
	}

	/* Get the internal parameters of ifr */
	if (ioctl(dev->ctrl_sock, SIOCGIFFLAGS, &ifr) == -1) {
		tuntap_log(0, "libtuntap (sys): ioctl SIOCGIFFLAGS");
	    	return -1;
	}

	/* Save flags for tuntap_{up, down} */
	dev->flags = ifr.ifr_flags;

	/* Save the interface name */
	(void)memcpy(dev->if_name, ifr.ifr_name, sizeof ifr.ifr_name);

	/* Save pre-existing MAC address */
	if (mode == TUNTAP_MODE_ETHERNET) {
		struct ifreq ifr_hw;

		(void)memcpy(ifr_hw.ifr_name, dev->if_name,
		    sizeof(dev->if_name));
		if (ioctl(fd, SIOCGIFHWADDR, &ifr_hw) == -1) {
			tuntap_log(0, "libtuntap (sys): ioctl SIOCGIFHWADDR\n");
			return -1;
		}
		(void)memcpy(dev->hwaddr, ifr_hw.ifr_hwaddr.sa_data, ETH_ALEN);
	}
	return fd;
}

void
tuntap_sys_destroy(struct device *dev) {
	/* Linux automatically remove unused interface */
	(void)dev;
}

int
tuntap_sys_set_hwaddr(struct device *dev, struct ether_addr *eth_addr) {
	struct ifreq ifr;

	(void)memset(&ifr, '\0', sizeof ifr);
	(void)memcpy(ifr.ifr_name, dev->if_name, sizeof dev->if_name);

	ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
	(void)memcpy(ifr.ifr_hwaddr.sa_data, eth_addr->ether_addr_octet, 6);

	/* Linux has a special flag for setting the MAC address */
	if (ioctl(dev->ctrl_sock, SIOCSIFHWADDR, &ifr) == -1) {
		tuntap_log(0, "libtuntap (sys): ioctl SIOCSIFHWADDR");
		return -1;
	}
	return 0;
}

int
tuntap_sys_set_ipv4(struct device *dev, struct sockaddr_in *s4, uint32_t bits) {
	struct ifreq ifr;
	struct sockaddr_in mask;

	(void)memset(&ifr, '\0', sizeof ifr);
	(void)memcpy(ifr.ifr_name, dev->if_name, sizeof dev->if_name);

	/* Set the IP address first */
	(void)memcpy(&ifr.ifr_addr, s4, sizeof ifr.ifr_addr);
	if (ioctl(dev->ctrl_sock, SIOCSIFADDR, &ifr) == -1) {
		tuntap_log(0, "libtuntap (sys): ioctl SIOCSIFADDR");
		return -1;
	}
	
	/* Reinit the struct ifr */
	(void)memset(&ifr.ifr_addr, '\0', sizeof ifr.ifr_addr);

	/* Then set the netmask */
	(void)memset(&mask, '\0', sizeof mask);
	mask.sin_family = AF_INET;
	mask.sin_addr.s_addr = bits;
	(void)memcpy(&ifr.ifr_netmask, &mask, sizeof ifr.ifr_netmask);
	if (ioctl(dev->ctrl_sock, SIOCSIFNETMASK, &ifr) == -1) {
		tuntap_log(0, "libtuntap (sys): ioctl SIOCSIFNETMASK");
		return -1;
	}

	return 0;
}

int
tuntap_sys_set_ipv6(struct device *dev, struct sockaddr_in6 *s6, uint32_t bits) {
	(void)dev;
	(void)s6;
	(void)bits;
	tuntap_log(0, "libtuntap (sys): ipv6 not implemented");
	return -1;
}
