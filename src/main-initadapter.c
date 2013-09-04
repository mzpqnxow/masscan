#include "masscan.h"
#include "logger.h"
#include "rawsock.h"


/***************************************************************************
 * Initialize the network adapter.
 *
 * This requires finding things like our IP address, MAC address, and router
 * MAC address. The user could configure these things manually instead.
 *
 * Note that we don't update the "static" configuration with the discovered
 * values, but instead return them as the "running" configuration. That's
 * so if we pause and resume a scan, autodiscovered values don't get saved
 * in the configuration file.
 ***************************************************************************/
int
masscan_initialize_adapter(struct Masscan *masscan,
    unsigned *r_adapter_ip,
    unsigned char *adapter_mac,
    unsigned char *router_mac)
{
    char *ifname;
    char ifname2[256];

    LOG(1, "initializing adapter\n");

    /*
     * ADAPTER/NETWORK-INTERFACE
     *
     * If no network interface was configured, we need to go hunt down
     * the best Interface to use. We do this by choosing the first
     * interface with a "default route" (aka. "gateway") defined
     */
    if (masscan->ifname && masscan->ifname[0])
        ifname = masscan->ifname;
    else {
        /* no adapter specified, so find a default one */
        int err;
        err = rawsock_get_default_interface(ifname2, sizeof(ifname2));
        if (err) {
            fprintf(stderr, "FAIL: could not determine default interface\n");
            fprintf(stderr, "FAIL:... try \"--interface ethX\"\n");
            return -1;
        } else {
            LOG(2, "auto-detected: interface=%s\n", ifname2);
        }
        ifname = ifname2;

    }

    /*
     * IP ADDRESS
     *
     * We need to figure out that IP address to send packets from. This
     * is done by queryin the adapter (or configured by user). If the
     * adapter doesn't have one, then the user must configure one.
     */
    *r_adapter_ip = masscan->adapter_ip;
    if (*r_adapter_ip == 0) {
        *r_adapter_ip = rawsock_get_adapter_ip(ifname);
        LOG(2, "auto-detected: adapter-ip=%u.%u.%u.%u\n",
            (*r_adapter_ip>>24)&0xFF,
            (*r_adapter_ip>>16)&0xFF,
            (*r_adapter_ip>> 8)&0xFF,
            (*r_adapter_ip>> 0)&0xFF
            );
    }
    if (*r_adapter_ip == 0) {
        fprintf(stderr, "FAIL: failed to detect IP of interface: \"%s\"\n", ifname);
        fprintf(stderr, "FAIL:... try something like \"--adapter-ip 192.168.100.5\"\n");
        return -1;
    }

    /*
     * MAC ADDRESS
     *
     * This is the address we send packets from. It actually doesn't really
     * matter what this address is, but to be a "responsible" citizen we
     * try to use the hardware address in the network card.
     */
    memcpy(adapter_mac, masscan->adapter_mac, 6);
    if (memcmp(adapter_mac, "\0\0\0\0\0\0", 6) == 0) {
        rawsock_get_adapter_mac(ifname, adapter_mac);
        LOG(2, "auto-detected: adapter-mac=%02x-%02x-%02x-%02x-%02x-%02x\n",
            adapter_mac[0],
            adapter_mac[1],
            adapter_mac[2],
            adapter_mac[3],
            adapter_mac[4],
            adapter_mac[5]
            );
    }
    if (memcmp(adapter_mac, "\0\0\0\0\0\0", 6) == 0) {
        fprintf(stderr, "FAIL: failed to detect MAC address of interface: \"%s\"\n", ifname);
        fprintf(stderr, "FAIL:... try something like \"--adapter-mac 00-11-22-33-44\"\n");
        return -1;
    }

    /*
     * START ADAPTER
     *
     * Once we've figured out which adapter to use, we now need to
     * turn it on.
     */
    masscan->adapter = rawsock_init_adapter(ifname, masscan->is_pfring, masscan->is_sendq);
    if (masscan->adapter == 0) {
        fprintf(stderr, "adapter[%s].init: failed\n", ifname);
        return -1;
    }
    LOG(3, "rawsock: ignoring transmits\n");
    rawsock_ignore_transmits(masscan->adapter, adapter_mac);
    LOG(3, "rawsock: initialization done\n");

    /*
     * ROUTER MAC ADDRESS
     *
     * NOTE: this is one of the least understood aspects of the code. We must
     * send packets to the local router, which means the MAC address (not
     * IP address) of the router.
     *
     * Note: in order to ARP the router, we need to first enable the libpcap
     * code above.
     */
    memcpy(router_mac, masscan->router_mac, 6);
    if (memcmp(router_mac, "\0\0\0\0\0\0", 6) == 0) {
        unsigned router_ipv4;
        int err;

        LOG(1, "rawsock: looking for default gateway\n");
        err = rawsock_get_default_gateway(ifname, &router_ipv4);
        if (err == 0) {
            LOG(2, "auto-detected: router-ip=%u.%u.%u.%u\n",
                (router_ipv4>>24)&0xFF,
                (router_ipv4>>16)&0xFF,
                (router_ipv4>> 8)&0xFF,
                (router_ipv4>> 0)&0xFF
                );

            arp_resolve_sync(
                    masscan->adapter,
                    *r_adapter_ip,
                    adapter_mac,
                    router_ipv4,
                    router_mac);

            if (memcmp(router_mac, "\0\0\0\0\0\0", 6) != 0) {
                LOG(2, "auto-detected: router-mac=%02x-%02x-%02x-%02x-%02x-%02x\n",
                    router_mac[0],
                    router_mac[1],
                    router_mac[2],
                    router_mac[3],
                    router_mac[4],
                    router_mac[5]
                    );
            }
        }
    }
    if (memcmp(router_mac, "\0\0\0\0\0\0", 6) == 0) {
        fprintf(stderr, "FAIL: failed to detect router for interface: \"%s\"\n", ifname);
        fprintf(stderr, "FAIL:... try something like \"--router-mac 66-55-44-33-22-11\"\n");
        return -1;
    }

    LOG(1, "adapter initialization done.\n");
    return 0;
}