/*
    Read in the configuration for MASSCAN.

    Configuration parameters can be read either from the command-line
    or a configuration file. Long parameters of the --xxxx variety have
    the same name in both.

    Most of the code in this module is for 'nmap' options we don't support.
    That's because we support some 'nmap' options, and I wanted to give
    more feedback for some of them why they don't work as expected, such
    as reminding people that this is an asynchronous scanner.

*/
#include "masscan.h"
#include "masscan-version.h"
#include "ranges.h"
#include "range-file.h"     /* reads millions of IP addresss from a file */
#include "string_s.h"
#include "logger.h"
#include "proto-banner1.h"
#include "templ-payloads.h"
#include "templ-port.h"
#include "crypto-base64.h"
#include "vulncheck.h"
#include "masscan-app.h"
#include "unusedparm.h"
#include "read-service-probes.h"
#include "util-malloc.h"
#include <ctype.h>
#include <limits.h>

#ifdef WIN32
#include <direct.h>
#define getcwd _getcwd
#else
#include <unistd.h>
#endif

#ifndef min
#define min(a,b) ((a)<(b)?(a):(b))
#endif

#if defined(_MSC_VER)
#define strdup _strdup
#endif

static void masscan_echo(struct Masscan *masscan, FILE *fp, unsigned is_echo_all);


/***************************************************************************
 ***************************************************************************/
/*static struct Range top_ports_tcp[] = {
    {80, 80},{23, 23}, {443,443},{21,22},{25,25},{3389,3389},{110,110},
    {445,445},
};
static struct Range top_ports_udp[] = {
    {161, 161}, {631, 631}, {137,138},{123,123},{1434},{445,445},{135,135},
    {67,67},
};
static struct Range top_ports_sctp[] = {
    {7, 7},{9, 9},{20,22},{80,80},{179,179},{443,443},{1167,1167},
};*/

/***************************************************************************
 ***************************************************************************/
void
masscan_usage(void)
{
    printf("usage:\n");
    printf("masscan -p80,8000-8100 10.0.0.0/8 --rate=10000\n");
    printf(" scan some web ports on 10.x.x.x at 10kpps\n");
    printf("masscan --nmap\n");
    printf(" list those options that are compatible with nmap\n");
    printf("masscan -p80 10.0.0.0/8 --banners -oB <filename>\n");
    printf(" save results of scan in binary format to <filename>\n");
    printf("masscan --open --banners --readscan <filename> -oX <savefile>\n");
    printf(" read binary scan results in <filename> and save them as xml in <savefile>\n");
    exit(1);
}

/***************************************************************************
 ***************************************************************************/
static void
print_version()
{
    const char *cpu = "unknown";
    const char *compiler = "unknown";
    const char *compiler_version = "unknown";
    const char *os = "unknown";
    printf("\n");
    printf("Masscan version %s ( %s )\n", 
        MASSCAN_VERSION,
        "https://github.com/robertdavidgraham/masscan"
        );
    printf("Compiled on: %s %s\n", __DATE__, __TIME__);

#if defined(_MSC_VER)
    #if defined(_M_AMD64) || defined(_M_X64)
        cpu = "x86";
    #elif defined(_M_IX86)
        cpu = "x86";
    #elif defined (_M_ARM_FP)
        cpu = "arm";
    #endif

    {
        int msc_ver = _MSC_VER;

        compiler = "VisualStudio";

        if (msc_ver < 1500)
            compiler_version = "pre2008";
        else if (msc_ver == 1500)
            compiler_version = "2008";
        else if (msc_ver == 1600)
            compiler_version = "2010";
        else if (msc_ver == 1700)
            compiler_version = "2012";
        else if (msc_ver == 1800)
            compiler_version = "2013";
        else
            compiler_version = "post-2013";
    }


#elif defined(__GNUC__)
    compiler = "gcc";
    compiler_version = __VERSION__;

#if defined(i386) || defined(__i386) || defined(__i386__)
    cpu = "x86";
#endif

#if defined(__corei7) || defined(__corei7__)
    cpu = "x86-Corei7";
#endif

#endif

#if defined(WIN32)
    os = "Windows";
#elif defined(__linux__)
    os = "Linux";
#elif defined(__APPLE__)
    os = "Apple";
#elif defined(__MACH__)
    os = "MACH";
#elif defined(__FreeBSD__)
    os = "FreeBSD";
#elif defined(unix) || defined(__unix) || defined(__unix__)
    os = "Unix";
#endif

    printf("Compiler: %s %s\n", compiler, compiler_version);
    printf("OS: %s\n", os);
    printf("CPU: %s (%u bits)\n", cpu, (unsigned)(sizeof(void*))*8);

#if defined(GIT)
    printf("GIT version: %s\n", GIT);
#endif
}

/***************************************************************************
 ***************************************************************************/
static void
print_nmap_help(void)
{
    printf("Masscan (https://github.com/robertdavidgraham/masscan)\n"
"Usage: masscan [Options] -p{Target-Ports} {Target-IP-Ranges}\n"
"TARGET SPECIFICATION:\n"
"  Can pass only IPv4 address, CIDR networks, or ranges (non-nmap style)\n"
"  Ex: 10.0.0.0/8, 192.168.0.1, 10.0.0.1-10.0.0.254\n"
"  -iL <inputfilename>: Input from list of hosts/networks\n"
"  --exclude <host1[,host2][,host3],...>: Exclude hosts/networks\n"
"  --excludefile <exclude_file>: Exclude list from file\n"
"  --randomize-hosts: Randomize order of hosts (default)\n"
"HOST DISCOVERY:\n"
"  -Pn: Treat all hosts as online (default)\n"
"  -n: Never do DNS resolution (default)\n"
"SCAN TECHNIQUES:\n"
"  -sS: TCP SYN (always on, default)\n"
"SERVICE/VERSION DETECTION:\n"
"  --banners: get the banners of the listening service if available. The\n"
"    default timeout for waiting to recieve data is 30 seconds.\n"
"PORT SPECIFICATION AND SCAN ORDER:\n"
"  -p <port ranges>: Only scan specified ports\n"
"    Ex: -p22; -p1-65535; -p 111,137,80,139,8080\n"
"TIMING AND PERFORMANCE:\n"
"  --max-rate <number>: Send packets no faster than <number> per second\n"
"  --connection-timeout <number>: time in seconds a TCP connection will\n"
"    timeout while waiting for banner data from a port.\n"
"FIREWALL/IDS EVASION AND SPOOFING:\n"
"  -S/--source-ip <IP_Address>: Spoof source address\n"
"  -e <iface>: Use specified interface\n"
"  -g/--source-port <portnum>: Use given port number\n"
"  --ttl <val>: Set IP time-to-live field\n"
"  --spoof-mac <mac address/prefix/vendor name>: Spoof your MAC address\n"
"OUTPUT:\n"
"  --output-format <format>: Sets output to binary/list/unicornscan/json/ndjson/grepable/xml\n"
"  --output-file <file>: Write scan results to file. If --output-format is\n"
"     not given default is xml\n"
"  -oL/-oJ/-oD/-oG/-oB/-oX/-oU <file>: Output scan in List/JSON/nDjson/Grepable/Binary/XML/Unicornscan format,\n"
"     respectively, to the given filename. Shortcut for\n"
"     --output-format <format> --output-file <file>\n"
"  -v: Increase verbosity level (use -vv or more for greater effect)\n"
"  -d: Increase debugging level (use -dd or more for greater effect)\n"
"  --open: Only show open (or possibly open) ports\n"
"  --packet-trace: Show all packets sent and received\n"
"  --iflist: Print host interfaces and routes (for debugging)\n"
"  --append-output: Append to rather than clobber specified output files\n"
"  --resume <filename>: Resume an aborted scan\n"
"MISC:\n"
"  --send-eth: Send using raw ethernet frames (default)\n"
"  -V: Print version number\n"
"  -h: Print this help summary page.\n"
"EXAMPLES:\n"
"  masscan -v -sS 192.168.0.0/16 10.0.0.0/8 -p 80\n"
"  masscan 23.0.0.0/0 -p80 --banners -output-format binary --output-filename internet.scan\n"
"  masscan --open --banners --readscan internet.scan -oG internet_scan.grepable\n"
"SEE (https://github.com/robertdavidgraham/masscan) FOR MORE HELP\n"
"\n");
}

/***************************************************************************
 ***************************************************************************/
static unsigned
count_cidr_bits(struct Range range)
{
    unsigned i;

    for (i=0; i<32; i++) {
        unsigned mask = 0xFFFFFFFF >> i;

        if ((range.begin & ~mask) == (range.end & ~mask)) {
            if ((range.begin & mask) == 0 && (range.end & mask) == mask)
                return i;
        }
    }

    return 0;
}


/***************************************************************************
 * Echoes the configuration for one nic
 ***************************************************************************/
static void
masscan_echo_nic(struct Masscan *masscan, FILE *fp, unsigned i)
{
    char idx_str[64];

    /* If we have only one adapter, then don't print the array indexes.
     * Otherwise, we need to print the array indexes to distinguish
     * the NICs from each other */
    if (masscan->nic_count <= 1)
        idx_str[0] = '\0';
    else
        sprintf_s(idx_str, sizeof(idx_str), "[%u]", i);

    if (masscan->nic[i].ifname[0])
        fprintf(fp, "adapter%s = %s\n", idx_str, masscan->nic[i].ifname);
    
    /**
     * FIX 495.1 for issue #495: Single adapter-ip is not saved at all
     *
     * The else case handles a simple invocation of one adapter-ip:
     *
     * 1. masscan ... --adapter-ip 1.2.3.1 ...   [BROKEN]
     *
     * This looks like it was just copy pasta/typo. If the first ip is the same
     * as the last ip, it is a single adapter-ip
     *
     * This never worked as it was before so paused.conf would never save the
     * adapter-ip as it fell through this if/else if into nowhere. It probably
     * went undetected because in simple environments and/or in simple scans,
     * masscan is able to intelligently determine the adapter-ip and only
     * advanced usage requires overriding the chosen value. In addition to
     * that, it is probably relatively uncommon to interrupt a scan as not many
     * users are doing multi-hour / multi-day scans, having them paused and
     * then resuming them (apparently)
     */
    if (masscan->nic[i].src.ip.first == masscan->nic[i].src.ip.last)
        fprintf(fp, "adapter-ip%s = %u.%u.%u.%u\n", idx_str,
            (masscan->nic[i].src.ip.first>>24)&0xFF,
            (masscan->nic[i].src.ip.first>>16)&0xFF,
            (masscan->nic[i].src.ip.first>> 8)&0xFF,
            (masscan->nic[i].src.ip.first>> 0)&0xFF
            );
    /**
     * FIX 495.2 for issue #495: Ranges of size two don't print. When 495.1 is
     * added, ranges of size two print as only the first value in the range
     * Before 495.1, they didn't print at all, so this is not a bug that is
     * introduced by 495.1, just noticed while applying that fix
     *
     * The first if case here is for handling when adapter-ip is a range
     *
     * Examples of the multiple/range case:
     *
     * 1. masscan ... --adapter-ip 1.2.3.1-1.2.3.2 ...   [BROKEN]
     * 2. masscan ... --adapter-ip 1.2.3.1-1.2.3.4 ...   [OK]
     *
     * If the range spans exactly two adapter-ips, it will not hit the range
     * printing logic case here because of an off-by-one
     *
     * Changing it from < to <= fixes that issue and both of the above cases
     * now print the correct range as expected
     */
    else if (masscan->nic[i].src.ip.first+1 <= masscan->nic[i].src.ip.last)
        fprintf(fp, "adapter-ip%s = %u.%u.%u.%u-%u.%u.%u.%u\n", idx_str,
            (masscan->nic[i].src.ip.first>>24)&0xFF,
            (masscan->nic[i].src.ip.first>>16)&0xFF,
            (masscan->nic[i].src.ip.first>> 8)&0xFF,
            (masscan->nic[i].src.ip.first>> 0)&0xFF,
            (masscan->nic[i].src.ip.last>>24)&0xFF,
            (masscan->nic[i].src.ip.last>>16)&0xFF,
            (masscan->nic[i].src.ip.last>> 8)&0xFF,
            (masscan->nic[i].src.ip.last>> 0)&0xFF
            );

    if (masscan->nic[i].my_mac_count)
        fprintf(fp, "adapter-mac%s = %02x:%02x:%02x:%02x:%02x:%02x\n", idx_str,
                masscan->nic[i].my_mac[0],
                masscan->nic[i].my_mac[1],
                masscan->nic[i].my_mac[2],
                masscan->nic[i].my_mac[3],
                masscan->nic[i].my_mac[4],
                masscan->nic[i].my_mac[5]);
    if (masscan->nic[i].router_ip) {
        fprintf(fp, "router-ip%s = %u.%u.%u.%u\n", idx_str,
            (masscan->nic[i].router_ip>>24)&0xFF,
            (masscan->nic[i].router_ip>>16)&0xFF,
            (masscan->nic[i].router_ip>> 8)&0xFF,
            (masscan->nic[i].router_ip>> 0)&0xFF
            );
    } else if (memcmp(masscan->nic[i].router_mac, "\0\0\0\0\0\0", 6) != 0)
        fprintf(fp, "router-mac%s = %02x:%02x:%02x:%02x:%02x:%02x\n", idx_str,
            masscan->nic[i].router_mac[0],
            masscan->nic[i].router_mac[1],
            masscan->nic[i].router_mac[2],
            masscan->nic[i].router_mac[3],
            masscan->nic[i].router_mac[4],
            masscan->nic[i].router_mac[5]);

}


/***************************************************************************
 ***************************************************************************/
void
masscan_save_state(struct Masscan *masscan)
{
    char filename[512];
    FILE *fp;
    int err;


    strcpy_s(filename, sizeof(filename), "paused.conf");
    fprintf(stderr, "                                   "
                    "                                   \r");
    fprintf(stderr, "saving resume file to: %s\n", filename);

    err = fopen_s(&fp, filename, "wt");
    if (err) {
        perror(filename);
        return;
    }

    
    masscan_echo(masscan, fp, 0);

    fclose(fp);
}


#if 0
/*****************************************************************************
 * Read in ranges from a file
 *
 * There can be multiple ranges on a line, delimited by spaces. In fact,
 * millions of ranges can be on a line: there is limit to the line length.
 * That makes reading the file a little bit squirrelly. From one perspective
 * this parser doesn't treat the new-line '\n' any different than other
 * space. But, from another perspective, it has to, because things like
 * comments are terminated by a newline. Also, it has to count the number
 * of lines correctly to print error messages.
 *****************************************************************************/
static void
ranges_from_file(struct RangeList *ranges, const char *filename)
{
    FILE *fp;
    errno_t err;
    unsigned line_number = 0;

    err = fopen_s(&fp, filename, "rt");
    if (err) {
        perror(filename);
        exit(1); /* HARD EXIT: because if it's an exclusion file, we don't
                  * want to continue. We don't want ANY chance of
                  * accidentally scanning somebody */
    }

    while (!feof(fp)) {
        int c = '\n';

        /* remove leading whitespace */
        while (!feof(fp)) {
            c = getc(fp);
            line_number += (c == '\n');
            if (!isspace(c&0xFF))
                break;
        }

        /* If this is a punctuation, like '#', then it's a comment */
        if (ispunct(c&0xFF)) {
            while (!feof(fp)) {
                c = getc(fp);
                line_number += (c == '\n');
                if (c == '\n') {
                    break;
                }
            }
            /* Loop back to the begining state at the start of a line */
            continue;
        }

        if (c == '\n') {
            continue;
        }

        /*
         * Read in a single entry
         */
        if (!feof(fp)) {
            char address[64];
            size_t i;
            struct Range range;
            unsigned offset = 0;


            /* Grab all bytes until the next space or comma */
            address[0] = (char)c;
            i = 1;
            while (!feof(fp)) {
                c = getc(fp);
                if (c == EOF)
                    break;
                line_number += (c == '\n');
                if (isspace(c&0xFF) || c == ',') {
                    break;
                }
                if (i+1 >= sizeof(address)) {
                    LOG(0, "%s:%u:%u: bad address spec: \"%.*s\"\n",
                            filename, line_number, offset, (int)i, address);
                    exit(1);
                } else
                    address[i] = (char)c;
                i++;
            }
            address[i] = '\0';

            /* parse the address range */
            range = range_parse_ipv4(address, &offset, (unsigned)i);
            if (range.begin == 0xFFFFFFFF && range.end == 0) {
                LOG(0, "%s:%u:%u: bad range spec: \"%.*s\"\n",
                        filename, line_number, offset, (int)i, address);
                exit(1);
            } else {
                rangelist_add_range(ranges, range.begin, range.end);
            }
        }
    }

    fclose(fp);

    /* Target list must be sorted every time it's been changed, 
     * before it can be used */
    rangelist_sort(ranges);
}
#endif

/***************************************************************************
 ***************************************************************************/
static unsigned
hexval(char c)
{
    if ('0' <= c && c <= '9')
        return (unsigned)(c - '0');
    if ('a' <= c && c <= 'f')
        return (unsigned)(c - 'a' + 10);
    if ('A' <= c && c <= 'F')
        return (unsigned)(c - 'A' + 10);
    return 0xFF;
}

/***************************************************************************
 ***************************************************************************/
static int
parse_mac_address(const char *text, unsigned char *mac)
{
    unsigned i;

    for (i=0; i<6; i++) {
        unsigned x;
        char c;

        while (isspace(*text & 0xFF) && ispunct(*text & 0xFF))
            text++;

        c = *text;
        if (!isxdigit(c&0xFF))
            return -1;
        x = hexval(c)<<4;
        text++;

        c = *text;
        if (!isxdigit(c&0xFF))
            return -1;
        x |= hexval(c);
        text++;

        mac[i] = (unsigned char)x;

        if (ispunct(*text & 0xFF))
            text++;
    }

    return 0;
}

/***************************************************************************
 ***************************************************************************/
static uint64_t
parseInt(const char *str)
{
    uint64_t result = 0;

    while (*str && isdigit(*str & 0xFF)) {
        result = result * 10 + (*str - '0');
        str++;
    }
    return result;
}

static unsigned
parseBoolean(const char *str)
{
    if (str == NULL || str[0] == 0)
        return 1;
    if (isdigit(str[0])) {
        if (strtoul(str,0,0) == 0)
            return 0;
        else
            return 1;
    }
    switch (str[0]) {
    case 't':
    case 'T':
        return 1;
    case 'f':
    case 'F':
        return 0;
    case 'o':
    case 'O':
        if (str[1] == 'f' || str[1] == 'F')
            return 0;
        else
            return 1;
        break;
    case 'Y':
    case 'y':
        return 1;
    case 'n':
    case 'N':
        return 0;
    }
    return 1;
}

/***************************************************************************
 * Parses the number of seconds (for rotating files mostly). We do a little
 * more than just parse an integer. We support strings like:
 *
 * hourly
 * daily
 * Week
 * 5days
 * 10-months
 * 3600
 ***************************************************************************/
static uint64_t
parseTime(const char *value)
{
    uint64_t num = 0;
    unsigned is_negative = 0;

    while (*value == '-') {
        is_negative = 1;
        value++;
    }

    while (isdigit(value[0]&0xFF)) {
        num = num*10 + (value[0] - '0');
        value++;
    }
    while (ispunct(value[0]) || isspace(value[0]))
        value++;

    if (isalpha(value[0]) && num == 0)
        num = 1;

    if (value[0] == '\0')
        return num;

    switch (tolower(value[0])) {
    case 's':
        num *= 1;
        break;
    case 'm':
        num *= 60;
        break;
    case 'h':
        num *= 60*60;
        break;
    case 'd':
        num *= 24*60*60;
        break;
    case 'w':
        num *= 24*60*60*7;
        break;
    default:
        fprintf(stderr, "--rotate-offset: unknown character\n");
        exit(1);
    }
    if (num >= 24*60*60) {
        fprintf(stderr, "--rotate-offset: value is greater than 1 day\n");
        exit(1);
    }
    if (is_negative)
        num = 24*60*60 - num;

    return num;
}

/***************************************************************************
 * Parses a size integer, which can be suffixed with "tera", "giga", 
 * "mega", and "kilo". These numbers are in units of 1024 so suck it.
 ***************************************************************************/
static uint64_t
parseSize(const char *value)
{
    uint64_t num = 0;

    while (isdigit(value[0]&0xFF)) {
        num = num*10 + (value[0] - '0');
        value++;
    }
    while (ispunct(value[0]) || isspace(value[0]))
        value++;

    if (isalpha(value[0]) && num == 0)
        num = 1;

    if (value[0] == '\0')
        return num;

    switch (tolower(value[0])) {
    case 'k': /* kilobyte */
        num *= 1024ULL;
        break;
    case 'm': /* megabyte */
        num *= 1024ULL * 1024ULL;
        break;
    case 'g': /* gigabyte */
        num *= 1024ULL * 1024ULL * 1024ULL;
        break;
    case 't': /* terabyte, 'cause we roll that way */
        num *=  1024ULL * 1024ULL * 1024ULL * 1024ULL;
        break;
    case 'p': /* petabyte, 'cause we are awesome */
        num *=  1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL;
        break;
    case 'e': /* exabyte, now that's just silly */
        num *=  1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL;
        break;
    default:
        fprintf(stderr, "--rotate-size: unknown character\n");
        exit(1);
    }
    return num;
}


/***************************************************************************
 ***************************************************************************/
static int
is_power_of_two(uint64_t x)
{
    while ((x&1) == 0)
        x >>= 1;
    return x == 1;
}


/***************************************************************************
 * Tests if the named parameter on the command-line. We do a little
 * more than a straight string compare, because I get confused
 * whether parameter have punctuation. Is it "--excludefile" or
 * "--exclude-file"? I don't know if it's got that dash. Screw it,
 * I'll just make the code so it don't care.
 ***************************************************************************/
static int
EQUALS(const char *lhs, const char *rhs)
{
    for (;;) {
        while (*lhs == '-' || *lhs == '.' || *lhs == '_')
            lhs++;
        while (*rhs == '-' || *rhs == '.' || *rhs == '_')
            rhs++;
        if (*lhs == '\0' && *rhs == '[')
            return 1; /*arrays*/
        if (tolower(*lhs & 0xFF) != tolower(*rhs & 0xFF))
            return 0;
        if (*lhs == '\0')
            return 1;
        lhs++;
        rhs++;
    }
}

static int
EQUALSx(const char *lhs, const char *rhs, size_t rhs_length)
{
    for (;;) {
        while (*lhs == '-' || *lhs == '.' || *lhs == '_')
            lhs++;
        while (*rhs == '-' || *rhs == '.' || *rhs == '_')
            rhs++;
        if (*lhs == '\0' && *rhs == '[')
            return 1; /*arrays*/
        if (tolower(*lhs & 0xFF) != tolower(*rhs & 0xFF))
            return 0;
        if (*lhs == '\0')
            return 1;
        lhs++;
        rhs++;
        if (--rhs_length == 0)
            return 1;
    }
}

static unsigned
INDEX_OF(const char *str, char c)
{
    unsigned i;
    for (i=0; str[i] && str[i] != c; i++)
        ;
    return i;
}

static unsigned
ARRAY(const char *rhs)
{
    const char *p = strchr(rhs, '[');
    if (p == NULL)
        return 0;
    else
        p++;
    return (unsigned)parseInt(p);
}

static void
config_top_ports(struct Masscan *masscan, unsigned n)
{
    unsigned i;
    static const unsigned short top_tcp_ports[] = {
#ifdef _ORIGINAL_TOP_PORTS
        1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,70,
        79,80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,135,
        139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,280,
        301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,464,
        465,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,563,
        587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,705,
        711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,888,
        898,900,901,902,903,911,912,981,987,990,992,993,995,999,1000,1001,
        1002,1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,1028,
        1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,
        1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,
        1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,
        1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,
        1081,1082,1083,1084,1085,1086,1087,1088,1089,1090,1091,1092,1093,
        1094,1095,1096,1097,1098,1099,1100,1102,1104,1105,1106,1107,1108,
        1110,1111,1112,1113,1114,1117,1119,1121,1122,1123,1124,1126,1130,
        1131,1132,1137,1138,1141,1145,1147,1148,1149,1151,1152,1154,1163,
        1164,1165,1166,1169,1174,1175,1183,1185,1186,1187,1192,1198,1199,
        1201,1213,1216,1217,1218,1233,1234,1236,1244,1247,1248,1259,1271,
        1272,1277,1287,1296,1300,1301,1309,1310,1311,1322,1328,1334,1352,
        1417,1433,1434,1443,1455,1461,1494,1500,1501,1503,1521,1524,1533,
        1556,1580,1583,1594,1600,1641,1658,1666,1687,1688,1700,1717,1718,
        1719,1720,1721,1723,1755,1761,1782,1783,1801,1805,1812,1839,1840,
        1862,1863,1864,1875,1900,1914,1935,1947,1971,1972,1974,1984,1998,
        1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010,2013,
        2020,2021,2022,2030,2033,2034,2035,2038,2040,2041,2042,2043,2045,
        2046,2047,2048,2049,2065,2068,2099,2100,2103,2105,2106,2107,2111,
        2119,2121,2126,2135,2144,2160,2161,2170,2179,2190,2191,2196,2200,
        2222,2251,2260,2288,2301,2323,2366,2381,2382,2383,2393,2394,2399,
        2401,2492,2500,2522,2525,2557,2601,2602,2604,2605,2607,2608,2638,
        2701,2702,2710,2717,2718,2725,2800,2809,2811,2869,2875,2909,2910,
        2920,2967,2968,2998,3000,3001,3003,3005,3006,3007,3011,3013,3017,
        3030,3031,3052,3071,3077,3128,3168,3211,3221,3260,3261,3268,3269,
        3283,3300,3301,3306,3322,3323,3324,3325,3333,3351,3367,3369,3370,
        3371,3372,3389,3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,
        3689,3690,3703,3737,3766,3784,3800,3801,3809,3814,3826,3827,3828,
        3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,
        3995,3998,4000,4001,4002,4003,4004,4005,4006,4045,4111,4125,4126,
        4129,4224,4242,4279,4321,4343,4443,4444,4445,4446,4449,4550,4567,
        4662,4848,4899,4900,4998,5000,5001,5002,5003,5004,5009,5030,5033,
        5050,5051,5054,5060,5061,5080,5087,5100,5101,5102,5120,5190,5200,
        5214,5221,5222,5225,5226,5269,5280,5298,5357,5405,5414,5431,5432,
        5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678,5679,
        5718,5730,5800,5801,5802,5810,5811,5815,5822,5825,5850,5859,5862,
        5877,5900,5901,5902,5903,5904,5906,5907,5910,5911,5915,5922,5925,
        5950,5952,5959,5960,5961,5962,5963,5987,5988,5989,5998,5999,6000,
        6001,6002,6003,6004,6005,6006,6007,6009,6025,6059,6100,6101,6106,
        6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565,6566,6567,
        6580,6646,6666,6667,6668,6669,6689,6692,6699,6779,6788,6789,6792,
        6839,6881,6901,6969,7000,7001,7002,7004,7007,7019,7025,7070,7100,
        7103,7106,7200,7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,
        7777,7778,7800,7911,7920,7921,7937,7938,7999,8000,8001,8002,8007,
        8008,8009,8010,8011,8021,8022,8031,8042,8045,8080,8081,8082,8083,
        8084,8085,8086,8087,8088,8089,8090,8093,8099,8100,8180,8181,8192,
        8193,8194,8200,8222,8254,8290,8291,8292,8300,8333,8383,8400,8402,
        8443,8500,8600,8649,8651,8652,8654,8701,8800,8873,8888,8899,8994,
        9000,9001,9002,9003,9009,9010,9011,9040,9050,9071,9080,9081,9090,
        9091,9099,9100,9101,9102,9103,9110,9111,9200,9207,9220,9290,9415,
        9418,9485,9500,9502,9503,9535,9575,9593,9594,9595,9618,9666,9876,
        9877,9878,9898,9900,9917,9929,9943,9944,9968,9998,9999,10000,10001,
        10002,10003,10004,10009,10010,10012,10024,10025,10082,10180,10215,
        10243,10566,10616,10617,10621,10626,10628,10629,10778,11110,11111,
        11967,12000,12174,12265,12345,13456,13722,13782,13783,14000,14238,
        14441,14442,15000,15002,15003,15004,15660,15742,16000,16001,16012,
        16016,16018,16080,16113,16992,16993,17877,17988,18040,18101,18988,
        19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221,
        20222,20828,21571,22939,23502,24444,24800,25734,25735,26214,27000,
        27352,27353,27355,27356,27715,28201,30000,30718,30951,31038,31337,
        32768,32769,32770,32771,32772,32773,32774,32775,32776,32777,32778,
        32779,32780,32781,32782,32783,32784,32785,33354,33899,34571,34572,
        34573,35500,38292,40193,40911,41511,42510,44176,44442,44443,44501,
        45100,48080,49152,49153,49154,49155,49156,49157,49158,49159,49160,
        49161,49163,49165,49167,49175,49176,49400,49999,50000,50001,50002,
        50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,
        52848,52869,54045,54328,55055,55056,55555,55600,56737,56738,57294,
        57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,
        65129,65389
#else  /* _ORIGINAL_TOP_PORTS */
        1,3-4,6-7,9,13,17,19-27,30,32-33,37,42-43,49,53,55,57,59,70,77,79-90,
        97-100,102,106,109-111,113,119,123,125,127,135,139,143-144,146,148,
        153,157,161,163,179,183,195,199,210-212,220,222-223,225,250-252,
        254-257,259-260,264,280,301,306,311,320,333,340,350,366,388-389,
        406-407,411,416-417,419,425,427,441-443,443-445,447,449,452,
        454-455,458,464-465,475,481,495,497,500,502,512-515,523-524,528,
        539-541,543,543-545,548,554-557,563,587,593,600,602-603,606,610,
        616-617,621,623,625,631,636,639,641,643,646-648,655,657,659-660,664,
        666-669,674,683-684,687,690-691,700-701,705,709-711,713-715,720,
        722,725-726,728-732,740,743,748-749,754,757-758,765,777-778,780,
        782-783,786-787,790,792-793,795,797,800-803,805-806,808,816,
        822-825,829,836,839-840,843,843,846-847,850,856,858-859,862,864,
        873-874,877-878,880,882,888,898,900-905,911-913,918,921-922,924,
        928,930-931,934,941,943,943,953,969,971,980-982,987,990,992-993,
        995-996,998-1002,1004-1015,1019-1043,1043-1100,1102-1114,1117,
        1119,1121-1124,1126-1127,1130-1132,1137-1138,1141,1143,1145,
        1147-1149,1151-1152,1154,1158,1163-1166,1169,1174-1175,1183,
        1185-1187,1192,1194,1198-1199,1201,1212-1213,1216-1218,
        1220-1222,1233-1234,1236,1241,1243-1244,1247-1248,1259,
        1270-1272,1277,1287,1296,1300-1301,1309-1312,1322,1328,1334,1337,
        1343,1347,1350-1353,1357,1367,1374,1413-1414,1417,1433-1434,
        1443,1443-1453,1455,1461,1490,1494,1500-1501,1503,1516-1517,
        1521-1522,1524-1526,1533,1543,1547,1550,1552,1556,1580,1583,1594,
        1600,1610,1612,1641,1643,1658,1666,1687-1689,1700,1711,
        1717-1721,1723,1725,1743,1745,1755,1761,1764,1769,1782-1783,1797,
        1801,1805,1812,1831,1839-1840,1843,1862-1864,1875,1883,1900,
        1914,1935,1943,1947,1951,1971-1972,1974,1984,1998-2013,
        2020-2022,2025,2030,2033-2035,2038,2040-2043,2043-2049,
        2052-2053,2065,2067-2068,2082-2083,2086-2087,2095-2096,
        2099-2100,2103,2105-2107,2111-2112,2119,2121,2126,2135,2143-2144,
        2160-2161,2170-2171,2179,2190-2191,2196,2199-2202,2209,2222,2232,
        2241,2243,2251,2260,2272,2288,2301,2322-2323,2334,2343,2364,2366,
        2381-2383,2390,2393-2394,2399,2401,2406,2433,2443,2443,2484,2492,
        2500-2501,2516,2522,2525,2543,2549,2557,2600-2602,2604-2605,
        2607-2608,2628,2633,2635,2638,2640,2643,2661,2664,2679,2701-2702,
        2710-2711,2717-2718,2720,2725,2743,2781,2800,2809,2811,2843,2863,
        2869,2872,2875,2894,2903,2909-2910,2920,2943,2949,2967-2968,
        2998,3000-3001,3003,3005-3007,3011,3013,3017,3021,3025,
        3030-3031,3043,3050,3052,3070-3071,3077,3089,3119,3128,3143,3162,
        3166,3168,3188,3201,3211,3221,3241,3243-3244,3260-3261,
        3268-3269,3283,3299-3301,3304,3306-3307,3322-3325,3333,3343,3351,
        3367,3369-3372,3376,3389-3390,3399-3400,3404,3410,3443,3443,
        3456,3476,3493,3496,3511,3514,3517,3524,3527,3543,3546,3551,3580,
        3617,3632,3643,3659,3661,3667,3684,3689-3690,3697,3700,3703,3731,
        3735,3737,3743,3743,3746,3758,3766,3770-3772,3784,3792,3797,
        3800-3801,3808-3809,3814,3820,3824,3826-3828,3843,3846-3849,
        3851-3853,3859,3863,3869-3872,3878,3880,3888-3890,3899,3905,3907,
        3914,3916,3918,3920,3929,3931,3941,3943-3946,3948,3952,3957,3963,
        3968-3969,3971-3972,3981,3986,3990-3991,3993-3995,3998-4006,
        4009,4022,4024,4040,4043,4045,4050,4056,4080,4096,4111,4125-4126,
        4129,4143,4143,4147,4164,4167,4172,4190,4200,4224,4242-4243,4248,
        4252,4259-4260,4267,4277,4279,4321,4333,4341,4343,4343,4349,4356,
        4385,4428,4430,4443,4443-4446,4449,4543,4550,4555,4559,4567,4600,
        4643,4658,4662,4689,4709,4728,4743,4743,4776,4800,4823,4837,4843,
        4848,4868,4875,4899-4900,4943,4949,4995,4998,5000-5005,
        5009-5011,5022,5030,5033,5040,5043,5050-5051,5054,5060-5061,5063,
        5074,5079-5081,5087,5100-5102,5120,5126,5130,5143,5151,5190,
        5200,5203,5212,5214,5221-5223,5225-5226,5233,5242-5243,5269,
        5279-5280,5283,5298,5335,5339,5343-5344,5353,5357,5377,5388,5405,
        5414,5421,5431-5432,5438,5440,5443,5500-5501,5510,5520,5522,
        5543-5544,5550,5555,5560,5566,5631,5633,5643,5656,5663,5666,
        5671-5672,5676,5678-5680,5718,5726,5730,5733,5743,5800-5803,5807,
        5810-5812,5815,5818,5822-5823,5825,5843,5850,5859,5862,5868-5869,
        5877,5899-5907,5909-5911,5914-5915,5918,5922,5925,5938,5940,
        5943,5950,5952,5959-5963,5968,5981,5987-5989,5998-6009,6017,
        6025,6043,6050-6051,6059-6060,6068,6086,6100-6101,6103,6106,
        6112,6123,6129,6143,6156,6197,6203,6222,6243,6247,6331,6343,6346,
        6363,6371,6379,6383,6386,6389,6410,6418,6421,6443,6481,6500,6502,
        6504,6510,6512,6520-6521,6529,6543,6543,6547,6550,6565-6567,
        6578,6580,6598,6600,6636,6639,6643,6646,6659,6662,6666-6670,6674,
        6682,6689,6692,6699,6711,6713,6717,6729,6732,6743,6750,6762,6779,
        6783,6788-6789,6792,6809,6839-6840,6843,6848-6849,6871,6881,
        6889,6896-6897,6901,6903,6919,6929,6943,6950,6969,6985,
        7000-7004,7007,7010-7011,7019,7024-7025,7035,7043,7050-7051,7058,
        7070,7076-7078,7080,7100,7103,7106,7123,7143,7193,7200-7201,
        7241,7243,7255,7260,7272-7273,7278,7281,7297,7335,7343,7356,7389,
        7391,7394-7396,7402,7412,7435,7438,7443,7443,7485,7491,7496,
        7503-7505,7512,7522-7524,7527,7540,7543,7554,7556,7581,7596,7600,
        7625,7627,7638,7643,7647,7649,7654,7657,7667,7673,7676,7678,7725,
        7741,7743-7744,7746,7749,7770,7775,7777-7778,7798,7800,7809,
        7813-7814,7843,7843,7853,7875,7878,7900,7911,7913,7920-7921,7929,
        7937-7938,7943,7952,7969-7970,7974,7978,7985,7992,7998-8002,
        8006-8011,8015-8017,8019,8021-8022,8028,8030-8031,8042-8043,
        8045-8046,8048,8050,8053-8054,8075,8080-8090,8092-8093,8095,
        8097-8100,8110,8113,8118,8126,8142-8143,8146,8161,8172,8174,
        8180-8181,8183,8189,8192-8194,8200,8206,8222,8243,8254,8262,8278,
        8290-8294,8300,8302,8313,8317,8333,8342-8343,8362,8372,8376,8381,
        8383,8385,8397,8400,8402-8403,8405,8423,8430,8443,8443-8448,
        8474,8481,8490,8500,8511,8540,8543,8588,8591,8600,8616-8617,8622,
        8638,8643,8647-8649,8651-8652,8654,8656,8671,8675-8676,8678,
        8686,8701,8704,8712,8733,8743,8755,8765-8766,8778,8800,8802,8804,
        8817-8818,8824,8836,8838,8843,8843,8853,8869,8873,8877,8880,8883,
        8888-8889,8899,8926,8943-8944,8987,8992,8994,8996,9000-9003,9005,
        9009-9011,9031,9039-9040,9043,9048,9050-9051,9059,9064,9067,9071,
        9080-9081,9083,9090-9092,9097-9103,9110-9111,9119,9132,9143,9152,
        9158,9160,9171,9191,9197-9198,9200,9202,9207,9220,9243,
        9265-9266,9290-9291,9300,9315,9327,9343,9358,9386,9391-9392,9396,
        9409,9415,9418,9424,9441-9443,9443-9444,9471-9472,9483,9485,
        9495-9496,9500-9503,9516,9524,9535,9541,9543,9545,9563,9575,
        9593-9595,9600,9604,9618,9621-9622,9643,9643,9645,9651,9653,9661,
        9666,9673,9712-9713,9725,9737,9743,9761,9809,9815,9820,9843,9843,
        9853,9876-9878,9897-9898,9900,9914,9917,9929,9941,9943,
        9943-9945,9968,9988,9992,9998-10005,10008-10012,10022-10025,
        10034,10043,10050,10058-10059,10072,10082-10083,10143,10160,
        10180,10215,10219,10243,10243,10270,10319,10343,10346,10374,
        10396,10443,10449,10504,10515,10519,10543-10544,10566,
        10616-10617,10619,10621,10626,10628-10629,10631,10643,10655,10664,
        10688,10743,10774,10778,10819,10843,10873,10890,10942-10943,
        10970,10988,11006,11017,11043,11099,11103,11110-11111,11134,
        11143,11243,11280,11337,11342-11343,11348,11358,11422,11438,
        11443,11462,11543,11566,11643,11743,11748,11795-11796,11798,
        11808,11843,11865,11877,11901,11907,11913,11943,11949,11967,
        11997,12000,12006,12021,12043,12059,12072,12104,12117,12143,
        12149,12156,12167,12174,12192,12196,12215,12243,12262,12265,
        12302,12343,12345-12346,12357,12371,12380,12419,12443-12444,
        12452,12501,12543,12597,12619,12642-12643,12670,12725,
        12742-12743,12766,12820,12843,12879,12893,12936,12943,12960,12985,
        13043,13047,13140,13143,13200,13237,13243,13317,13328,13343,
        13346,13393,13406,13421,13431,13439,13443,13445,13456,13470,
        13484,13543,13625,13638,13643,13722,13724,13743,13782-13783,
        13798,13827,13843,13869,13894,13943-13944,14000,14043,14063,
        14066,14122,14129,14134,14143,14211,14238,14240,14243,14283,
        14291,14334,14343,14358,14376,14384,14410,14441-14443,14451,
        14482,14499,14543,14562,14573,14606,14615,14643,14685,14704,
        14743,14800,14843,14943,15000-15004,15043,15110,15143,15143,
        15230,15243,15260,15315,15343,15354,15391,15402,15443,15455,
        15543,15643,15660,15674,15742-15743,15749,15785,15801,15813,
        15838,15843,15903,15943,15996,16000-16001,16012,16016,16018,
        16020,16043,16080,16087,16110,16113,16143,16212-16213,16243,
        16259,16268,16275,16343,16411,16443,16449,16462,16543,16547,
        16597,16638,16643,16705,16743,16747,16800,16813,16843,
        16850-16851,16857,16940,16943,16961,16969,16992-16993,17000,
        17042-17043,17057,17060,17127,17143,17177,17200,17226,17243,17300,
        17343,17358,17415,17443,17455,17485,17530,17543,17595-17596,
        17609,17624,17630,17643,17645,17656,17697,17743,17788,17843,
        17845,17877,17936,17943,17964,17988,18000,18018,18040,
        18043-18044,18048,18083,18086,18101,18110,18143,18196,18203,18243,
        18264,18292,18336,18343,18443,18455,18474,18500,18526,18539,
        18543,18558,18562,18575,18588,18643,18659,18697,18740,18743,
        18819,18834,18836,18841,18843,18857,18897,18943,18948,18953,
        18983,18988,18994,19003,19026,19043,19065,19067,19101,19143,
        19157,19192,19215,19227,19243,19283,19295,19315,19332,19343,
        19350,19387,19417,19443-19444,19463,19519,19543,19547,19579,
        19628,19643,19688,19714,19743,19757,19777,19780,19801,
        19829-19830,19842-19843,19845,19900,19903,19943,19951,19958,20000,
        20002,20005,20015,20017,20019,20031,20043,20068,20085,20087,
        20143,20204,20221-20222,20243,20327,20343,20347,20358,20380,
        20395,20417,20422,20430,20439,20443,20457,20543,20604,20614,
        20643,20645,20743,20755,20792,20828,20843,20853,20861,20943,
        20946,20953,20958,20967,20988,21005,21020,21043,21063,21082,
        21110,21143,21199,21202,21243,21280,21319,21322,21343,21349,
        21405,21443,21477,21543,21561,21571,21643,21661,21673,21690,
        21706-21707,21743,21792,21798,21808,21843,21904,21943,21955,22009,
        22013,22043,22099,22139,22143,22174,22222,22237,22243,22298,
        22328,22343,22443,22537,22543,22552,22562,22577,22616,22621,
        22643,22649-22650,22723,22729,22742-22743,22749,22754,22782,
        22804,22843-22844,22899,22939,22943,23043,23052,23082,23141,
        23143,23155,23243,23287,23341,23343,23371,23443,23453,23463,
        23502-23503,23521,23543,23576,23592,23637,23643,23678,23736,23739,
        23743,23778,23796,23843,23864,23943,23975,24004,24012,24027,
        24030,24043,24045,24143,24223,24227,24233,24239,24243,24269,
        24343,24443-24444,24455,24480,24488,24543,24643,24708,24743,
        24795,24800,24824,24835,24843,24848,24864,24876,24943,24947,
        24965,25002,25008,25043,25058,25074,25133,25143,25156,25164,
        25201,25243,25250,25299,25320,25343,25349,25351,25359,25375,
        25379,25443,25526,25543,25643,25734-25735,25743,25769,25773,
        25787,25843,25864,25895,25943,26000,26043,26065,26122,26143,
        26145,26153,26202,26208,26214,26218,26234,26243,26257,26268,
        26294,26321,26329,26337,26343,26443,26470,26478,26543,26566,
        26587,26589,26597,26632,26643,26700,26721,26743,26768,26778,
        26843,26894,26934,26937,26943,26967,27000,27043,27091,27119,
        27143,27231,27243-27244,27324,27328,27342-27343,27352-27353,
        27355-27357,27362,27411,27423-27424,27429,27443,27475,27481,27484,
        27491,27501,27543,27581,27643,27668,27715,27732,27743,27762,
        27796,27843,27851,27859,27881,27912,27921,27923,27935,27943,
        27975,28036,28043,28064,28118,28143,28157,28172,28179,28201,
        28211,28243,28251,28264,28295,28299,28343,28351,28366,28381,
        28443,28477,28511,28521,28525-28527,28543,28562,28576,28633,
        28636,28643,28653,28736,28743,28762,28776,28837,28843,28853,
        28855,28916,28930,28943,28956,28978,28986,29003,29043,29058,
        29143,29168,29232,29243,29343,29443,29445,29474,29485,29522,
        29535,29543,29585,29595,29643,29646,29658,29672,29675,29743,
        29778,29831,29843,29865,29875,29943,29958,29999-30000,30005,
        30018,30024,30029,30043,30113,30119,30143,30154,30178,30185,
        30212,30243,30266,30316,30330,30343,30412,30443,30506,30508,
        30532,30543,30555,30558,30565,30591,30628,30643,30683,30704,
        30718,30723,30727,30743,30756,30810,30813,30822,30843,30848,
        30861,30872,30908,30925,30943,30951,31003,31006,31023-31024,
        31038,31043,31048,31143,31147,31155,31172,31174,31178,31191,
        31204,31213,31232,31243,31267,31306,31316,31337,31343,31364,
        31381,31442-31443,31454,31471,31479,31483,31543,31554,31578,
        31584,31643-31644,31658,31673,31711,31718,31726-31727,31734,
        31743,31772,31843,31884,31932,31943,31947,31969,32000-32001,
        32005,32040,32043,32100,32143,32157,32167,32194,32200,32215,
        32223,32233,32243,32298,32343,32363,32392,32414,32443,32543,
        32643,32643,32646,32674,32717,32743,32756,32761,32767-32785,
        32791-32792,32803,32816,32818,32822,32825-32826,32835,32843,32919,
        32943,33012,33043,33050,33063,33079,33081,33101,33143,33148,
        33164,33188,33210,33243,33312,33343,33354,33360,33385,33411,
        33435,33440,33443,33453,33495,33543,33554,33609,33643,33693,
        33726,33743,33767,33843,33845,33851,33859,33882,33899,33909,
        33943,33948,33966,34043,34078,34115,34121,34143,34167,34243,
        34301,34325,34343,34345,34362,34421,34430,34443,34445,34480,
        34519,34543,34551,34563,34571-34573,34612,34621,34625-34626,
        34643,34686,34701,34728,34743,34822,34834,34843,34912,34943,
        35002,35043,35096,35105,35143,35145,35190,35210,35217,35243,
        35250,35294,35339,35341,35343,35360,35371,35381,35443,35462,
        35500,35513,35543,35566,35578,35643-35644,35680,35683,35702,
        35719,35743,35833,35843,35851,35881,35900,35906,35928,35937,
        35943,36020,36032,36043,36072,36084,36143,36243,36270,36317,
        36343,36417,36443,36488,36503,36543,36643,36680,36722,36743,
        36805,36824,36843,36906,36920,36931,36939,36943,37041,37043,
        37119,37131,37143,37176,37236-37237,37243,37247,37312,37343,
        37443,37479,37498,37543,37643,37669,37700,37743,37751,37839,
        37843,37943,37956,37965,37980,38028,38037,38043,38050,38114,
        38124,38143,38162,38177,38185,38188,38236,38243,38248,38251,
        38255,38284,38292,38328,38343,38359,38402,38410,38443,38464,
        38528,38543,38617,38643,38649,38651,38691,38722,38743,38829,
        38843,38866,38920,38924,38943,38960,38968,38976,38999,39003,
        39043,39051,39086,39136,39143,39213,39218,39243,39251,39330,
        39343,39376,39443,39543,39572,39607,39610,39643,39659,39673,
        39675,39679,39721,39724,39743,39749,39759,39767,39783,39791,
        39835,39843,39924,39943,39950,39987,40000,40043,40143,40146,
        40193,40243,40246,40256,40270,40290,40302,40335,40337,40343,
        40365,40432,40443,40451,40470,40543,40555,40569,40573,40580,
        40643-40644,40660-40661,40668,40677,40743,40786,40811,40843,40868,
        40897,40911,40943,40967,41043,41043,41057,41060,41064,
        41066-41067,41113,41143,41167,41172,41178,41221-41222,41228,
        41242-41244,41249,41271,41343,41443,41451,41483,41511,41523,41543,
        41598,41624,41626,41643,41687,41743,41826,41843,41921,41943,
        42039,42043,42058,42082,42087,42117,42143-42144,42203,42243,
        42257,42260,42268,42295,42312,42343,42362,42364,42381,42401,
        42412,42434,42443,42509-42510,42513,42530,42543,42548,42643,
        42665,42678,42690,42743,42760,42781,42786,42821,42832,42843,
        42898,42943,42968,42991,43002,43027-43028,43036,43043,43100,
        43105,43118,43143,43205,43233,43243,43276,43343,43384,43443,
        43472,43483,43521,43523,43537,43543,43643,43743,43743,43770,
        43774,43791,43843,43861,43908,43914,43943,43945,43954,43999,
        44041,44043,44075,44079,44143,44167,44176,44201,44243,44320,
        44334,44343,44346,44374,44418,44428-44429,44441-44443,44443,
        44486,44501,44543,44580,44596-44597,44643,44684,44693,44709,
        44714,44728,44743,44745,44825,44843,44897,44921,44939,44943,
        44966,44969,45005,45043,45098,45100,45118,45143,45145,45218,
        45243,45263,45282,45285,45329,45343,45443,45448,45466,45478,
        45511,45519,45543,45600,45606,45627,45643,45654,45743,45751,
        45755,45843,45846,45933,45941,45943,45961,45964,46005,46043,
        46072-46073,46085,46123,46141,46143,46164-46165,46197,46200,46203,
        46243,46274,46315,46326,46332-46333,46341,46343,46362,46443,
        46477,46542-46543,46594,46619,46623,46627,46638,46643,46647,
        46653,46743-46744,46843,46852,46869,46943,46966,46996,47001,
        47003,47043,47093,47120,47143,47156,47164,47214,47226,47243,
        47264,47291,47304,47312,47343,47350,47412,47443,47463,47469,
        47543-47544,47568,47579,47587,47612,47624,47643,47692,47743,47843,
        47869,47923,47936,47943,48001,48003,48031,48043,48071,48080,
        48082,48115,48143,48160,48170,48172,48179,48187,48194-48195,
        48203,48243,48326,48343,48443,48457,48543,48643,48664,48694,
        48743,48784,48794,48816,48843,48943,49003,49024,49043,49084,
        49143,49152-49161,49163-49168,49171,49175-49176,49186,49195,
        49214,49236,49243,49255,49343,49359,49400-49401,49404,49425,
        49443,49514,49543,49578,49615,49643,49650,49664,49666-49669,
        49743,49765,49789,49843,49847,49870,49943,49957,49963,
        49999-50003,50006,50021,50043,50043,50050,50071,50143,50157,50169,
        50171,50238,50243,50283,50300,50343,50389,50409-50410,50422,
        50432,50443,50461,50465,50470,50486,50500,50543,50579,50636,
        50643,50712,50743,50800,50805,50843,50875,50943,51007,51021,
        51033,51043,51058,51103,51109-51110,51115,51143,51191,51210,
        51223,51243,51258,51304,51334,51343,51359,51397,51401,51413,
        51443,51454,51483,51493,51499,51543,51552,51611,51619,51631,
        51643,51737,51743,51745,51781,51789,51843,51858,51890,51943,
        51956,51962,51988,51991,52035,52043,52134,52143,52162,52187,
        52243,52343,52380,52389,52419,52443,52516,52543,52596,52643,
        52643,52660,52673,52700,52710,52735-52736,52743,52805,52822,
        52843,52847-52851,52853,52867,52869,52943,52948,53043,53054,
        53086,53090,53140,53143,53200,53211,53219,53235,53243,53250,
        53302,53313-53314,53343,53402,53443,53487,53504,53524,53535,
        53543,53553,53557,53561,53578,53605,53643,53664,53692,53707,
        53743,53759,53762,53781-53782,53785,53791,53795,53825,53828,
        53843,53903,53912,53943,54043,54045,54143,54153,54205,54243,
        54257,54287,54310,54328,54343,54379,54398,54443,54534,54543,
        54585,54643,54651,54659,54663,54743,54773,54794,54802,54813,
        54824,54830,54833,54843,54938,54943,54943,55002,55004,55020,
        55043,55055-55056,55114,55143,55159,55164,55168,55187,55216,
        55227,55243,55253,55283,55340,55343,55443,55478,55493,55517,
        55543,55555,55576,55600,55643,55713,55716,55735,55743,55745,
        55749,55792,55843,55860,55903,55943,55950,55989,56015,56043,
        56043,56143,56190,56193,56219,56224,56233,56241,56243,56259,
        56272,56297,56343,56357,56368,56388,56440,56443,56468,56491,
        56543,56543,56573,56586,56602,56628,56643,56668,56737-56738,
        56743,56745,56774,56806,56843,56867,56884,56888,56908,56943,
        57042-57043,57043,57101,57133,57141,57143,57160,57178,57243,57270,
        57272,57294,57343,57387,57399,57443,57456,57484,57543,57563,
        57579,57643,57649,57665,57715,57727,57743,57768,57797,57808,
        57810,57829,57843,57892,57943,58001-58002,58025,58043,58056,
        58069,58080,58090,58143,58156,58243,58270,58343,58414,58436,
        58443,58454,58543,58554,58559,58611,58629-58630,58632,58643,
        58656,58693,58743,58792,58823,58838,58843,58867,58943,58950,
        58998,59006,59043,59089,59110,59143,59156,59200-59202,59243,
        59281,59284,59311,59343,59382,59422,59443,59446,59452,59463,
        59466,59489,59543,59557,59570,59621,59637,59643,59739,59743,
        59776,59786,59843,59906,59917,59921,59943-59944,59947-59948,
        59956,59960,59965,59973,59979,59981,59983,59985-59986,
        59988-59989,59991-59995,59997-60000,60008,60015,60020,60037,
        60041,60043,60123,60143,60146,60201,60209,60217,60224,60232,
        60240,60243,60319,60328,60330,60343,60371,60377,60382,60397,
        60401,60403,60443,60443,60485,60492,60504,60543-60544,60579,
        60605,60612,60621,60628,60639,60642-60643,60700,60713,60728,
        60743,60743,60748,60753,60782-60783,60789,60794,60801,60839,
        60843,60916,60936,60943,60969,60975,60989,61018,61043,61043,
        61143,61159,61169-61170,61211,61220,61231,61243,61313,61343,
        61350,61366,61368,61386,61402,61443,61473,61479,61516,61532,
        61543,61546,61579,61613,61616-61617,61643,61669,61722,61734,
        61743,61777,61827,61843,61851,61853,61900,61942-61943,61946,
        62006,62042-62043,62078,62080,62143,62179,62188,62243,62257,
        62264,62269,62312,62343,62383,62396,62412,62428,62443,62445,
        62452,62519,62543,62560,62564,62568,62570,62615,62634,62640,
        62643,62674,62721,62734,62743,62747,62838,62842-62843,62849,
        62866,62885,62926,62929,62943,62965,62973,63019,63035,63043,
        63094,63105,63118,63143,63156,63208,63243,63260,63331,63343,
        63360,63394,63423,63434,63443,63455,63527,63535,63543,63558,
        63604,63631,63643,63647,63651,63658,63673,63675,63682,63708,
        63731,63740,63743,63771,63787,63803,63807,63813,63838,63843,
        63857,63861,63865,63875,63892,63909,63916,63920,63936,63943,
        63953-63954,63959,63971,63999,64012,64043,64076,64080,64104,64127,
        64143,64154,64159,64167,64188,64207,64243,64248,64250,64262,
        64285,64312,64318,64320,64333,64343,64384,64392,64400,64435,
        64438,64443,64507,64512,64543,64549,64551,64597,64609,64617,
        64620,64623-64624,64641,64643,64651,64680-64681,64712,64721,
        64726-64727,64743,64751,64760,64762,64764,64766,64770,64788,64801,
        64821,64843,64860,64890,64930,64943,64962,64973,64975,65000,
        65029,65043,65046,65048,65063,65076,65095,65101,65129,65132,
        65143,65147,65166,65184,65192,65197,65210,65238,65243-65244,
        65294-65295,65306,65310-65311,65318,65343,65347,65363,65367,65389,
        65391,65448,65456,65478-65479,65488,65503-65507,65514,65524,
        65530,65535
#endif /* _ORIGINAL_TOP_PORTS */
   };
    struct RangeList *ports = &masscan->ports;

    if (masscan->scan_type.tcp) {
        for (i=0; i<n && i<sizeof(top_tcp_ports)/sizeof(top_tcp_ports[0]); i++)
            rangelist_add_range(ports, top_tcp_ports[i], top_tcp_ports[i]);
    }
    if (masscan->scan_type.udp) {
        for (i=0; i<n && i<sizeof(top_tcp_ports)/sizeof(top_tcp_ports[0]); i++)
            rangelist_add_range(ports, top_tcp_ports[i], top_tcp_ports[i]);
    }

    /* Targets must be sorted after every change, before being used */
    rangelist_sort(ports);
}

/***************************************************************************
 ***************************************************************************/
static int
isInteger(const char *value)
{
    size_t i;
    
    if (value == NULL)
        return 0;
    
    for (i=0; value[i]; i++)
        if (!isdigit(value[i]&0xFF))
            return 0;
    return 1;
}

/***************************************************************************
 ***************************************************************************/
typedef int (*SET_PARAMETER)(struct Masscan *masscan, const char *name, const char *value);
enum {CONF_OK, CONF_WARN, CONF_ERR};

static int SET_arpscan(struct Masscan *masscan, const char *name, const char *value)
{
    struct Range range;

    UNUSEDPARM(name);
    UNUSEDPARM(value);

    if (masscan->echo) {
        if (masscan->scan_type.arp || masscan->echo_all)
            fprintf(masscan->echo, "arpscan = %s\n", masscan->scan_type.arp?"true":"false");
        return 0;
    }
    range.begin = Templ_ARP;
    range.end = Templ_ARP;
    rangelist_add_range(&masscan->ports, range.begin, range.end);
    rangelist_sort(&masscan->ports);
    masscan_set_parameter(masscan, "router-mac", "ff-ff-ff-ff-ff-ff");
    masscan->scan_type.arp = 1;
    LOG(5, "--arpscan\n");
    return CONF_OK;
}

static int SET_banners(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->is_banners || masscan->echo_all)
            fprintf(masscan->echo, "banners = %s\n", masscan->is_banners?"true":"false");
       return 0;
    }
    masscan->is_banners = parseBoolean(value);
    return CONF_OK;
}

static int SET_capture(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
        if (!masscan->is_capture_cert || masscan->echo_all)
            fprintf(masscan->echo, "%scapture = cert\n", masscan->is_capture_cert?"":"no");
        if (masscan->is_capture_html || masscan->echo_all)
            fprintf(masscan->echo, "%scapture = html\n", masscan->is_capture_html?"":"no");
        if (masscan->is_capture_heartbleed || masscan->echo_all)
            fprintf(masscan->echo, "%scapture = heartbleed\n", masscan->is_capture_heartbleed?"":"no");
        if (masscan->is_capture_ticketbleed || masscan->echo_all)
            fprintf(masscan->echo, "%scapture = ticketbleed\n", masscan->is_capture_ticketbleed?"":"no");
        return 0;
    }
    if (EQUALS("capture", name)) {
        if (EQUALS("cert", value))
            masscan->is_capture_cert = 1;
        else if (EQUALS("html", value))
            masscan->is_capture_html = 1;
        else if (EQUALS("heartbleed", value))
            masscan->is_capture_heartbleed = 1;
        else if (EQUALS("ticketbleed", value))
            masscan->is_capture_ticketbleed = 1;
        else {
            fprintf(stderr, "FAIL: %s: unknown capture type\n", value);
            return CONF_ERR;
        }
    } else if (EQUALS("nocapture", name)) {
        if (EQUALS("cert", value))
            masscan->is_capture_cert = 0;
        else if (EQUALS("html", value))
            masscan->is_capture_html = 0;
        else if (EQUALS("heartbleed", value))
            masscan->is_capture_heartbleed = 0;
        else if (EQUALS("ticketbleed", value))
            masscan->is_capture_ticketbleed = 0;
        else {
            fprintf(stderr, "FAIL: %s: unknown nocapture type\n", value);
            return CONF_ERR;
        }
    }
    return CONF_OK;
}

static int SET_hello(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->is_hello_ssl) {
            fprintf(masscan->echo, "hello = ssl\n");
        } else if (masscan->is_hello_smbv1) {
            fprintf(masscan->echo, "hello = smbv1\n");
        } else if (masscan->is_hello_http) {
            fprintf(masscan->echo, "hello = http\n");
        }
        return 0;
    }
    if (EQUALS("ssl", value))
        masscan->is_hello_ssl = 1;
    else if (EQUALS("smbv1", value))
        masscan->is_hello_smbv1 = 1;
    else if (EQUALS("http", value))
        masscan->is_hello_http = 1;
    else {
        fprintf(stderr, "FAIL: %s: unknown hello type\n", value);
        return CONF_ERR;
    }
    return CONF_OK;
}

static int SET_hello_file(struct Masscan *masscan, const char *name, const char *value)
{
    unsigned index;
    FILE *fp;
    int x;
    char buf[16384];
    char buf2[16384];
    size_t bytes_read;
    size_t bytes_encoded;
    char foo[64];

    if (masscan->echo) {
        //Echoed as a string "hello-string" that was originally read
        //from a file, not the "hello-filename"
        return 0;
    }
    
    index = ARRAY(name);
    if (index >= 65536) {
        fprintf(stderr, "%s: bad index\n", name);
        return CONF_ERR;
    }

    /* When connecting via TCP, send this file */
    x = fopen_s(&fp, value, "rb");
    if (x != 0) {
        LOG(0, "[FAILED] could not read hello file\n");
        perror(value);
        return CONF_ERR;
    }
    
    bytes_read = fread(buf, 1, sizeof(buf), fp);
    if (bytes_read == 0) {
        LOG(0, "[FAILED] could not read hello file\n");
        perror(value);
        fclose(fp);
        return CONF_ERR;
    }
    fclose(fp);
    
    bytes_encoded = base64_encode(buf2, sizeof(buf2)-1, buf, bytes_read);
    buf2[bytes_encoded] = '\0';
    
    sprintf_s(foo, sizeof(foo), "hello-string[%u]", (unsigned)index);
    
    masscan_set_parameter(masscan, foo, buf2);

    return CONF_OK;
}

static int SET_hello_string(struct Masscan *masscan, const char *name, const char *value)
{
    unsigned index;
    char *value2;
    struct TcpCfgPayloads *pay;

    if (masscan->echo) {
        for (pay = masscan->payloads.tcp; pay; pay = pay->next) {
            fprintf(masscan->echo, "hello-string[%u] = %s\n",
                    pay->port, pay->payload_base64);
        }
        return 0;
    }
    
    index = ARRAY(name);
    if (index >= 65536) {
        fprintf(stderr, "%s: bad index\n", name);
        exit(1);
    }

    
    value2 = STRDUP(value);

    pay = MALLOC(sizeof(*pay));
    
    pay->payload_base64 = value2;
    pay->port = index;
    pay->next = masscan->payloads.tcp;
    masscan->payloads.tcp = pay;
    return CONF_OK;
}

static int SET_hello_timeout(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->tcp_hello_timeout || masscan->echo_all)
            fprintf(masscan->echo, "hello-timeout = %u\n", masscan->tcp_hello_timeout);
        return 0;
    }
    masscan->tcp_hello_timeout = (unsigned)parseInt(value);
    return CONF_OK;
}

static int SET_min_packet(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->min_packet_size != 60 || masscan->echo_all)
            fprintf(masscan->echo, "min-packet = %u\n", masscan->min_packet_size);
        return 0;
    }
    masscan->min_packet_size = (unsigned)parseInt(value);
    return CONF_OK;
}


static int SET_nobanners(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        return 0;
    }
    masscan->is_banners = !parseBoolean(value);
    return CONF_OK;
}

static int SET_noreset(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->is_noreset || masscan->echo_all)
            fprintf(masscan->echo, "noreset = %s\n", masscan->is_noreset?"true":"false");
        return 0;
    }
    masscan->is_noreset = parseBoolean(value);
    return CONF_OK;
}

static int SET_nmap_payloads(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    
    if (masscan->echo) {
        if ((masscan->payloads.nmap_payloads_filename && masscan->payloads.nmap_payloads_filename[0]) || masscan->echo_all)
            fprintf(masscan->echo, "nmap-payloads = %s\n", masscan->payloads.nmap_payloads_filename);
        return 0;
    }
    
    if (masscan->payloads.nmap_payloads_filename)
        free(masscan->payloads.nmap_payloads_filename);
    masscan->payloads.nmap_payloads_filename = strdup(value);

    return CONF_OK;
}

static int SET_nmap_service_probes(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    
    if (masscan->echo) {
        if ((masscan->payloads.nmap_service_probes_filename && masscan->payloads.nmap_service_probes_filename[0]) || masscan->echo_all)
            fprintf(masscan->echo, "nmap-service-probes = %s\n", masscan->payloads.nmap_service_probes_filename);
        return 0;
    }
    
    if (masscan->payloads.nmap_service_probes_filename)
        free(masscan->payloads.nmap_service_probes_filename);
    masscan->payloads.nmap_service_probes_filename = strdup(value);
    
    
    return CONF_OK;
}

static int SET_output_append(struct Masscan *masscan, const char *name, const char *value)
{
    if (masscan->echo) {
        if (masscan->output.is_append || masscan->echo_all)
            fprintf(masscan->echo, "output-append = %s\n",
                    masscan->output.is_append?"true":"false");
        return 0;
    }
    if (EQUALS("overwrite", name) || !parseBoolean(value))
        masscan->output.is_append = 0;
    else
        masscan->output.is_append = 1;
    return CONF_OK;
}

static int SET_output_filename(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->output.filename[0] || masscan->echo_all)
            fprintf(masscan->echo, "output-filename = %s\n", masscan->output.filename);
        return 0;
    }
    if (masscan->output.format == 0)
        masscan->output.format = Output_XML; /*TODO: Why is the default XML?*/
    strcpy_s(masscan->output.filename,
             sizeof(masscan->output.filename),
             value);
    return CONF_OK;
}

static int SET_output_format(struct Masscan *masscan, const char *name, const char *value)
{
    enum OutputFormat x = 0;
    UNUSEDPARM(name);
    if (masscan->echo) {
        FILE *fp = masscan->echo;
        switch (masscan->output.format) {
            case Output_Default:    if (masscan->echo_all) fprintf(fp, "output-format = interactive\n"); break;
            case Output_Interactive:fprintf(fp, "output-format = interactive\n"); break;
            case Output_List:       fprintf(fp, "output-format = list\n"); break;
            case Output_Unicornscan:fprintf(fp, "output-format = unicornscan\n"); break;
            case Output_XML:        fprintf(fp, "output-format = xml\n"); break;
            case Output_Binary:     fprintf(fp, "output-format = binary\n"); break;
            case Output_Grepable:   fprintf(fp, "output-format = grepable\n"); break;
            case Output_JSON:       fprintf(fp, "output-format = json\n"); break;
            case Output_NDJSON:     fprintf(fp, "output-format = ndjson\n"); break;
            case Output_Certs:      fprintf(fp, "output-format = certs\n"); break;
            case Output_None:       fprintf(fp, "output-format = none\n"); break;
            case Output_Redis:
                fprintf(fp, "output-format = redis\n");
                fprintf(fp, "redis = %u.%u.%u.%u:%u\n",
                        (unsigned char)(masscan->redis.ip>>24),
                        (unsigned char)(masscan->redis.ip>>16),
                        (unsigned char)(masscan->redis.ip>> 8),
                        (unsigned char)(masscan->redis.ip>> 0),
                        masscan->redis.port);
                break;
                
            default:
                fprintf(fp, "output-format = unknown(%u)\n", masscan->output.format);
                break;
        }
        return 0;
    }
    if (EQUALS("unknown(0)", value))        x = Output_Interactive;
    else if (EQUALS("interactive", value))  x = Output_Interactive;
    else if (EQUALS("list", value))         x = Output_List;
    else if (EQUALS("unicornscan", value))  x = Output_Unicornscan;
    else if (EQUALS("xml", value))          x = Output_XML;
    else if (EQUALS("binary", value))       x = Output_Binary;
    else if (EQUALS("greppable", value))    x = Output_Grepable;
    else if (EQUALS("grepable", value))     x = Output_Grepable;
    else if (EQUALS("json", value))         x = Output_JSON;
    else if (EQUALS("ndjson", value))       x = Output_NDJSON;
    else if (EQUALS("certs", value))        x = Output_Certs;
    else if (EQUALS("none", value))         x = Output_None;
    else if (EQUALS("redis", value))        x = Output_Redis;
    else {
        LOG(0, "FAIL: unknown output-format: %s\n", value);
        LOG(0, "  hint: 'binary', 'xml', 'grepable', ...\n");
        return CONF_ERR;
    }
    masscan->output.format = x;

    return CONF_OK;
}

static int SET_output_noshow(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->echo_all) {
            fprintf(masscan->echo, "output-noshow = %s%s%s\n",
                    (!masscan->output.is_show_open)?"open,":"",
                    (!masscan->output.is_show_closed)?"closed,":"",
                    (!masscan->output.is_show_host)?"host,":""
                    );
        }
        return 0;
    }
    for (;;) {
        const char *val2 = value;
        unsigned val2_len = INDEX_OF(val2, ',');
        if (val2_len == 0)
            break;
        if (EQUALSx("open", val2, val2_len))
            masscan->output.is_show_open = 0;
        else if (EQUALSx("closed", val2, val2_len) || EQUALSx("close", val2, val2_len))
            masscan->output.is_show_closed = 0;
        else if (EQUALSx("open", val2, val2_len))
            masscan->output.is_show_host = 0;
        else if (EQUALSx("all",val2,val2_len)) {
            masscan->output.is_show_open = 0;
            masscan->output.is_show_host = 0;
            masscan->output.is_show_closed = 0;
        }
        else {
            LOG(0, "FAIL: unknown 'noshow' spec: %.*s\n", val2_len, val2);
            exit(1);
        }
        value += val2_len;
        while (*value == ',')
            value++;
    }
    return CONF_OK;
}

static int SET_output_show(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->echo_all) {
            fprintf(masscan->echo, "output-show = %s%s%s\n",
                    masscan->output.is_show_open?"open,":"",
                    masscan->output.is_show_closed?"closed,":"",
                    masscan->output.is_show_host?"host,":""
                    );
        }
        return 0;
    }
    for (;;) {
        const char *val2 = value;
        unsigned val2_len = INDEX_OF(val2, ',');
        if (val2_len == 0)
            break;
        if (EQUALSx("open", val2, val2_len))
            masscan->output.is_show_open = 1;
        else if (EQUALSx("closed", val2, val2_len) || EQUALSx("close", val2, val2_len))
            masscan->output.is_show_closed = 1;
        else if (EQUALSx("open", val2, val2_len))
            masscan->output.is_show_host = 1;
        else if (EQUALSx("all",val2,val2_len)) {
            masscan->output.is_show_open = 1;
            masscan->output.is_show_host = 1;
            masscan->output.is_show_closed = 1;
        }
        else {
            LOG(0, "FAIL: unknown 'show' spec: %.*s\n", val2_len, val2);
            exit(1);
        }
        value += val2_len;
        while (*value == ',')
            value++;
    }
    return CONF_OK;
}
static int SET_output_show_open(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    UNUSEDPARM(value);
    if (masscan->echo) {
        return 0;
    }
    /* "open" "open-only" */
    masscan->output.is_show_open = 1;
    masscan->output.is_show_closed = 0;
    masscan->output.is_show_host = 0;
    return CONF_OK;
}
static int SET_pcap_filename(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->pcap_filename[0])
            fprintf(masscan->echo, "pcap-filename = %s\n", masscan->pcap_filename);
        return 0;
    }
    if (value)
        strcpy_s(masscan->pcap_filename, sizeof(masscan->pcap_filename), value);
    return CONF_OK;
}

static int SET_pcap_payloads(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if ((masscan->payloads.pcap_payloads_filename && masscan->payloads.pcap_payloads_filename[0]) || masscan->echo_all)
            fprintf(masscan->echo, "pcap-payloads = %s\n", masscan->payloads.pcap_payloads_filename);
        return 0;
    }
    
    if (masscan->payloads.pcap_payloads_filename)
        free(masscan->payloads.pcap_payloads_filename);
    masscan->payloads.pcap_payloads_filename = strdup(value);
    
    /* file will be loaded in "masscan_load_database_files()" */
    
    return CONF_OK;
}


static int SET_randomize_hosts(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    UNUSEDPARM(value);
    if (masscan->echo) {
        //fprintf(masscan->echo, "randomize-hosts = true\n");
        return 0;
    }
    return CONF_OK;
}


static int SET_rate(struct Masscan *masscan, const char *name, const char *value)
{
    double rate = 0.0;
    double point = 10.0;
    unsigned i;
    
    if (masscan->echo) {
        fprintf(masscan->echo, "rate = %-10.2f\n", masscan->max_rate);
        return 0;
    }
    
    for (i=0; value[i] && value[i] != '.'; i++) {
        char c = value[i];
        if (c < '0' || '9' < c) {
            fprintf(stderr, "CONF: non-digit in rate spec: %s=%s\n", name, value);
            return CONF_ERR;
        }
        rate = rate * 10.0 + (c - '0');
    }
    
    if (value[i] == '.') {
        i++;
        while (value[i]) {
            char c = value[i];
            if (c < '0' || '9' < c) {
                fprintf(stderr, "CONF: non-digit in rate spec: %s=%s\n",
                        name, value);
                return CONF_ERR;
            }
            rate += (c - '0')/point;
            point /= 10.0;
            value++;
        }
    }
    
    masscan->max_rate = rate;
    return CONF_OK;
}

static int SET_resume_count(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->resume.count || masscan->echo_all) {
            fprintf(masscan->echo, "resume-count = %" PRIu64 "\n", masscan->resume.count);
        }
        return 0;
    }
    masscan->resume.count = parseInt(value);
    return CONF_OK;
}

static int SET_resume_index(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->resume.index  || masscan->echo_all) {
            fprintf(masscan->echo, "\n# resume information\n");
            fprintf(masscan->echo, "resume-index = %" PRIu64 "\n", masscan->resume.index);
        }
        return 0;
    }
    masscan->resume.index = parseInt(value);
    return CONF_OK;
}

static int SET_retries(struct Masscan *masscan, const char *name, const char *value)
{
    uint64_t x;
    
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->retries || masscan->echo_all)
            fprintf(masscan->echo, "retries = %u\n", masscan->retries);
        return 0;
    }
    x = strtoul(value, 0, 0);
    if (x >= 1000) {
        fprintf(stderr, "FAIL: retries=<n>: expected number less than 1000\n");
        return CONF_ERR;
    }
    masscan->retries = (unsigned)x;
    return CONF_OK;
    
}

static int SET_rotate_time(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->output.rotate.timeout || masscan->echo_all)
            fprintf(masscan->echo, "rotate = %u\n", masscan->output.rotate.timeout);
        return 0;
    }
    masscan->output.rotate.timeout = (unsigned)parseTime(value);
    return CONF_OK;
}
static int SET_rotate_directory(struct Masscan *masscan, const char *name, const char *value)
{
    char *p;
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (memcmp(masscan->output.rotate.directory, ".",2) != 0 || masscan->echo_all) {
            fprintf(masscan->echo, "rotate-dir = %s\n", masscan->output.rotate.directory);
        }
        return 0;
    }
    strcpy_s(   masscan->output.rotate.directory,
             sizeof(masscan->output.rotate.directory),
             value);
    /* strip trailing slashes */
    p = masscan->output.rotate.directory;
    while (*p && (p[strlen(p)-1] == '/' || p[strlen(p)-1] == '/'))
        p[strlen(p)-1] = '\0';
    return CONF_OK;
}
static int SET_rotate_offset(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    /* Time offset, otherwise output files are aligned to nearest time
     * interval, e.g. at the start of the hour for "hourly" */
    if (masscan->echo) {
        if (masscan->output.rotate.offset || masscan->echo_all)
            fprintf(masscan->echo, "rotate-offset = %u\n", masscan->output.rotate.offset);
        return 0;
    }
    masscan->output.rotate.offset = (unsigned)parseTime(value);
    return CONF_OK;
}
static int SET_rotate_filesize(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->output.rotate.filesize || masscan->echo_all)
            fprintf(masscan->echo, "rotate-size = %" PRIu64 "\n", masscan->output.rotate.filesize);
        return 0;
    }
    masscan->output.rotate.filesize = parseSize(value);
    return CONF_OK;
    
}

static int SET_script(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if ((masscan->scripting.name && masscan->scripting.name[0]) || masscan->echo_all)
            fprintf(masscan->echo, "script = %s\n", masscan->scripting.name);
        return 0;
    }
    if (value && value[0])
        masscan->is_scripting = 1;
    else
        masscan->is_scripting = 0;
    
    if (masscan->scripting.name)
        free(masscan->scripting.name);
    
    masscan->scripting.name = strdup(value);
    
    return CONF_OK;
}


static int SET_seed(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        fprintf(masscan->echo, "seed = %" PRIu64 "\n", masscan->seed);
        return 0;
    }
    if (EQUALS("time", value))
        masscan->seed = time(0);
    else
        masscan->seed = parseInt(value);
    return CONF_OK;
}

static int SET_space(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    UNUSEDPARM(value);
    if (masscan->echo) {
        fprintf(masscan->echo, "\n");
        return 0;
    }
    return CONF_OK;
}

static int SET_shard(struct Masscan *masscan, const char *name, const char *value)
{
    unsigned one = 0;
    unsigned of = 0;

    UNUSEDPARM(name);
    if (masscan->echo) {
        if ((masscan->shard.one != 1 && masscan->shard.of != 1)  || masscan->echo_all)
            fprintf(masscan->echo, "shard = %u/%u\n", masscan->shard.one, masscan->shard.of);
        return 0;
    }
    while (isdigit(*value))
        one = one*10 + (*(value++)) - '0';
    while (ispunct(*value))
        value++;
    while (isdigit(*value))
        of = of*10 + (*(value++)) - '0';
    
    if (one < 1) {
        LOG(0, "FAIL: shard index can't be zero\n");
        LOG(0, "hint   it goes like 1/4 2/4 3/4 4/4\n");
        return CONF_ERR;
    }
    if (one > of) {
        LOG(0, "FAIL: shard spec is wrong\n");
        LOG(0, "hint   it goes like 1/4 2/4 3/4 4/4\n");
        return CONF_ERR;
    }
    masscan->shard.one = one;
    masscan->shard.of = of;
    return CONF_OK;
}

static int SET_output_stylesheet(struct Masscan *masscan, const char *name, const char *value)
{
    UNUSEDPARM(name);
    if (masscan->echo) {
        if (masscan->output.stylesheet[0] || masscan->echo_all)
            fprintf(masscan->echo, "stylesheet = %s\n", masscan->output.stylesheet);
        return 0;
    }
    
    if (masscan->output.format == 0)
        masscan->output.format = Output_XML;
    
    strcpy_s(masscan->output.stylesheet, sizeof(masscan->output.stylesheet), value);
    return CONF_OK;
}



struct ConfigParameter {
    const char *name;
    SET_PARAMETER set;
    unsigned flags;
    const char *alts[6];
};
enum {F_NONE, F_BOOL};
struct ConfigParameter config_parameters[] = {
    {"resume-index",    SET_resume_index,       0,      {0}},
    {"resume-count",    SET_resume_count,       0,      {0}},
    {"seed",            SET_seed,               0,      {0}},
    {"arpscan",         SET_arpscan,            F_BOOL, {"arp",0}},
    {"randomize-hosts", SET_randomize_hosts,    F_BOOL, {0}},
    {"rate",            SET_rate,               0,      {"max-rate",0}},
    {"shard",           SET_shard,              0,      {"shards",0}},
    {"banners",         SET_banners,            F_BOOL, {"banner",0}},
    {"nobanners",       SET_nobanners,          F_BOOL, {"nobanner",0}},
    {"retries",         SET_retries,            0,      {"retry", "max-retries", "max-retry", 0}},
    {"noreset",         SET_noreset,            F_BOOL, {0}},
    {"nmap-payloads",   SET_nmap_payloads,      0,      {"nmap-payload",0}},
    {"nmap-service-probes",SET_nmap_service_probes, 0,  {"nmap-service-probe",0}},
    {"pcap-filename",   SET_pcap_filename,      0,      {"pcap",0}},
    {"pcap-payloads",   SET_pcap_payloads,      0,      {"pcap-payload",0}},
    {"hello",           SET_hello,              0,      {0}},
    {"hello-file",      SET_hello_file,         0,      {"hello-filename",0}},
    {"hello-string",    SET_hello_string,       0,      {0}},
    {"hello-timeout",   SET_hello_timeout,      0,      {0}},
    {"min-packet",      SET_min_packet,         0,      {"min-pkt",0}},
    {"capture",         SET_capture,            0,      {0}},
    {"SPACE",           SET_space,              0,      {0}},
    {"output-filename", SET_output_filename,    0,      {"output-file",0}},
    {"output-format",   SET_output_format,      0,      {0}},
    {"output-show",     SET_output_show,        0,      {"output-status", "show",0}},
    {"output-noshow",   SET_output_noshow,      0,      {"noshow",0}},
    {"output-show-open",SET_output_show_open,   F_BOOL, {"open", "open-only", 0}},
    {"output-append",   SET_output_append,      0,      {"append-output",0}},
    {"rotate",          SET_rotate_time,        0,      {"output-rotate", "rotate-output", "rotate-time", 0}},
    {"rotate-dir",      SET_rotate_directory,   0,      {"output-rotate-dir", "rotate-directory", 0}},
    {"rotate-offset",   SET_rotate_offset,      0,      {"output-rotate-offset", 0}},
    {"rotate-size",     SET_rotate_filesize,    0,      {"output-rotate-filesize", "rotate-filesize", 0}},
    {"stylesheet",      SET_output_stylesheet,  0,      {0}},
    {"script",          SET_script,             0,      {0}},
    {"SPACE",           SET_space,              0,      {0}},
    {0}
};

/***************************************************************************
 * Called either from the "command-line" parser when it sees a --parm,
 * or from the "config-file" parser for normal options.
 ***************************************************************************/
void
masscan_set_parameter(struct Masscan *masscan,
                      const char *name, const char *value)
{
    unsigned index = ARRAY(name);
    if (index >= 65536) {
        fprintf(stderr, "%s: bad index\n", name);
        exit(1);
    }
    
    /*
     * NEW:
     * Go through configured list of parameters
     */
    {
        size_t i;
        
        for (i=0; config_parameters[i].name; i++) {
            if (EQUALS(config_parameters[i].name, name)) {
                config_parameters[i].set(masscan, name, value);
                return;
            } else {
                size_t j;
                for (j=0; config_parameters[i].alts[j]; j++) {
                    if (EQUALS(config_parameters[i].alts[j], name)) {
                        config_parameters[i].set(masscan, name, value);
                        return;
                    }
                }
            }
        }
    }

    /*
     * OLD:
     * Configure the old parameters, the ones we don't have in the new config
     * system yet (see the NEW part above).
     * TODO: transition all these old params to the new system
     */
    if (EQUALS("conf", name) || EQUALS("config", name)) {
        masscan_read_config_file(masscan, value);
    } else if (EQUALS("adapter", name) || EQUALS("if", name) || EQUALS("interface", name)) {
        if (masscan->nic[index].ifname[0]) {
            fprintf(stderr, "CONF: overwriting \"adapter=%s\"\n", masscan->nic[index].ifname);
        }
        if (masscan->nic_count < index + 1)
            masscan->nic_count = index + 1;
        sprintf_s(  masscan->nic[index].ifname,
                    sizeof(masscan->nic[index].ifname),
                    "%s",
                    value);

    }
    else if (EQUALS("adapter-ip", name) || EQUALS("source-ip", name)
             || EQUALS("source-address", name) || EQUALS("spoof-ip", name)
             || EQUALS("spoof-address", name) || EQUALS("src-ip", name)) {
        /* Send packets FROM this IP address */
        struct Range range;

        range = range_parse_ipv4(value, 0, 0);

        /* Check for bad format */
        if (range.begin > range.end) {
            LOG(0, "FAIL: bad source IPv4 address: %s=%s\n",
                    name, value);
            LOG(0, "hint   addresses look like \"19.168.1.23\"\n");
            exit(1);
        }

        /* If more than one IP address given, make the range is
            * an even power of two (1, 2, 4, 8, 16, ...) */
        if (!is_power_of_two((uint64_t)range.end - range.begin + 1)) {
            LOG(0, "FAIL: range must be even power of two: %s=%s\n",
                    name, value);
            exit(1);
        }

        masscan->nic[index].src.ip.first = range.begin;
        masscan->nic[index].src.ip.last = range.end;
        masscan->nic[index].src.ip.range = range.end - range.begin + 1;
    } else if (EQUALS("adapter-port", name) || EQUALS("source-port", name)
               || EQUALS("src-port", name)) {
        /* Send packets FROM this port number */
        unsigned is_error = 0;
        struct RangeList ports = {0};
        memset(&ports, 0, sizeof(ports));

        rangelist_parse_ports(&ports, value, &is_error, 0);

        /* Check if there was an error in parsing */
        if (is_error) {
            LOG(0, "FAIL: bad source port specification: %s\n",
                    name);
            exit(1);
        }

        /* Only allow one range of ports */
        if (ports.count != 1) {
            LOG(0, "FAIL: only one '%s' range may be specified, found %u ranges\n",
                    name, ports.count);
            exit(1);
        }

        /* verify range is even power of 2 (1, 2, 4, 8, 16, ...) */
        if (!is_power_of_two(ports.list[0].end - ports.list[0].begin + 1)) {
            LOG(0, "FAIL: source port range must be even power of two: %s=%s\n",
                    name, value);
            exit(1);
        }

        masscan->nic[index].src.port.first = ports.list[0].begin;
        masscan->nic[index].src.port.last = ports.list[0].end;
        masscan->nic[index].src.port.range = ports.list[0].end - ports.list[0].begin + 1;
    } else if (EQUALS("adapter-mac", name) || EQUALS("spoof-mac", name)
               || EQUALS("source-mac", name) || EQUALS("src-mac", name)) {
        /* Send packets FROM this MAC address */
        unsigned char mac[6];

        if (parse_mac_address(value, mac) != 0) {
            fprintf(stderr, "CONF: bad MAC address: %s=%s\n", name, value);
            return;
        }

        /* Check for duplicates */
        if (memcmp(masscan->nic[index].my_mac, mac, 6) == 0)
            return;

        /* Warn if we are overwriting a Mac address */
        if (masscan->nic[index].my_mac_count != 0) {
            LOG(0, "WARNING: overwriting MAC address\n");
        }

        memcpy(masscan->nic[index].my_mac, mac, 6);
        masscan->nic[index].my_mac_count = 1;
    }
    else if (EQUALS("router-mac", name) || EQUALS("router", name)
             || EQUALS("dest-mac", name) || EQUALS("destination-mac", name)
             || EQUALS("dst-mac", name) || EQUALS("target-mac", name)) {
        unsigned char mac[6];

        if (parse_mac_address(value, mac) != 0) {
            fprintf(stderr, "CONF: bad MAC address: %s=%s\n", name, value);
            return;
        }

        memcpy(masscan->nic[index].router_mac, mac, 6);
    }
    else if (EQUALS("router-ip", name)) {
        /* Send packets FROM this IP address */
        struct Range range;

        range = range_parse_ipv4(value, 0, 0);

        /* Check for bad format */
        if (range.begin != range.end) {
            LOG(0, "FAIL: bad source IPv4 address: %s=%s\n",
                    name, value);
            LOG(0, "hint   addresses look like \"19.168.1.23\"\n");
            exit(1);
        }

        masscan->nic[index].router_ip = range.begin;
    }
    else if (EQUALS("udp-ports", name) || EQUALS("udp-port", name)) {
        unsigned is_error = 0;
        masscan->scan_type.udp = 1;
        rangelist_parse_ports(&masscan->ports, value, &is_error, Templ_UDP);
        if (masscan->op == 0)
            masscan->op = Operation_Scan;
    }
    else if (EQUALS("oprotos", name) || EQUALS("oproto", name)) {
        unsigned is_error = 0;
        masscan->scan_type.oproto = 1;
        rangelist_parse_ports(&masscan->ports, value, &is_error, Templ_Oproto_first);
        if (masscan->op == 0)
            masscan->op = Operation_Scan;
    }
    else if (EQUALS("tcp-ports", name) || EQUALS("tcp-port", name)) {
        unsigned is_error = 0;
        masscan->scan_type.tcp = 1;
        rangelist_parse_ports(&masscan->ports, value, &is_error, Templ_TCP);
        if (masscan->op == 0)
            masscan->op = Operation_Scan;
    }
    else if (EQUALS("ports", name) || EQUALS("port", name)
             || EQUALS("dst-port", name) || EQUALS("dest-port", name)
             || EQUALS("destination-port", name)
             || EQUALS("target-port", name)) {
        unsigned is_error = 0;
        if (masscan->scan_type.udp)
            rangelist_parse_ports(&masscan->ports, value, &is_error, Templ_UDP);
        else
            rangelist_parse_ports(&masscan->ports, value, &is_error, 0);
        if (masscan->op == 0)
            masscan->op = Operation_Scan;
    }
    else if (EQUALS("banner-types", name) || EQUALS("banner-type", name)
             || EQUALS("banner-apps", name) || EQUALS("banner-app", name)
           ) {
        enum ApplicationProtocol app;
        
        app = masscan_string_to_app(value);
        
        if (app) {
            rangelist_add_range(&masscan->banner_types, app, app);
            rangelist_sort(&masscan->banner_types);
        } else {
            LOG(0, "FAIL: bad banner app: %s\n", value);
            fprintf(stderr, "err\n");
            exit(1);
        }
    } else if (EQUALS("exclude-ports", name) || EQUALS("exclude-port", name)) {
        unsigned is_error = 0;
        rangelist_parse_ports(&masscan->exclude_port, value, &is_error, 0);
        if (is_error) {
            LOG(0, "FAIL: bad exclude port: %s\n", value);
            exit(1);
        }
    } else if (EQUALS("bpf", name)) {
        size_t len = strlen(value) + 1;
        if (masscan->bpf_filter)
            free(masscan->bpf_filter);
        masscan->bpf_filter = MALLOC(len);
        memcpy(masscan->bpf_filter, value, len);
    } else if (EQUALS("ping", name) || EQUALS("ping-sweep", name)) {
        /* Add ICMP ping request */
        struct Range range;
        range.begin = Templ_ICMP_echo;
        range.end = Templ_ICMP_echo;
        rangelist_add_range(&masscan->ports, range.begin, range.end);
        rangelist_sort(&masscan->ports);
        masscan->scan_type.ping = 1;
        LOG(5, "--ping\n");
    } else if (EQUALS("range", name) || EQUALS("ranges", name)
               || EQUALS("ip", name) || EQUALS("ipv4", name)
               || EQUALS("dst-ip", name) || EQUALS("dest-ip", name)
               || EQUALS("destination-ip", name)
               || EQUALS("target-ip", name)) {
        const char *ranges = value;
        unsigned offset = 0;
        unsigned max_offset = (unsigned)strlen(ranges);

        for (;;) {
            struct Range range;

            range = range_parse_ipv4(ranges, &offset, max_offset);
            if (range.end < range.begin) {
                fprintf(stderr, "ERROR: bad IP address/range: %s\n", ranges);
                break;
            }

            rangelist_add_range(&masscan->targets, range.begin, range.end);

            if (offset >= max_offset || ranges[offset] != ',')
                break;
            else
                offset++; /* skip comma */
        }
        if (masscan->op == 0)
            masscan->op = Operation_Scan;
    }
    else if (
                EQUALS("exclude", name) ||
                EQUALS("exclude-range", name) ||
                EQUALS("exclude-ranges", name) ||
                EQUALS("exclude-ip", name) ||
                EQUALS("exclude-ipv4", name)
                ) {
        const char *ranges = value;
        unsigned offset = 0;
        unsigned max_offset = (unsigned)strlen(ranges);

        for (;;) {
            struct Range range;

            range = range_parse_ipv4(ranges, &offset, max_offset);
            if (range.begin == 0 && range.end == 0) {
                fprintf(stderr, "CONF: bad range spec: %s\n", ranges);
                exit(1);
            }

            rangelist_add_range(&masscan->exclude_ip, range.begin, range.end);

            if (offset >= max_offset || ranges[offset] != ',')
                break;
            else
                offset++; /* skip comma */
        }
        if (masscan->op == 0)
            masscan->op = Operation_Scan;
    } else if (EQUALS("badsum", name)) {
        masscan->nmap.badsum = 1;
    } else if (EQUALS("banner1", name)) {
        banner1_test(value);
        exit(1);
    } else if (EQUALS("blackrock-rounds", name)) {
        masscan->blackrock_rounds = (unsigned)parseInt(value);
    } else if (EQUALS("connection-timeout", name) || EQUALS("tcp-timeout", name)) {
        /* The timeout for banners TCP connections */
        masscan->tcp_connection_timeout = (unsigned)parseInt(value);
    } else if (EQUALS("datadir", name)) {
        strcpy_s(masscan->nmap.datadir, sizeof(masscan->nmap.datadir), value);
    } else if (EQUALS("data-length", name)) {
        unsigned x = (unsigned)strtoul(value, 0, 0);
        if (x >= 1514 - 14 - 40) {
            fprintf(stderr, "error: %s=<n>: expected number less than 1500\n", name);
        } else {
            masscan->nmap.data_length = x;
        }
    } else if (EQUALS("debug", name)) {
        if (EQUALS("if", value)) {
            masscan->op = Operation_DebugIF;
        }
    } else if (EQUALS("dns-servers", name)) {
        fprintf(stderr, "nmap(%s): unsupported: DNS lookups too synchronous\n",
                name);
        exit(1);
    } else if (EQUALS("echo", name) || EQUALS("echo-all", name)) {
        masscan_echo(masscan, stdout, EQUALS("echo-all", name));
        exit(0);
    } else if (EQUALS("excludefile", name)) {
        unsigned count1 = masscan->exclude_ip.count;
        unsigned count2;
        int err;
        const char *filename = value;

        LOG(1, "EXCLUDING: %s\n", value);
        err = rangefile_read(filename, &masscan->exclude_ip, &masscan->exclude_ipv6);
        if (err) {
            LOG(0, "FAIL: error reading from exclude file\n");
            exit(1);
        }

        /* Detect if this file has made any change, otherwise don't print
         * a message */
        count2 = masscan->exclude_ip.count;
        if (count2 - count1)
            fprintf(stderr, "%s: excluding %u ranges from file\n",
                value, count2 - count1);
    } else if (EQUALS("heartbleed", name)) {
        masscan->is_heartbleed = 1;
        masscan_set_parameter(masscan, "no-capture", "cert");
        masscan_set_parameter(masscan, "no-capture", "heartbleed");
        masscan_set_parameter(masscan, "banners", "true");
    } else if (EQUALS("ticketbleed", name)) {
        masscan->is_ticketbleed = 1;
        masscan_set_parameter(masscan, "no-capture", "cert");
        masscan_set_parameter(masscan, "no-capture", "ticketbleed");
        masscan_set_parameter(masscan, "banners", "true");
    } else if (EQUALS("host-timeout", name)) {
        fprintf(stderr, "nmap(%s): unsupported: this is an asynchronous tool, so no timeouts\n", name);
        exit(1);
    } else if (EQUALS("http-user-agent", name)) {
        if (masscan->http_user_agent)
            free(masscan->http_user_agent);
        masscan->http_user_agent_length = (unsigned)strlen(value);
        masscan->http_user_agent = MALLOC(masscan->http_user_agent_length+1);
        memcpy( masscan->http_user_agent,
                value,
                masscan->http_user_agent_length+1
                );
    } else if (memcmp("http-header", name, 11) == 0) {
        unsigned j;
        unsigned name_length;
        char *newname;
        unsigned value_length = (unsigned)strlen(value);
        unsigned char *newvalue;

        /* allocate new value */
        newvalue = MALLOC(value_length+1);
        memcpy(newvalue, value, value_length+1);
        newvalue[value_length] = '\0';

        /* allocate a new name */
        name += 11;
        while (ispunct(*name))
            name++;
        name_length = (unsigned)strlen(name);
        while (name_length && ispunct(name[name_length-1]))
            name_length--;
        newname = MALLOC(name_length+1);
        memcpy(newname, name, name_length+1);
        newname[name_length] = '\0';


        for (j=0; j < sizeof(masscan->http_headers)/sizeof(masscan->http_headers[0]); j++) {
            if (masscan->http_headers[j].header_name == 0) {
                masscan->http_headers[j].header_name = newname;
                masscan->http_headers[j].header_value = newvalue;
                masscan->http_headers[j].header_value_length = value_length;
                return;
            }
        }

    } else if (EQUALS("iflist", name)) {
        masscan->op = Operation_List_Adapters;
    } else if (EQUALS("includefile", name)) {
        int err;
        const char *filename = value;

        err = rangefile_read(filename, &masscan->targets, &masscan->targets_ipv6);
        if (err) {
            LOG(0, "FAIL: error reading from include file\n");
            exit(1);
        }
        if (masscan->op == 0)
            masscan->op = Operation_Scan;
    } else if (EQUALS("infinite", name)) {
        masscan->is_infinite = 1;
    } else if (EQUALS("interactive", name)) {
        masscan->output.is_interactive = 1;
    } else if (EQUALS("nointeractive", name)) {
        masscan->output.is_interactive = 0;
    } else if (EQUALS("status", name)) {
        masscan->output.is_status_updates = 1;
    } else if (EQUALS("nostatus", name)) {
        masscan->output.is_status_updates = 0;
    } else if (EQUALS("ip-options", name)) {
        fprintf(stderr, "nmap(%s): unsupported: maybe soon\n", name);
        exit(1);
    } else if (EQUALS("log-errors", name)) {
        fprintf(stderr, "nmap(%s): unsupported: maybe soon\n", name);
        exit(1);
    } else if (EQUALS("min-hostgroup", name) || EQUALS("max-hostgroup", name)) {
        fprintf(stderr, "nmap(%s): unsupported: we randomize all the groups!\n", name);
        exit(1);
    } else if (EQUALS("min-parallelism", name) || EQUALS("max-parallelism", name)) {
        fprintf(stderr, "nmap(%s): unsupported: we all the parallel!\n", name);
        exit(1);
    } else if (EQUALS("min-rtt-timeout", name) || EQUALS("max-rtt-timeout", name) || EQUALS("initial-rtt-timeout", name)) {
        fprintf(stderr, "nmap(%s): unsupported: we are asychronous, so no timeouts, no RTT tracking!\n", name);
        exit(1);
    } else if (EQUALS("min-rate", name)) {
        fprintf(stderr, "nmap(%s): unsupported, we go as fast as --max-rate allows\n", name);
        /* no exit here, since it's just info */
    } else if (EQUALS("mtu", name)) {
        fprintf(stderr, "nmap(%s): fragmentation not yet supported\n", name);
        exit(1);
    } else if (EQUALS("nmap", name)) {
        print_nmap_help();
        exit(1);
    } else if (EQUALS("offline", name)) {
        /* Run in "offline" mode where it thinks it's sending packets, but
         * it's not */
        masscan->is_offline = 1;
    } else if (EQUALS("osscan-limit", name)) {
        fprintf(stderr, "nmap(%s): OS scanning unsupported\n", name);
        exit(1);
    } else if (EQUALS("osscan-guess", name)) {
        fprintf(stderr, "nmap(%s): OS scanning unsupported\n", name);
        exit(1);
    } else if (EQUALS("packet-trace", name) || EQUALS("trace-packet", name)) {
        masscan->nmap.packet_trace = 1;
    } else if (EQUALS("privileged", name) || EQUALS("unprivileged", name)) {
        fprintf(stderr, "nmap(%s): unsupported\n", name);
        exit(1);
    } else if (EQUALS("pfring", name)) {
        masscan->is_pfring = 1;
    } else if (EQUALS("port-ratio", name)) {
        fprintf(stderr, "nmap(%s): unsupported\n", name);
        exit(1);
    } else if (EQUALS("readrange", name) || EQUALS("readranges", name)) {
        masscan->op = Operation_ReadRange;
    } else if (EQUALS("reason", name)) {
        masscan->output.is_reason = 1;
    } else if (EQUALS("redis", name)) {
        struct Range range;
        unsigned offset = 0;
        unsigned max_offset = (unsigned)strlen(value);
        unsigned port = 6379;

        range = range_parse_ipv4(value, &offset, max_offset);
        if ((range.begin == 0 && range.end == 0) || range.begin != range.end) {
            LOG(0, "FAIL:  bad redis IP address: %s\n", value);
            exit(1);
        }
        if (offset < max_offset) {
            while (offset < max_offset && isspace(value[offset]))
                offset++;
            if (offset+1 < max_offset && value[offset] == ':' && isdigit(value[offset+1]&0xFF)) {
                port = (unsigned)strtoul(value+offset+1, 0, 0);
                if (port > 65535 || port == 0) {
                    LOG(0, "FAIL: bad redis port: %s\n", value+offset+1);
                    exit(1);
                }
            }
        }

        masscan->redis.ip = range.begin;
        masscan->redis.port = port;
        masscan->output.format = Output_Redis;
        strcpy_s(masscan->output.filename, 
                 sizeof(masscan->output.filename), 
                 "<redis>");
    } else if (EQUALS("release-memory", name)) {
        fprintf(stderr, "nmap(%s): this is our default option\n", name);
    } else if (EQUALS("resume", name)) {
        masscan_read_config_file(masscan, value);
        masscan_set_parameter(masscan, "output-append", "true");
    } else if (EQUALS("vuln", name)) {
        if (EQUALS("heartbleed", value)) {
            masscan_set_parameter(masscan, "heartbleed", "true");
            return;
		} else if (EQUALS("ticketbleed", value)) {
            masscan_set_parameter(masscan, "ticketbleed", "true");
            return;
        } else if (EQUALS("poodle", value) || EQUALS("sslv3", value)) {
            masscan->is_poodle_sslv3 = 1;
            masscan_set_parameter(masscan, "no-capture", "cert");
            masscan_set_parameter(masscan, "banners", "true");
            return;
        }
        
        if (!vulncheck_lookup(value)) {
            fprintf(stderr, "FAIL: vuln check '%s' does not exist\n", value);
            fprintf(stderr, "  hint: use '--vuln list' to list available scripts\n");
            exit(1);
        }
        if (masscan->vuln_name != NULL) {
            if (strcmp(masscan->vuln_name, value) == 0)
                return; /* ok */
            else {
                fprintf(stderr, "FAIL: only one vuln check supported at a time\n");
                fprintf(stderr, "  hint: '%s' is existing vuln check, '%s' is new vuln check\n",
                        masscan->vuln_name, value);
                exit(1);
            }
        }
        
        masscan->vuln_name = vulncheck_lookup(value)->name;
    } else if (EQUALS("scan-delay", name) || EQUALS("max-scan-delay", name)) {
        fprintf(stderr, "nmap(%s): unsupported: we do timing VASTLY differently!\n", name);
        exit(1);
    } else if (EQUALS("scanflags", name)) {
        fprintf(stderr, "nmap(%s): TCP scan flags not yet supported\n", name);
        exit(1);
    } else if (EQUALS("sendq", name) || EQUALS("sendqueue", name)) {
        masscan->is_sendq = 1;
    } else if (EQUALS("send-eth", name)) {
        fprintf(stderr, "nmap(%s): unnecessary, we always do --send-eth\n", name);
    } else if (EQUALS("send-ip", name)) {
        fprintf(stderr, "nmap(%s): unsupported, we only do --send-eth\n", name);
        exit(1);
    } else if (EQUALS("selftest", name) || EQUALS("self-test", name) || EQUALS("regress", name)) {
        masscan->op = Operation_Selftest;
        return;
    } else if (EQUALS("benchmark", name)) {
        masscan->op = Operation_Benchmark;
        return;
    } else if (EQUALS("source-port", name) || EQUALS("sourceport", name)) {
        masscan_set_parameter(masscan, "adapter-port", value);
    } else if (EQUALS("nobacktrace", name) || EQUALS("backtrace", name)) {
        ;
    } else if (EQUALS("no-stylesheet", name)) {
        masscan->output.stylesheet[0] = '\0';
    } else if (EQUALS("system-dns", name)) {
        fprintf(stderr, "nmap(%s): DNS lookups will never be supported by this code\n", name);
        exit(1);
    } else if (EQUALS("top-ports", name)) {
        unsigned n = (unsigned)parseInt(value);
        if (!isInteger(value))
            n = 100;
        LOG(2, "top-ports = %u\n", n);
        masscan->top_ports = n;
    } else if (EQUALS("traceroute", name)) {
        fprintf(stderr, "nmap(%s): unsupported\n", name);
        exit(1);
    } else if (EQUALS("test", name)) {
        if (EQUALS("csv", value))
            masscan->is_test_csv = 1;
    } else if (EQUALS("notest", name)) {
        if (EQUALS("csv", value))
            masscan->is_test_csv = 0;
    } else if (EQUALS("ttl", name)) {
        unsigned x = (unsigned)strtoul(value, 0, 0);
        if (x >= 256) {
            fprintf(stderr, "error: %s=<n>: expected number less than 256\n", name);
        } else {
            masscan->nmap.ttl = x;
        }
    } else if (EQUALS("version", name)) {
        print_version();
        exit(1);
    } else if (EQUALS("version-intensity", name)) {
        fprintf(stderr, "nmap(%s): unsupported\n", name);
        exit(1);
    } else if (EQUALS("version-light", name)) {
        fprintf(stderr, "nmap(%s): unsupported\n", name);
        exit(1);
    } else if (EQUALS("version-all", name)) {
        fprintf(stderr, "nmap(%s): unsupported\n", name);
        exit(1);
    } else if (EQUALS("version-trace", name)) {
        fprintf(stderr, "nmap(%s): unsupported\n", name);
        exit(1);
    } else if (EQUALS("vlan", name) || EQUALS("adapter-vlan", name)) {
        masscan->nic[index].is_vlan = 1;
        masscan->nic[index].vlan_id = (unsigned)parseInt(value);
    } else if (EQUALS("wait", name)) {
        if (EQUALS("forever", value))
            masscan->wait =  INT_MAX;
        else
            masscan->wait = (unsigned)parseInt(value);
    } else if (EQUALS("webxml", name)) {
        masscan_set_parameter(masscan, "stylesheet", "http://nmap.org/svn/docs/nmap.xsl");
    } else {
        fprintf(stderr, "CONF: unknown config option: %s=%s\n", name, value);
        exit(1);
    }
}

/***************************************************************************
 * Command-line parsing code assumes every --parm is followed by a value.
 * This is a list of the parameters that don't follow the default.
 ***************************************************************************/
static int
is_singleton(const char *name)
{
    static const char *singletons[] = {
        "echo", "echo-all", "selftest", "self-test", "regress",
        "benchmark",
        "system-dns", "traceroute", "version",
        "version-light",
        "version-all", "version-trace",
        "osscan-limit", "osscan-guess",
        "badsum", "reason", "open", "open-only",
        "packet-trace", "release-memory",
        "log-errors", "append-output", "webxml",
        "no-stylesheet", "heartbleed", "ticketbleed",
        "send-eth", "send-ip", "iflist",
        "nmap", "trace-packet", "pfring", "sendq",
        "offline", "ping", "ping-sweep", "nobacktrace", "backtrace",
        "infinite", "nointeractive", "interactive", "status", "nostatus",
        "read-range", "read-ranges", "readrange", "read-ranges",
        0};
    size_t i;

    for (i=0; singletons[i]; i++) {
        if (EQUALS(singletons[i], name))
            return 1;
    }
    
    for (i=0; config_parameters[i].name; i++) {
        if (EQUALS(config_parameters[i].name, name)) {
            return (config_parameters[i].flags & F_BOOL) == F_BOOL;
        } else {
            size_t j;
            for (j=0; config_parameters[i].alts[j]; j++) {
                if (EQUALS(config_parameters[i].alts[j], name)) {
                    return (config_parameters[i].flags & F_BOOL) == F_BOOL;
                }
            }
        }
    }
    
    return 0;
}

/*****************************************************************************
 *****************************************************************************/
static void
masscan_help()
{
    printf(
"MASSCAN is a fast port scanner. The primary input parameters are the\n"
"IP addresses/ranges you want to scan, and the port numbers. An example\n"
"is the following, which scans the 10.x.x.x network for web servers:\n"
" masscan 10.0.0.0/8 -p80\n"
"The program auto-detects network interface/adapter settings. If this\n"
"fails, you'll have to set these manually. The following is an\n"
"example of all the parameters that are needed:\n"
" --adapter-ip 192.168.10.123\n"
" --adapter-mac 00-11-22-33-44-55\n"
" --router-mac 66-55-44-33-22-11\n"
"Parameters can be set either via the command-line or config-file. The\n"
"names are the same for both. Thus, the above adapter settings would\n"
"appear as follows in a configuration file:\n"
" adapter-ip = 192.168.10.123\n"
" adapter-mac = 00-11-22-33-44-55\n"
" router-mac = 66-55-44-33-22-11\n"
"All single-dash parameters have a spelled out double-dash equivalent,\n"
"so '-p80' is the same as '--ports 80' (or 'ports = 80' in config file).\n"
"To use the config file, type:\n"
" masscan -c <filename>\n"
"To generate a config-file from the current settings, use the --echo\n"
"option. This stops the program from actually running, and just echoes\n"
"the current configuration instead. This is a useful way to generate\n"
"your first config file, or see a list of parameters you didn't know\n"
"about. I suggest you try it now:\n"
" masscan -p1234 --echo\n");
    exit(1);
}

/***************************************************************************
 ***************************************************************************/
void
masscan_load_database_files(struct Masscan *masscan)
{
    const char *filename;
    
    /*
     * "pcap-payloads"
     */
    filename = masscan->payloads.pcap_payloads_filename;
    if (filename) {
        if (masscan->payloads.udp == NULL)
            masscan->payloads.udp = payloads_udp_create();
        if (masscan->payloads.oproto == NULL)
            masscan->payloads.oproto = payloads_udp_create();

        payloads_read_pcap(filename, masscan->payloads.udp, masscan->payloads.oproto);
    }

    /*
     * "nmap-payloads"
     */
    filename = masscan->payloads.nmap_payloads_filename;
    if (filename) {
        FILE *fp;
        int err;
        
        
        err = fopen_s(&fp, filename, "rt");
        if (err || fp == NULL) {
            perror(filename);
        } else {
            if (masscan->payloads.udp == NULL)
                masscan->payloads.udp = payloads_udp_create();
            
            payloads_udp_readfile(fp, filename, masscan->payloads.udp);
            
            fclose(fp);
        }
    }
    
    /*
     * "nmap-service-probes"
     */
    filename = masscan->payloads.nmap_service_probes_filename;
    if (filename) {
        if (masscan->payloads.probes)
            nmapserviceprobes_free(masscan->payloads.probes);
        
        masscan->payloads.probes = nmapserviceprobes_read_file(filename);
    }
}

/***************************************************************************
 * Read the configuration from the command-line.
 * Called by 'main()' when starting up.
 ***************************************************************************/
void
masscan_command_line(struct Masscan *masscan, int argc, char *argv[])
{
    int i;

    for (i=1; i<argc; i++) {

        /*
         * --name=value
         * --name:value
         * -- name value
         */
        if (argv[i][0] == '-' && argv[i][1] == '-') {
            if (strcmp(argv[i], "--help") == 0) {
                masscan_help();
            } else if (EQUALS("top-ports", argv[i]+2)) {
                /* special handling here since the following parameter
                 * is optional */
                const char *value = "1000";
                unsigned n;
                
                /* Only consume the next parameter if it's a number,
                 * otherwise default to 10000 */
                if (i+1 < argc && isInteger(argv[i+1])) {
                    value = argv[++i];
                }
                n = (unsigned)parseInt(value);
                LOG(2, "top-ports = %u\n", n);
                masscan->top_ports = n;
               
            } else if (EQUALS("readscan", argv[i]+2)) {
                /* Read in a binary file instead of scanning the network*/
                masscan->op = Operation_ReadScan;
                
                /* Default to reading banners */
                masscan->is_banners = 1;

                /* This option may be followed by many filenames, therefore,
                 * skip forward in the argument list until the next
                 * argument */
                while (i+1 < argc && argv[i+1][0] != '-')
                    i++;
                continue;
            } else {
                char name2[64];
                char *name = argv[i] + 2;
                unsigned name_length;
                const char *value;

                value = strchr(&argv[i][2], '=');
                if (value == NULL)
                    value = strchr(&argv[i][2], ':');
                if (value == NULL) {
                    if (is_singleton(name))
                        value = "";
                    else
                        value = argv[++i];
                    name_length = (unsigned)strlen(name);
                } else {
                    name_length = (unsigned)(value - name);
                    value++;
                }

                if (i >= argc) {
                    fprintf(stderr, "%.*s: empty parameter\n", name_length, name);
                    break;
                }

                if (name_length > sizeof(name2) - 1) {
                    fprintf(stderr, "%.*s: name too long\n", name_length, name);
                    name_length = sizeof(name2) - 1;
                }

                memcpy(name2, name, name_length);
                name2[name_length] = '\0';

                masscan_set_parameter(masscan, name2, value);
            }
            continue;
        }

        /* For for a single-dash parameter */
        if (argv[i][0] == '-') {
            const char *arg;

            switch (argv[i][1]) {
            case '6':
                fprintf(stderr, "nmap(%s): unsupported: maybe one day\n", argv[i]);
                exit(1);
            case 'A':
                fprintf(stderr, "nmap(%s): unsupported: this tool only does SYN scan\n", argv[i]);
                exit(1);
            case 'b':
                fprintf(stderr, "nmap(%s): FTP bounce scans will never be supported\n", argv[i]);
                exit(1);
            case 'c':
                if (argv[i][2])
                    arg = argv[i]+2;
                else
                    arg = argv[++i];
                masscan_read_config_file(masscan, arg);
                break;
            case 'd': /* just do same as verbosity level */
                {
                    int v;
                    for (v=1; argv[i][v] == 'd'; v++) {
                        LOG_add_level(1);
                    }
                }
                break;
            case 'e':
                if (argv[i][2])
                    arg = argv[i]+2;
                else
                    arg = argv[++i];
                masscan_set_parameter(masscan, "adapter", arg);
                break;
            case 'f':
                fprintf(stderr, "nmap(%s): fragmentation not yet supported\n", argv[i]);
                exit(1);
            case 'F':
                fprintf(stderr, "nmap(%s): unsupported, no slow/fast mode\n", argv[i]);
                exit(1);
            case 'g':
                if (argv[i][2])
                    arg = argv[i]+2;
                else
                    arg = argv[++i];
                masscan_set_parameter(masscan, "adapter-port", arg);
                break;
            case 'h':
            case '?':
                masscan_usage();
                break;
            case 'i':
                if (argv[i][3] == '\0' && !isdigit(argv[i][2]&0xFF)) {
                    /* This looks like an nmap option*/
                    switch (argv[i][2]) {
                    case 'L':
                        masscan_set_parameter(masscan, "includefile", argv[++i]);
                        break;
                    case 'R':
                        /* -iR in nmap makes it randomize addresses completely. Thus,
                         * it's nearest equivalent is scanning the entire Internet range */
                        masscan_set_parameter(masscan, "include", "0.0.0.0/0");
                        break;
                    default:
                        fprintf(stderr, "nmap(%s): unsupported option\n", argv[i]);
                        exit(1);
                    }

                } else {
                    if (argv[i][2])
                        arg = argv[i]+2;
                    else
                        arg = argv[++i];

                    masscan_set_parameter(masscan, "adapter", arg);
                }
                break;
            case 'n':
                /* This looks like an nmap option*/
                /* Do nothing: this code never does DNS lookups anyway */
                break;
            case 'o': /* nmap output format */
                switch (argv[i][2]) {
                case 'A':
                    masscan->output.format = Output_All;
                    fprintf(stderr, "nmap(%s): unsupported output format\n", argv[i]);
                    exit(1);
                    break;
                case 'B':
                    masscan->output.format = Output_Binary;
                    break;
                case 'D':
                    masscan->output.format = Output_NDJSON;
                    break;
                case 'J':
                    masscan->output.format = Output_JSON;
                    break;
                case 'N':
                    masscan->output.format = Output_Nmap;
                    fprintf(stderr, "nmap(%s): unsupported output format\n", argv[i]);
                    exit(1);
                    break;
                case 'X':
                    masscan->output.format = Output_XML;
                    break;
                case 'R':
                    masscan->output.format = Output_Redis;
                    if (i+1 < argc && argv[i+1][0] != '-')
                        masscan_set_parameter(masscan, "redis", argv[i+1]);
                    break;
                case 'S':
                    masscan->output.format = Output_ScriptKiddie;
                    fprintf(stderr, "nmap(%s): unsupported output format\n", argv[i]);
                    exit(1);
                    break;
                case 'G':
                    masscan->output.format = Output_Grepable;
                    break;
                case 'L':
                    masscan_set_parameter(masscan, "output-format", "list");
                    break;
                case 'U':
                    masscan_set_parameter(masscan, "output-format", "unicornscan");
                    break;
                default:
                    fprintf(stderr, "nmap(%s): unknown output format\n", argv[i]);
                    exit(1);
                }

                ++i;
                if (i >= argc || (argv[i][0] == '-' && argv[i][1] != '\0')) {
                    fprintf(stderr, "missing output filename\n");
                    exit(1);
                }

                masscan_set_parameter(masscan, "output-filename", argv[i]);
                break;
            case 'O':
                fprintf(stderr, "nmap(%s): unsupported, OS detection is too complex\n", argv[i]);
                exit(1);
                break;
            case 'p':
                if (argv[i][2])
                    arg = argv[i]+2;
                else
                    arg = argv[++i];
                if (i >= argc || arg[0] == 0) { // if string is empty
                    fprintf(stderr, "%s: empty parameter\n", argv[i]);
                } else
                    masscan_set_parameter(masscan, "ports", arg);
                break;
            case 'P':
                switch (argv[i][2]) {
                case 'n':
                    /* we already do this */
                    break;
                default:
                    fprintf(stderr, "nmap(%s): unsupported option, maybe in future\n", argv[i]);
                    exit(1);
                }
                break;
            case 'r':
                /* This looks like an nmap option*/
                fprintf(stderr, "nmap(%s): wat? randomization is our raison d'etre!! rethink prease\n", argv[i]);
                exit(1);
                break;
            case 'R':
                /* This looks like an nmap option*/
                fprintf(stderr, "nmap(%s): unsupported. This code will never do DNS lookups.\n", argv[i]);
                exit(1);
                break;
            case 's': /* NMAP: scan type */
                if (argv[i][3] == '\0' && !isdigit(argv[i][2]&0xFF)) {
                    unsigned j;

                    for (j=2; argv[i][j]; j++)
                    switch (argv[i][j]) {
                    case 'A':
                        fprintf(stderr, "nmap(%s): ACK scan not yet supported\n", argv[i]);
                        exit(1);
                    case 'C':
                        fprintf(stderr, "nmap(%s): unsupported\n", argv[i]);
                        exit(1);
                    case 'F':
                        fprintf(stderr, "nmap(%s): FIN scan not yet supported\n", argv[i]);
                        exit(1);
                    case 'I':
                        fprintf(stderr, "nmap(%s): Zombie scans will never be supported\n", argv[i]);
                        exit(1);
                    case 'L': /* List Scan - simply list targets to scan */
                        masscan->op = Operation_ListScan;
                        break;
                    case 'M':
                        fprintf(stderr, "nmap(%s): Maimon scan not yet supported\n", argv[i]);
                        exit(1);
                    case 'n': /* Ping Scan - disable port scan */
                        fprintf(stderr, "nmap(%s): ping-sweeps not yet supported\n", argv[i]);
                        exit(1);
                    case 'N':
                        fprintf(stderr, "nmap(%s): NULL scan not yet supported\n", argv[i]);
                        exit(1);
                    case 'O': /* Other IP protocols (not ICMP, UDP, TCP, or SCTP) */
                        masscan->scan_type.oproto = 1;
                        break;
                    case 'S': /* TCP SYN scan - THIS IS WHAT WE DO! */
                        masscan->scan_type.tcp = 1;
                        break;
                    case 'T': /* TCP connect scan */
                        fprintf(stderr, "nmap(%s): connect() is too synchronous for cool kids\n", argv[i]);
                        fprintf(stderr, "WARNING: doing SYN scan (-sS) anyway, ignoring (-sT)\n");
                        break;
                    case 'U': /* UDP scan */
                        masscan->scan_type.udp = 1;
                        break;
                    case 'V':
                        fprintf(stderr, "nmap(%s): unlikely this will be supported\n", argv[i]);
                        exit(1);
                    case 'W':
                        fprintf(stderr, "nmap(%s): Windows scan not yet supported\n", argv[i]);
                        exit(1);
                    case 'X':
                        fprintf(stderr, "nmap(%s): Xmas scan not yet supported\n", argv[i]);
                        exit(1);
                    case 'Y':
                        break;
                    case 'Z':
                        masscan->scan_type.sctp = 1;
                        break;
                    default:
                        fprintf(stderr, "nmap(%s): unsupported option\n", argv[i]);
                        exit(1);
                    }

                } else {
                    fprintf(stderr, "%s: unknown parameter\n", argv[i]);
                    exit(1);
                }
                break;
            case 'S':
                if (argv[i][2])
                    arg = argv[i]+2;
                else
                    arg = argv[++i];
                masscan_set_parameter(masscan, "adapter-ip", arg);
                break;
            case 'v':
                {
                    int v;
                    for (v=1; argv[i][v] == 'v'; v++)
                        LOG_add_level(1);
                }
                break;
            case 'V': /* print version and exit */
                masscan_set_parameter(masscan, "version", "");
                break;
            case 'W':
                masscan->op = Operation_List_Adapters;
                return;
            case 'T':
                fprintf(stderr, "nmap(%s): unsupported, we do timing WAY different than nmap\n", argv[i]);
                exit(1);
                return;
            default:
                LOG(0, "FAIL: unknown option: -%s\n", argv[i]);
                LOG(0, " [hint] try \"--help\"\n");
                LOG(0, " [hint] ...or, to list nmap-compatible options, try \"--nmap\"\n");
                exit(1);
            }
            continue;
        }

        if (!isdigit(argv[i][0])) {
            fprintf(stderr, "FAIL: unknown command-line parameter \"%s\"\n", argv[i]);
            fprintf(stderr, " [hint] did you want \"--%s\"?\n", argv[i]);
            exit(1);
        }

        /* If parameter doesn't start with '-', assume it's an
         * IPv4 range
         */
        masscan_set_parameter(masscan, "range", argv[i]);
    }

    /*
     * Targets must be sorted
     */
    rangelist_sort(&masscan->targets);
    rangelist_sort(&masscan->ports);
    rangelist_sort(&masscan->exclude_ip);
    rangelist_sort(&masscan->exclude_port);

    /*
     * If no other "scan type" found, then default to TCP
     */
    if (masscan->scan_type.udp == 0 && masscan->scan_type.sctp == 0
        && masscan->scan_type.ping == 0 && masscan->scan_type.arp == 0
        && masscan->scan_type.oproto == 0)
        masscan->scan_type.tcp = 1;
    
    /*
     * If "top-ports" specified, then add all those ports. This may be in
     * addition to any other ports
     */
    if (masscan->top_ports) {
        config_top_ports(masscan, masscan->top_ports);
    }
}

/***************************************************************************
 * Prints the current configuration to the command-line then exits.
 * Use#1: create a template file of all setable parameters.
 * Use#2: make sure your configuration was interpreted correctly.
 ***************************************************************************/
static void
masscan_echo(struct Masscan *masscan, FILE *fp, unsigned is_echo_all)
{
    unsigned i;
    unsigned l = 0;
    
    /*
     * NEW:
     * Print all configuration parameters
     */
    masscan->echo = fp;
    masscan->echo_all = is_echo_all;
    for (i=0; config_parameters[i].name; i++) {
        config_parameters[i].set(masscan, 0, 0);
    }
    masscan->echo = 0;
    masscan->echo_all = 0;
    
    /*
     * OLD:
     * Things here below are the old way of echoing parameters.
     * TODO: cleanup this code, replacing with the new way.
     */
    if (masscan->nic_count == 0)
        masscan_echo_nic(masscan, fp, 0);
    else {
        for (i=0; i<masscan->nic_count; i++)
            masscan_echo_nic(masscan, fp, i);
    }
    
    
    /*
     * Targets
     */
    fprintf(fp, "# TARGET SELECTION (IP, PORTS, EXCLUDES)\n");
    fprintf(fp, "ports = ");
    /* Disable comma generation for the first element */
    l = 0;
    for (i=0; i<masscan->ports.count; i++) {
        struct Range range = masscan->ports.list[i];
        do {
            struct Range rrange = range;
            unsigned done = 0;
            if (l)
                fprintf(fp, ",");
            l = 1;
            if (rrange.begin >= Templ_ICMP_echo) {
                rrange.begin -= Templ_ICMP_echo;
                rrange.end -= Templ_ICMP_echo;
                fprintf(fp,"I:");
                done = 1;
            } else if (rrange.begin >= Templ_SCTP) {
                rrange.begin -= Templ_SCTP;
                rrange.end -= Templ_SCTP;
                fprintf(fp,"S:");
                range.begin = Templ_ICMP_echo;
            } else if (rrange.begin >= Templ_UDP) {
                rrange.begin -= Templ_UDP;
                rrange.end -= Templ_UDP;
                fprintf(fp,"U:");
                range.begin = Templ_SCTP;
            } else if (Templ_Oproto_first <= rrange.begin && rrange.begin <= Templ_Oproto_last) {
                rrange.begin -= Templ_Oproto_first;
                rrange.end -= Templ_Oproto_first;
                fprintf(fp, "O:");
                range.begin = Templ_Oproto_first;
            } else
                range.begin = Templ_UDP;
            rrange.end = min(rrange.end, 65535);
            if (rrange.begin == rrange.end)
                fprintf(fp, "%u", rrange.begin);
            else
                fprintf(fp, "%u-%u", rrange.begin, rrange.end);
            if (done)
                break;
        } while (range.begin <= range.end);
    }
    fprintf(fp, "\n");
    for (i=0; i<masscan->targets.count; i++) {
        struct Range range = masscan->targets.list[i];
        fprintf(fp, "range = ");
        fprintf(fp, "%u.%u.%u.%u",
                (range.begin>>24)&0xFF,
                (range.begin>>16)&0xFF,
                (range.begin>> 8)&0xFF,
                (range.begin>> 0)&0xFF
                );
        if (range.begin != range.end) {
            unsigned cidr_bits = count_cidr_bits(range);
            
            if (cidr_bits) {
                fprintf(fp, "/%u", cidr_bits);
            } else
                fprintf(fp, "-%u.%u.%u.%u",
                        (range.end>>24)&0xFF,
                        (range.end>>16)&0xFF,
                        (range.end>> 8)&0xFF,
                        (range.end>> 0)&0xFF
                        );
        }
        fprintf(fp, "\n");
    }
    
    fprintf(fp, "\n");
    if (masscan->http_user_agent)
        fprintf(    fp,
                "http-user-agent = %.*s\n",
                masscan->http_user_agent_length,
                masscan->http_user_agent);
    
    for (i=0; i<sizeof(masscan->http_headers)/sizeof(masscan->http_headers[0]); i++) {
        if (masscan->http_headers[i].header_name == 0)
            continue;
        fprintf(    fp,
                "http-header[%s] = %.*s\n",
                masscan->http_headers[i].header_name,
                masscan->http_headers[i].header_value_length,
                masscan->http_headers[i].header_value);
    }
    
    
    
    
    
}


/***************************************************************************
 * remove leading/trailing whitespace
 ***************************************************************************/
static void
trim(char *line, size_t sizeof_line)
{
    if (sizeof_line > strlen(line))
        sizeof_line = strlen(line);

    while (isspace(*line & 0xFF))
        memmove(line, line+1, sizeof_line--);
    while (*line && isspace(line[sizeof_line-1] & 0xFF))
        line[--sizeof_line] = '\0';
}

/***************************************************************************
 ***************************************************************************/
void
masscan_read_config_file(struct Masscan *masscan, const char *filename)
{
    FILE *fp;
    errno_t err;
    char line[65536];

    err = fopen_s(&fp, filename, "rt");
    if (err) {
        char dir[512];
        perror(filename);
        getcwd(dir, sizeof(dir));
        fprintf(stderr, "cwd = %s\n", dir);
        return;
    }

    while (fgets(line, sizeof(line), fp)) {
        char *name;
        char *value;

        trim(line, sizeof(line));

        if (ispunct(line[0] & 0xFF) || line[0] == '\0')
            continue;

        name = line;
        value = strchr(line, '=');
        if (value == NULL)
            continue;
        *value = '\0';
        value++;
        trim(name, sizeof(line));
        trim(value, sizeof(line));

        masscan_set_parameter(masscan, name, value);
    }

    fclose(fp);
}



/***************************************************************************
 ***************************************************************************/
int masscan_conf_contains(const char *x, int argc, char **argv)
{
    int i;

    for (i=0; i<argc; i++) {
        if (strcmp(argv[i], x) == 0)
            return 1;
    }

    return 0;
}


/***************************************************************************
 ***************************************************************************/
int
mainconf_selftest()
{
    char test[] = " test 1 ";

    trim(test, sizeof(test));
    if (strcmp(test, "test 1") != 0)
        return 1; /* failure */

    {
        struct Range range;

        range.begin = 16;
        range.end = 32-1;
        if (count_cidr_bits(range) != 28)
            return 1;

        range.begin = 1;
        range.end = 13;
        if (count_cidr_bits(range) != 0)
            return 1;


    }

    /* */
    {
        int argc = 6;
        char *argv[] = { "foo", "bar", "-ddd", "--readscan", "xxx", "--something" };
    
        if (masscan_conf_contains("--nothing", argc, argv))
            return 1;

        if (!masscan_conf_contains("--readscan", argc, argv))
            return 1;
    }

    return 0;
}

