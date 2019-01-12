#define ArrayCount(arr) (sizeof(arr)/sizeof(arr[0]))
enum dns_type
{// TYPE    value and meaning
    A     = 1,  // a host address
    NS    = 2,  // an authoritative name server
    MD    = 3,  // a mail destination (Obsolete - use MX)
    MF    = 4,  // a mail forwarder (Obsolete - use MX)
    CNAME = 5,  // the canonical name for an alias
    SOA   = 6,  // marks the start of a zone of authority
    MB    = 7,  // a mailbox domain name (EXPERIMENTAL)
    MG    = 8,  // a mail group member (EXPERIMENTAL)
    MR    = 9,  // a mail rename domain name (EXPERIMENTAL)
    NUL   = 10, // ['NULL'] a null RR (EXPERIMENTAL)
    WKS   = 11, // a well known service description
    PTR   = 12, // a domain name pointer
    HINFO = 13, // host information
    MINFO = 14, // mailbox or mail list information
    MX    = 15, // mail exchange
    TXT   = 16, // text strings

 // QTYPE
    Q_AXFR  = 252, // A request for a transfer of an entire zone
    Q_MAILB = 253, // A request for mailbox-related records (MB, MG or MR)
    Q_MAILA = 254, // A request for mail agent RRs (Obsolete - see MX)
    Q_ANY   = 255, // [*] A request for all records
};

static char *DNSTypeTable[] = 
{
    [1] = "A",  // a host address
    [2] = "NS",  // an authoritative name server
    [3] = "MD",  // a mail destination (Obsolete - use MX)
    [4] = "MF",  // a mail forwarder (Obsolete - use MX)
    [5] = "CNAME",  // the canonical name for an alias
    [6] = "SOA",  // marks the start of a zone of authority
    [7] = "MB",  // a mailbox domain name (EXPERIMENTAL)
    [8] = "MG",  // a mail group member (EXPERIMENTAL)
    [9] = "MR",  // a mail rename domain name (EXPERIMENTAL)
    [10] = "NUL", // ['NULL'] a null RR (EXPERIMENTAL)
    [11] = "WKS", // a well known service description
    [12] = "PTR", // a domain name pointer
    [13] = "HINFO", // host information
    [14] = "MINFO", // mailbox or mail list information
    [15] = "MX", // mail exchange
    [16] = "TXT", // text strings

 // QTYPE
    [252] = "Q_AXFR", // A request for a transfer of an entire zone
    [253] = "Q_MAILB", // A request for mailbox-related records (MB, MG or MR)
    [254] = "Q_MAILA", // A request for mail agent RRs (Obsolete - see MX)
    [255] = "Q_ANY",
};

struct port_descriptor 
{
    char *Keyword;
    char *Description;
};

struct port_descriptor DNSPortTable[] =
{
      [0] = {"","Reserved"},
      [5] = {"RJE", "Remote Job Entry"},
      [7] = {"ECHO", "Echo"},
      [9] = {"DISCARD", "Discard"},
      [11] = {"USERS", "Active Users"},
      [13] = {"DAYTIME", "Daytime"},
      [15] = {"", "Unassigned"},
      [17] = {"QUOTE", "Quote of the Day"},
      [19] = {"CHARGEN", "Character Generator"},
      [20] = {"FTP-DATA", "File Transfer [Default Data]"},
      [21] = {"FTP", "File Transfer [Control]"},
      [23] = {"TELNET", "Telnet"},
      [25] = {"SMTP", "Simple Mail Transfer"},
      [27] = {"NSW-FE", "NSW User System FE"},
      [29] = {"MSG-ICP", "MSG ICP"},
      [31] = {"MSG-AUTH", "MSG Authentication"},
      [33] = {"DSP", "Display Support Protocol"},
      [35] = {"", "any private printer server"},
      [37] = {"TIME", "Time"},
      [39] = {"RLP", "Resource Location Protocol"},
      [41] = {"GRAPHICS", "Graphics"},
      [42] = {"NAMESERVER", "Host Name Server"},
      [43] = {"NICNAME", "Who Is"},
      [44] = {"MPM-FLAGS", "MPM FLAGS Protocol"},
      [45] = {"MPM", "Message Processing Module [recv]"},
      [46] = {"MPM-SND", "MPM [default send]"},
      [47] = {"NI-FTP", "NI FTP"},
      [49] = {"LOGIN", "Login Host Protocol"},
      [51] = {"LA-MAINT", "IMP Logical Address Maintenance"},
      [53] = {"DOMAIN", "Domain Name Server"},
      [55] = {"ISI-GL", "ISI Graphics Language"},
      [57] = {"", "any private terminal access"},
      [59] = {"", "any private file service"},
      [61] = {"NI-MAIL", "NI MAIL"},
      [63] = {"VIA-FTP", "VIA Systems - FTP"},
      [65] = {"TACACS-DS", "TACACS-Database Service"},
      [67] = {"BOOTPS", "Bootstrap Protocol Server"},
      [68] = {"BOOTPC", "Bootstrap Protocol Client"},
      [69] = {"TFTP", "Trivial File Transfer"},
      [71] = {"NETRJS-1", "Remote Job Service"},
      [72] = {"NETRJS-2", "Remote Job Service"},
      [73] = {"NETRJS-3", "Remote Job Service"},
      [74] = {"NETRJS-4", "Remote Job Service"},
      [75] = {"", "any private dial out service"},
      [77] = {"", "any private RJE service"},
      [79] = {"FINGER", "Finger"},
      [81] = {"HOSTS2-NS", "HOSTS2 Name Server"},
      [83] = {"MIT-ML-DEV", "MIT ML Device"},
      [85] = {"MIT-ML-DEV", "MIT ML Device"},
      [87] = {"", "any private terminal link"},
      [89] = {"SU-MIT-TG", "SU/MIT Telnet Gateway"},
      [91] = {"MIT-DOV", "MIT Dover Spooler"},
      [93] = {"DCP", "Device Control Protocol"},
      [95] = {"SUPDUP", "SUPDUP"},
      [97] = {"SWIFT-RVF", "Swift Remote Vitural File Protocol "},
      [98] = {"TACNEWS", "TAC News"},
      [99] = {"METAGRAM", "Metagram Relay"},
      [101] = {"HOSTNAME", "NIC Host Name Server"},
      [102] = {"ISO-TSAP", "ISO-TSAP"},
      [103] = {"X400", "X400"},
      [104] = {"X400-SND", "X400-SND"},
      [105] = {"CSNET-NS", "Mailbox Name Nameserver"},
      [107] = {"RTELNET", "Remote Telnet Service"},
      [109] = {"POP-2", "Post Office Protocol - Version 2"},
      [111] = {"SUNRPC", "SUN Remote Procedure Call"},
      [113] = {"AUTH", "Authentication Service"},
      [115] = {"SFTP", "Simple File Transfer Protocol"},
      [117] = {"UUCP-PATH", "UUCP Path Service"},
      [119] = {"NNTP", "Network News Transfer Protocol"},
      [121] = {"ERPC", "HYDRA Expedited Remote Procedure Ca"},
      [123] = {"NTP", "Network Time Protocol"},
      [125] = {"LOCUS-MAP", "Locus PC-Interface Net Map Server"},
      [127] = {"LOCUS-CON", "Locus PC-Interface Conn Server"},
      [129] = {"PWDGEN", "Password Generator Protocol"},
      [130] = {"CISCO-FNA", "CISCO FNATIVE"},
      [131] = {"CISCO-TNA", "CISCO TNATIVE"},
      [132] = {"CISCO-SYS", "CISCO SYSMAINT"},
      [133] = {"STATSRV", "Statistics Service"},
      [134] = {"INGRES-NET ", "INGRES-NET Service"},
      [135] = {"LOC-SRV", "Location Service"},
      [136] = {"PROFILE", "PROFILE Naming System"},
      [137] = {"NETBIOS-NS ", "NETBIOS Name Service"},
      [138] = {"NETBIOS-DGM", " NETBIOS Datagram Service"},
      [139] = {"NETBIOS-SSN", " NETBIOS Session Service"},
      [140] = {"EMFIS-DATA ", "EMFIS Data Service"},
      [141] = {"EMFIS-CNTL ", "EMFIS Control Service"},
      [142] = {"BL-IDM", "Britton-Lee IDM"},
      [160] = {"", "Reserved"},
      [243] = {"SUR-MEAS", "Survey Measurement"},
      [245] = {"LINK", "LINK"},
      [247] = {"", "Unassigned"},
};

struct port_descriptor DNSProtocolTable[] =
{
    [0] = {"", "Reserved"},
    [1] = {"ICMP", "Internet Control Message"},
    [2] = {"IGMP", "Internet Group Management"},
    [3] = {"GGP", "Gateway-to-Gateway"},
    [4] = {"", "Unassigned"},
    [5] = {"ST", "Stream"},
    [6] = {"TCP", "Transmission Control"},
    [7] = {"UCL", "UCL"},
    [8] = {"EGP", "Exterior Gateway Protocol"},
    [9] = {"IGP", "any private interior gateway"},
    [10] = {"BBN-RCC-MON", "BBN RCC Monitoring"},
    [11] = {"NVP-II", "Network Voice Protocol"},
    [12] = {"PUP", "PUP"},
    [13] = {"ARGUS", "ARGUS"},
    [14] = {"EMCON", "EMCON"},
    [15] = {"XNET", "Cross Net Debugger"},
    [16] = {"CHAOS", "Chaos"},
    [17] = {"UDP", "User Datagram"},
    [18] = {"MUX", "Multiplexing"},
    [19] = {"DCN-MEAS", "DCN Measurement Subsystems"},
    [20] = {"HMP", "Host Monitoring"},
    [21] = {"PRM", "Packet Radio Measurement"},
    [22] = {"XNS-IDP", "XEROX NS IDP"},
    [23] = {"TRUNK-1", "Trunk-1"},
    [24] = {"TRUNK-2", "Trunk-2"},
    [25] = {"LEAF-1", "Leaf-1"},
    [26] = {"LEAF-2", "Leaf-2"},
    [27] = {"RDP", "Reliable Data Protocol"},
    [28] = {"IRTP", "Internet Reliable Transaction"},
    [29] = {"ISO-TP4", "ISO Transport Protocol Class 4"},
    [30] = {"NETBLT", "Bulk Data Transfer Protocol"},
    [31] = {"MFE-NSP", "MFE Network Services Protocol"},
    [32] = {"MERIT-INP ", "MERIT Internodal Protocol"},
    [33] = {"SEP", "Sequential Exchange Protocol"},
    [61] = {"", "any host internal protocol"},
    [62] = {"CFTP", "CFTP"},
    [63] = {"", "any local network"},
    [64] = {"SAT-EXPAK ", "SATNET and Backroom EXPAK"},
    [65] = {"MIT-SUBNET", "MIT Subnet Support"},
    [66] = {"RVD", "MIT Remote Virtual Disk Protocol"},
    [67] = {"IPPC", "Internet Pluribus Packet Core"},
    [68] = {"", "any distributed file system"},
    [69] = {"SAT-MON", "SATNET Monitoring"},
    [70] = {"", "Unassigned"},
    [71] = {"IPCV", "Internet Packet Core Utility"},
    [76] = {"BR-SAT-MON", "Backroom SATNET Monitoring"},
    [78] = {"WB-MON", "WIDEBAND Monitoring"},
    [79] = {"WB-EXPAK", "WIDEBAND EXPAK"},
    [255] = {"", "Reserved"},
};

enum dns_class
{
    INET = 1, // ['IN'] the Internet
};

struct dns_message_header
{
    unsigned short Identifier;
    #if 1
    union
    {
        // Bitfields begin with LSB
        struct
        {
            unsigned char RCODE : 4;		/* Response code */
            unsigned char Z : 3;			/* --- Reserved --- */
            unsigned char RA : 1;		/* Recursion Available */
            unsigned char RD : 1;		/* Recursion Desired */
            unsigned char TC : 1;		/* TrunCation */
            unsigned char AA : 1;		/* Authoritative Answer */
            unsigned char OPCODE : 4;	/* Kind of query */
            unsigned char QR : 1;		/* Specifies whether this message is a query (0), or a response (1) */
        };
        unsigned short Flags;
    };
    #else
    unsigned short Flags;
    #endif
    unsigned short NumQuestions;
    unsigned short NumAnswerRRs;
    unsigned short NumAuthRRs;
    unsigned short NumAdditional;
	/* Questions (variable number of questions) */
	/* Answers (variable number of resource records) */
	/* Authority (variable number of resource records) */
	/* Additional information (variable number of resource records) */
};

struct dns_question
{
	int QLEN;
	char *QNAME;
	short QTYPE;
	short QCLASS;

	struct dns_question *Next;
};

struct dns_resource_record_header
{
    char Name[256];
    unsigned short Type;
    unsigned short Class;
    int TTL;
    unsigned short RDLength;
    //char RData[];
};

// Initially, non-linked
struct dns_message
{
	int Length;
	char *Message;
};