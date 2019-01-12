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