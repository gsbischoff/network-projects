struct dns_message_header
{
	union
	{
		struct
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
		};
		char Header[12];
	};
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

// Initially, non-linked
struct dns_message
{
	int Length;
	char *Message;
};