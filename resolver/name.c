#include <WinSock2.h>
#include <windows.h>
#include <stdio.h>

#include "dns.h"

// gcc -std=c99 name.c -o t -lws2_32

void
SerializeDNSHeader(struct dns_message_header *Header)
{
	// Change header fields to network byte order
	Header->Identifier    = htons(Header->Identifier);
	Header->Flags         = htons(Header->Flags);
	Header->NumQuestions  = htons(Header->NumQuestions);
	Header->NumAnswerRRs  = htons(Header->NumAnswerRRs);
	Header->NumAuthRRs    = htons(Header->NumAuthRRs);
	Header->NumAdditional = htons(Header->NumAdditional);
}

void
DeserializeDNSHeader(struct dns_message_header *Header)
{
	// Change header fields to host byte order
	Header->Identifier    = ntohs(Header->Identifier);
	Header->Flags         = ntohs(Header->Flags);
	Header->NumQuestions  = ntohs(Header->NumQuestions);
	Header->NumAnswerRRs  = ntohs(Header->NumAnswerRRs);
	Header->NumAuthRRs    = ntohs(Header->NumAuthRRs);
	Header->NumAdditional = ntohs(Header->NumAdditional);
}

void
PrintDNSHeader(struct dns_message_header *ResponseHeader)
{
	printf("\nIdentifier    %x\n"
			"Flags:  %x\n"
			"\tQR      %x\n"
			"\tOpcode  %x\n"	/* Kind of query */
			"\tAA      %x\n"	/* Authoritative Answer */
			"\tTC      %x\n"	/* TrunCation */
			"\tRD      %x\n"	/* Recursion Desired */
			"\tRA      %x\n"	/* Recursion Available */
			"\tZ       %x\n"	/* --- Reserved --- */
			"\tRCODE   %x\n"	/* Response code */
			"NumQuestions   %u\n"
			"NumAnswerRRs   %u\n"
			"NumAuthRRs     %u\n"
			"NumAdditional  %u\n", 
			ResponseHeader->Identifier, 
			ResponseHeader->Flags,
				ResponseHeader->QR,
				ResponseHeader->OPCODE, //Opcode,
				ResponseHeader->AA, //AA,
				ResponseHeader->TC, //TC,
				ResponseHeader->RD, //RD,
				ResponseHeader->RA, //RA,
				ResponseHeader->Z,  //Z,
				ResponseHeader->RCODE, //RCODE,
			ResponseHeader->NumQuestions, ResponseHeader->NumAnswerRRs,
			ResponseHeader->NumAuthRRs, ResponseHeader->NumAdditional);
}

int
PrintDNSName(unsigned char *MessageStart, int Offset)
{
    int LabelOffset = Offset;
    int Jumped = 0;
    while(MessageStart[LabelOffset])
    {
        if(MessageStart[LabelOffset] & 0xc0)
        {
            // Has high-order two bits set -> is a pointer
            unsigned short PointerOffset = ((unsigned short)MessageStart[Offset + 0] << 8) |
                                           ((unsigned short)MessageStart[Offset + 1] << 0);

            // Before jumping to this label pointer, advance 
            // 'offset' past the pointer to continue the message
            Offset = LabelOffset + 2; 
            LabelOffset = (PointerOffset & 0x3FFF) - sizeof(struct dns_message_header);

            Jumped = 1;
        }
        else
        {
            printf("%.*s.", MessageStart[LabelOffset], MessageStart + LabelOffset + 1);
            
            LabelOffset += MessageStart[LabelOffset] + 1;

            if(!Jumped) Offset = LabelOffset;
        }
    }

    return(Offset);
}

int
ParseQuestions(unsigned char *QuestionStart, short NumQuestions)
{
	unsigned char *MemoryPtr = QuestionStart;
    unsigned Offset = 0;
	for(int QuestionIndex = 0;
		QuestionIndex < NumQuestions;
		++QuestionIndex)
	{
        // Print QNAME
        Offset = PrintDNSName(QuestionStart, Offset);
        printf("\nprinted name: +%u", Offset);

        ++Offset;

        unsigned short Type;
        memcpy(&Type, &QuestionStart[Offset], 2);
        Type = ntohs(Type);

        // Print QTYPE
        printf("\nQTYPE: %s ", DNSTypeTable[Type]);

        unsigned short Class;
        memcpy(&Class, &QuestionStart[Offset + 2], 2);
        Class = ntohs(Class);

        // Print QCLASS
        printf("\nQCLASS: %s\n", (Class == 1) ? "IN" : "OTHER");

        Offset += 4;
	}

    return(Offset);
}

int
ParseAnswerRRs(void *QuestionStart, int Offset, short NumQuestions)
{
    // Print header

    // Name
    unsigned char *Name = QuestionStart;

    printf("NAME: ");
    Offset = PrintDNSName(Name, Offset);

    // Type, 
    unsigned short Type = (Name[Offset++] << 8) |
                          (Name[Offset++] << 0);

    printf("\nTYPE: %s\n", DNSTypeTable[Type]);

    // Class, 
    unsigned short Class = (Name[Offset++] << 8) |
                           (Name[Offset++] << 0);

    printf("CLASS: %s\n", (Type == INET) ? "IN" : "Other");
    // TTL, 
    unsigned uTTL = (Name[Offset++] << 24) |
                    (Name[Offset++] << 16) |
                    (Name[Offset++] << 8) |
                    (Name[Offset++] << 0);

    int TTL;
    memcpy(&TTL, &uTTL, sizeof(int));

    printf("TTL: %d\n", TTL);

    // RDLEN, 
    unsigned short RDLEN = (Name[Offset++] << 8) |
                           (Name[Offset++] << 0);

    printf("RDLEN: %u\n", RDLEN);

    // RDATA
    switch(Type)
    {
        case A:
        {
            struct in_addr Address;
            Address.s_addr = *(ULONG *)&Name[Offset];

            printf("Address: %s\n", inet_ntoa(Address));
        } break;
        case NS:
        {
            printf("NS: ");
            Offset = PrintDNSName(Name, Offset);
        } break;

        case CNAME:
        {
            printf("CNAME: ");
            Offset = PrintDNSName(Name, Offset);
        } break;
        case SOA:
        {
            printf("MNAME: ");
            Offset = PrintDNSName(Name, Offset);

            printf("RNAME: ");
            Offset = PrintDNSName(Name, Offset);

            unsigned Serial = (Name[Offset++] << 24) |
                              (Name[Offset++] << 16) |
                              (Name[Offset++] << 8) |
                              (Name[Offset++] << 0);

            unsigned Refresh = (Name[Offset++] << 24) |
                               (Name[Offset++] << 16) |
                               (Name[Offset++] << 8) |
                               (Name[Offset++] << 0);

            unsigned Retry = (Name[Offset++] << 24) |
                             (Name[Offset++] << 16) |
                             (Name[Offset++] << 8) |
                             (Name[Offset++] << 0);

            unsigned Expire = (Name[Offset++] << 24) |
                              (Name[Offset++] << 16) |
                              (Name[Offset++] << 8) |
                              (Name[Offset++] << 0);

            unsigned Minimum = (Name[Offset++] << 24) |
                               (Name[Offset++] << 16) |
                               (Name[Offset++] << 8) |
                               (Name[Offset++] << 0);

            printf("Serial: %u\n", Serial);
            printf("Refresh: %u\n", Refresh);
            printf("Retry: %u\n", Retry);
            printf("Expire: %u\n", Expire);
            printf("Minimum: %u\n", Minimum);
        } break;

        case WKS:
        {
            struct in_addr Address;
            Address.s_addr = *(ULONG *)&Name[Offset];

            printf("Address: %s\n", inet_ntoa(Address));

            unsigned char Protocol = Name[Offset + 4];

            printf("Protocol %s: %s", 
                (!DNSProtocolTable[Protocol].Keyword) ? "UNASSIGNED" : DNSProtocolTable[Protocol].Keyword,
                (!DNSProtocolTable[Protocol].Description) ? "Unassigned" : DNSProtocolTable[Protocol].Description);

            unsigned char *Bitmap = &Name[Offset + 5];
            int Length = RDLEN - 5;

            for(int ByteIndex = 0;
                ByteIndex < Length;
                ++ByteIndex)
            {
                for(int Bit = 1;
                    Bit <= 8;
                    ++Bit)
                {
                    if(Bitmap[ByteIndex] & (0x100 >> Bit))
                    {
                        // (Byte + Bit)th bit set set
                        int BitsetIndex = ByteIndex + Bit;
                        struct port_descriptor PortInfo = {0};
                        
                        if(BitsetIndex < ArrayCount(DNSPortTable))
                            PortInfo = DNSPortTable[BitsetIndex];

                        printf("Protocol %s: %s", 
                            (!PortInfo.Keyword) ? "UNASSIGNED" : PortInfo.Keyword,
                            (!PortInfo.Description) ? "Unassigned" : PortInfo.Description);
                    }
                }
            }
        } break;
        case PTR:
        {
            printf("PTR: ");
            Offset = PrintDNSName(Name, Offset);
        } break;
        case HINFO:
        {
            int Begin = Offset;
            printf("CPU: ");
            while(Offset - Begin < RDLEN)
            {
                printf("\"%*.s\"\n", Name[Offset], &Name[Offset + 1]);
                Offset += Name[Offset];
            }

            printf("OS: ");
            while(Offset - Begin < RDLEN)
            {
                printf("\"%*.s\"\n", Name[Offset], &Name[Offset + 1]);
                Offset += Name[Offset];
            }
        } break;
        case MINFO:
        {
            printf("RMAILBX: ");
            Offset = PrintDNSName(Name, Offset);

            printf("EMAILBX: ");
            Offset = PrintDNSName(Name, Offset);
        } break;
        case MX:
        {
            printf("TXT: \"%*.s\"\n", RDLEN, &Name[Offset]);
        } break;
        case TXT:
        {
            int Begin = Offset;
            while(Offset - Begin < RDLEN)
            {
                printf("TXT: \"%*.s\"\n", Name[Offset], &Name[Offset + 1]);
                Offset += Name[Offset];
            }
        } break;

        default:
        {
            printf("Unrecognized RR!\n");
        } break;
    }

    Offset += RDLEN;
    return(Offset);
}

void *
ParseAuthRRs(void *QuestionStart, short NumQuestions);

void *
ParseAdditional(void *QuestionStart, short NumQuestions);

void
PrintDNSMessage(char *Response, int ResponseLength)
{
	struct dns_message_header Header;
    memcpy(&Header, Response, sizeof(struct dns_message_header));
	DeserializeDNSHeader(&Header);

	void *ResponsePtr = Response + sizeof(struct dns_message_header);
    unsigned Offset;

    PrintDNSHeader(&Header);

    printf("------- DNS Message -------\n");
    printf("---------------------------\n\n");

    printf("-------- Questions --------\n");
	Offset = ParseQuestions(ResponsePtr, Header.NumQuestions);
    printf("+%u", Offset + 12);

    printf("\n--------- Answers ---------\n");
	Offset = ParseAnswerRRs(ResponsePtr, Offset, Header.NumAnswerRRs);
    
    printf("+%u", Offset + 12);
	//ResponsePtr = ParseAuthRRs(ResponsePtr, Header.NumAuthRRs);
	//ResponsePtr = ParseAdditional(ResponsePtr, Header.NumAdditional);

	short QTYPE, QCLASS;
}

struct dns_message
FormatDNSMessage(struct dns_message_header Header,
				 struct dns_question *Questions)
{
	char *Message, *MsgPtr;

	// Serialize header -- change to network-order!
	SerializeDNSHeader(&Header);

	// Make space for header
	int Length = sizeof(struct dns_message_header);
	
    // -- questions
	for(struct dns_question *QuestionPtr = Questions;
		QuestionPtr; QuestionPtr = QuestionPtr->Next)
	{
		Length += QuestionPtr->QLEN + 2*sizeof(short);
	}

	Message = malloc(Length);

	// Fill that space
	memcpy(Message, &Header, sizeof(struct dns_message_header));
	MsgPtr = Message + sizeof(struct dns_message_header);

	for(struct dns_question *QuestionPtr = Questions;
		QuestionPtr; QuestionPtr = QuestionPtr->Next)
	{
		memcpy(MsgPtr, QuestionPtr->QNAME, QuestionPtr->QLEN);
		MsgPtr += QuestionPtr->QLEN;

		((short *)MsgPtr)[0] = htons(QuestionPtr->QTYPE);
		((short *)MsgPtr)[1] = htons(QuestionPtr->QCLASS);
		MsgPtr += 2*sizeof(short);
	}

	struct dns_message Result;
	Result.Length = Length;
	Result.Message = Message;

	return Result;
}

// labels          63 octets or less
// names           255 octets or less

char *
ConvertToMessageForm(char *HostSource)
{
	int len = strlen(HostSource);
	static char Result[256] = {0}; // = malloc(len + 2);

	if(!HostSource[0]) return 0;

	Result[0] = '.';
    memcpy(Result + 1, HostSource, len + 1);

    /*
        biconditional:
          char A, B
          C = ~(A XOR B)
    */

	unsigned char LabelIndex = 0;
	for(char *ptr = Result;
		*ptr; ptr += LabelIndex + 1)
	{
		for(LabelIndex = 0;
			ptr[LabelIndex + 1] != '.' && ptr[LabelIndex + 1];
			++LabelIndex);
		
		*ptr = LabelIndex;
	}

	return Result;
}


int
main(int argc, char **argv)
{
	int ClientSocket;
	char *DomainName = 0;
	unsigned long ServerHost = 0;

	if(argc >= 3 && (argc % 2) == 1)
	{
		for(int Index = 1; Index < argc - 1; ++Index)
		{
			if(argv[Index][0] == '-')
			{
				switch(argv[Index][1])
				{
					case 'h':
						DomainName = argv[Index + 1];
						break;
					case 's':
						ServerHost = inet_addr(argv[Index + 1]);
						break;
					default:
						break;
				}
			}
		}
	}
	if(!ServerHost)
		ServerHost = inet_addr("8.8.8.8");

	if(!DomainName)
		exit(1);

	struct sockaddr_in ServerAddr;

	memset(&ServerAddr, 0, sizeof(ServerAddr));
	ServerAddr.sin_family		= AF_INET;
	ServerAddr.sin_addr.s_addr	= ServerHost;
	ServerAddr.sin_port			= htons(53);

	WSADATA WSAData = {0};
	WSAStartup(MAKEWORD(1,1), &WSAData);

	if((ClientSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		exit(1);

	// Format our question
	
	// NOTE: Our machine is *little-endian*, we must swap these values into network order when assigning them
	//       But we're smart network programmers, we were totally going to do that already

	// Header
	struct dns_message_header Header = {0};
	Header.Identifier = 0xABCD;
	Header.RD = 1;
	Header.NumQuestions = 1;

	// Create a question
	struct dns_question Question = {0};
	Question.QNAME  = ConvertToMessageForm(DomainName);
	Question.QLEN   = strlen(Question.QNAME) + 1;
	Question.QTYPE  = A;
	Question.QCLASS = INET;

	// Format entire message; Header, then questions
	// and *change the byte order to network-order*!
	struct dns_message Message = FormatDNSMessage(Header, &Question);	// Header, then LLs to fields

/*	Reference message bytes of query for google.com
	unsigned char boof[] = {0xAA,0xfA,0x1,0,0,1,0,0,0,0,0,0, 
							6,'g','o','o','g','l','e', 3 ,'c','o','m','\0', //'','','','','',
							0,1, 
							0,1};
*/

	sendto(ClientSocket, Message.Message, Message.Length, 0, (struct sockaddr *) 
		   &ServerAddr, sizeof(ServerAddr));

	free(Message.Message);

	char RecvBuffer[512]; 	/* RFC 1035 p.10: "UDP messages    512 octets or less" */
	//struct DNSMessageHeader RecvBuffer;
	//unsigned char RecvBuffer[512] = {0};
	struct sockaddr_in FromAddr;
	int FromLen = sizeof(FromAddr);

	int BytesRecv = recvfrom(ClientSocket, RecvBuffer, sizeof(RecvBuffer), 0, (struct sockaddr *)
							 &FromAddr, &FromLen);
	
	printf("BytesRecv: %u\nAddr: %s\n", BytesRecv, inet_ntoa(FromAddr.sin_addr));

	if(BytesRecv < sizeof(struct dns_message_header))
	{
		printf("Error! Recieved %u bytes!\n", BytesRecv);
		closesocket(ClientSocket);
		WSACleanup();
		exit(1);
	}

	PrintDNSMessage(RecvBuffer, BytesRecv);


/*
7.3. Processing responses

The first step in processing arriving response datagrams is to parse the
response.  This procedure should include:

   - Check the header for reasonableness.  Discard datagrams which
     are queries when responses are expected.

   - Parse the sections of the message, and insure that all RRs are
     correctly formatted.

   - As an optional step, check the TTLs of arriving data looking
     for RRs with excessively long TTLs.  If a RR has an
     excessively long TTL, say greater than 1 week, either discard
     the whole response, or limit all TTLs in the response to 1
     week.

The next step is to match the response to a current resolver request.
The recommended strategy is to do a preliminary matching using the ID
field in the domain header, and then to verify that the question section
corresponds to the information currently desired.  This requires that
the transmission algorithm devote several bits of the domain ID field to
a request identifier of some sort.  This step has several fine points:

   - Some name servers send their responses from different
     addresses than the one used to receive the query.  That is, a
     resolver cannot rely that a response will come from the same
     address which it sent the corresponding query to.  This name
     server bug is typically encountered in UNIX systems.

   - If the resolver retransmits a particular request to a name
     server it should be able to use a response from any of the
     transmissions.  However, if it is using the response to sample
     the round trip time to access the name server, it must be able
     to determine which transmission matches the response (and keep
     transmission times for each outgoing message), or only
     calculate round trip times based on initial transmissions.

   - A name server will occasionally not have a current copy of a
     zone which it should have according to some NS RRs.  The
     resolver should simply remove the name server from the current
     SLIST, and continue.


*/




	struct dns_message_header *ResponseHeader;
	ResponseHeader = (struct dns_message_header *) &RecvBuffer;
	//PrintDNSHeader(ResponseHeader);

	
#if 0
	
	printf("Buffer contents: ");
	for(int i = 0; i < 12; ++i)
		printf("%02x", RBptr[i]);

#endif
	closesocket(ClientSocket);
	WSACleanup();
	return(0);
}