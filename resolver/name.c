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

unsigned short
ConsumeShort(unsigned char *Buffer, int *Offset)
{
    int I = *Offset;
    unsigned short Result = 
                      (Buffer[I++] << 8) |
                      (Buffer[I++] << 0);

    *Offset = I;
    return(Result);
}

unsigned
ConsumeLong(unsigned char *Buffer, int *Offset)
{
    int I = *Offset;
    unsigned Result = (Buffer[I++] << 24) |
                      (Buffer[I++] << 16) |
                      (Buffer[I++] << 8) |
                      (Buffer[I++] << 0);

    *Offset = I;
    return(Result);
}

int
ParseQuestions(unsigned char *QuestionStart, short NumQuestions)
{
	unsigned char *MemoryPtr = QuestionStart;
    unsigned Offset = sizeof(struct dns_message_header);
	for(int QuestionIndex = 0;
		QuestionIndex < NumQuestions;
		++QuestionIndex)
	{
        // Print QNAME
        Offset = PrintDNSName(QuestionStart, Offset);

        ++Offset;

        unsigned short Type; // = ConsumeShort(&QuestionStart[Offset], &Offset);
        memcpy(&Type, &QuestionStart[Offset], 2);
        Type = ntohs(Type);

        // Print QTYPE
        printf("\nQTYPE: %s ", DNSTypeTable[Type]);

        unsigned short Class;
        memcpy(&Class, &QuestionStart[Offset + 2], 2);
        Class = ntohs(Class);

        // Print QCLASS
        printf("\nQCLASS: %s (%u)\n", (Class == 1) ? "IN" : "OTHER", Class);

        Offset += 4;
	}

    return(Offset);
}

int
PrintRDATA(int Type, int RDLEN, unsigned char *Base, int Offset)
{
    switch(Type)
    {
        case A:
        {
            struct in_addr Address;
            Address.s_addr = *(ULONG *)&Base[Offset];

            printf("Address: %s\n", inet_ntoa(Address));
        } break;
        case NS:
        {
            printf("NS: ");
            Offset = PrintDNSName(Base, Offset);
        } break;

        case CNAME:
        {
            printf("CNAME: ");
            Offset = PrintDNSName(Base, Offset);
        } break;
        case SOA:
        {
            printf("MNAME: ");
            Offset = PrintDNSName(Base, Offset);

            printf("\nRNAME: ");
            Offset = PrintDNSName(Base, Offset);

            unsigned Serial  = ConsumeLong(Base, &Offset);
            unsigned Refresh = ConsumeLong(Base, &Offset);
            unsigned Retry   = ConsumeLong(Base, &Offset);
            unsigned Expire  = ConsumeLong(Base, &Offset);
            unsigned Minimum = ConsumeLong(Base, &Offset);

            printf("\n");
            printf("Serial: %u\n", Serial);
            printf("Refresh: %u\n", Refresh);
            printf("Retry: %u\n", Retry);
            printf("Expire: %u\n", Expire);
            printf("Minimum: %u\n", Minimum);
        } break;

        case WKS:
        {
            struct in_addr Address;
            Address.s_addr = *(ULONG *)&Base[Offset];

            printf("Address: %s\n", inet_ntoa(Address));

            unsigned char Protocol = Base[Offset + 4];

            printf("Protocol %s: %s", 
                (!DNSProtocolTable[Protocol].Keyword) ? "UNASSIGNED" : DNSProtocolTable[Protocol].Keyword,
                (!DNSProtocolTable[Protocol].Description) ? "Unassigned" : DNSProtocolTable[Protocol].Description);

            unsigned char *Bitmap = &Base[Offset + 5];
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
                            (!PortInfo.Keyword ? "UNASSIGNED" : PortInfo.Keyword),
                            (!PortInfo.Description ? "Unassigned" : PortInfo.Description));
                    }
                }
            }
        } break;
        case PTR:
        {
            printf("PTR: ");
            Offset = PrintDNSName(Base, Offset);
        } break;
        case HINFO:
        {
            int Begin = Offset;
            printf("CPU: ");
            while(Offset - Begin < RDLEN)
            {
                printf("\"%*.s\"\n", Base[Offset], &Base[Offset + 1]);
                Offset += Base[Offset];
            }

            printf("OS: ");
            while(Offset - Begin < RDLEN)
            {
                printf("\"%*.s\"\n", Base[Offset], &Base[Offset + 1]);
                Offset += Base[Offset];
            }
        } break;
        case MINFO:
        {
            printf("RMAILBX: ");
            Offset = PrintDNSName(Base, Offset);

            printf("EMAILBX: ");
            Offset = PrintDNSName(Base, Offset);
        } break;
        case MX:
        {
            unsigned short Preference = (Base[Offset++] << 8) |
                                        (Base[Offset++] << 0);
            
            printf("Preference: %u\n", Preference);

            printf("Exchange: ");
            Offset = PrintDNSName(Base, Offset);
        } break;
        case TXT:
        {
            int Begin = Offset;
            while(Offset - Begin < RDLEN)
            {
                printf("TXT: \"%*.s\"\n", Base[Offset], &Base[Offset + 1]);
                Offset += Base[Offset];
            }
        } break;

        case GPOS:
        {
            printf("Long: %*.s\n", Base[Offset], &Base[Offset + 1]); Offset += Base[Offset];
            printf("Lat:  %*.s\n", Base[Offset], &Base[Offset + 1]); Offset += Base[Offset]; 
            printf("Alt:  %*.s\n", Base[Offset], &Base[Offset + 1]); Offset += Base[Offset];
        } break;
        case AAAA:
        {
            printf("Address: ");
            for(int Byte = 0;
                Byte < 16;
                Byte += 2)
            {
                printf("%02x%02x", Base[Offset + Byte], Base[Offset + Byte + 1]);
                printf("%s", (Byte == 14 ? "\n" : ":"));
            }
        } break;

        default:
        {
            printf("Unrecognized RR! Type no: %u\n", Type);
        } break;
    }

    return(Offset);
}

int
ParseAnswerRRs(void *QuestionStart, int Offset, short NumQuestions)
{
    for(int QuestionIndex = 0;
        QuestionIndex < NumQuestions;
        ++QuestionIndex)
    {
        // Print header
        // Name
        unsigned char *Name = QuestionStart;

        printf("NAME: ");
        Offset = PrintDNSName(Name, Offset);

        // Type, 
        unsigned short Type = ConsumeShort(Name, &Offset);

        printf("\nTYPE: %s\n", DNSTypeTable[Type]);

        // Class, 
        unsigned short Class = ConsumeShort(Name, &Offset);

        printf("CLASS: %s (%u)\n", (Class == INET) ? "IN" : "Other", Class);
        // TTL, 
        unsigned uTTL = ConsumeLong(Name, &Offset);

        int TTL;
        memcpy(&TTL, &uTTL, sizeof(int));

        printf("TTL: %d\n", TTL);

        // RDLEN, 
        unsigned short RDLEN = (Name[Offset++] << 8) |
                               (Name[Offset++] << 0);

        printf("RDLEN: %u\n", RDLEN);

        // RDATA
        Offset = PrintRDATA(Type, RDLEN, Name, Offset);
        
        printf("--\n");

        Offset += RDLEN;
    }
    return(Offset);
}

void
PrintDNSMessage(char *Response, int ResponseLength)
{
	struct dns_message_header Header;
    memcpy(&Header, Response, sizeof(struct dns_message_header));
	DeserializeDNSHeader(&Header);

    unsigned Offset;

    PrintDNSHeader(&Header);

    printf("------- DNS Message -------\n");
    printf("---------------------------\n\n");

    printf("-------- Questions --------\n");
	Offset = ParseQuestions(Response, Header.NumQuestions);
    printf("+%u", Offset + 12);

    if(Header.NumAnswerRRs > 0)
    {
        printf("\n--------- Answers ---------\n");
        Offset = ParseAnswerRRs(Response, Offset, Header.NumAnswerRRs);
        
        printf("+%u", Offset + 12);
    }
    if(Header.NumAuthRRs > 0)
    {
        printf("\n--------- AuthRRs ---------\n");
        Offset = ParseAnswerRRs(Response, Offset, Header.NumAuthRRs);
        
        printf("+%u", Offset + 12);
    }
    if(Header.NumAdditional > 0)
    {
        printf("\n-------- Additional -------\n");
        Offset = ParseAnswerRRs(Response, Offset, Header.NumAdditional);
        
        printf("+%u", Offset + 12);
    }

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
StringToQueryType(char *String)
{
    for(int Index = 0;
        Index < ArrayCount(DNSTypeTable);
        ++Index)
    {
        char *TableEntry;
        if(DNSTypeTable[Index])
        {
            TableEntry = DNSTypeTable[Index];

            if(strlen(TableEntry) == strlen(String))
            {
                for(int EntryIndex = 0;
                    EntryIndex < strlen(TableEntry);
                    ++EntryIndex)
                {
                    int Diff = TableEntry[EntryIndex] - String[EntryIndex];
                    if(!(Diff == 0 || Diff == 'A' - 'a' || Diff == 'a' - 'A')) break;

                    if(EntryIndex == strlen(TableEntry) - 1) return(Index);
                }
            }
        }
    }

    return(1);
}

int
main(int argc, char **argv)
{
	int ClientSocket;
	char *DomainName = 0;
	unsigned long ServerHost = 0;
    int QueryType = A;

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
                    case 'q':
                        QueryType = StringToQueryType(argv[Index + 1]);
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
	Question.QTYPE  = QueryType;
	Question.QCLASS = INET;

	// Format entire message; Header, then questions
	// and *change the byte order to network-order*!
	struct dns_message Message = FormatDNSMessage(Header, &Question);	// Header, then LLs to fields

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